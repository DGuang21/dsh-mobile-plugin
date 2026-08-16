/**
 * Composition root.
 *
 * One place that wires the parts together, so the CLI, tests, and the plugin entry
 * point all get an identically configured bridge. Nothing here makes policy
 * decisions; it decides what is connected to what.
 *
 * The wiring order matters in one respect: the dsh connection's sinks feed the
 * stream hub, and the hub's readiness gate is what `/m1/stream` consults, so a phone
 * can never attach to a bridge whose harness is not actually ready.
 */

import { chmodSync, mkdirSync } from 'node:fs';
import type { Server } from 'node:http';
import { createServer } from 'node:http';
import { AuditLog } from './audit/log.ts';
import { AuthService } from './auth/tokens.ts';
import { DshApiClient } from './dsh/client.ts';
import { DshConnection } from './dsh/connection.ts';
import { DshDownlink } from './dsh/downlink.ts';
import { BridgeServer } from './http/server.ts';
import { DeviceRegistry } from './identity/registry.ts';
import { IdentityStore } from './identity/store.ts';
import { PairingManager } from './identity/pairing.ts';
import { PolicyGate } from './policy/gate.ts';
import { StreamHub } from './stream/hub.ts';
import { createTlsServer, loadOrCreateTlsIdentity, spkiFingerprintOf } from './transport/tls.ts';
import { LocalBridgeBackend } from './relay/backend.ts';
import { RelayConnector } from './relay/connector.ts';
import { RendezvousListener } from './relay/rendezvous.ts';
import { ControlServer, type ControlHandlers, type ControlResponse } from './control.ts';
import { buildPairingUri, deriveRendezvousRoutingId } from './identity/pairing.ts';
import { deviceIdFromPublicKey } from './identity/crypto.ts';
import type { ScopeTier } from './policy/methods.ts';

export const BRIDGE_VERSION = '0.1.0';

/**
 * How long a rendezvous stays open after the operator confirms.
 *
 * Long enough for the phone's next poll (it polls about once a second) to collect
 * the bridge routing id, short enough that the listener is gone well before anyone
 * could make use of a token that is already spent.
 */
const RENDEZVOUS_LINGER_MS = 20_000;

/**
 * How long a revoked device's relay connector stays up after revocation.
 *
 * Revocation queues a `device-revoked` frame onto the carrier stream and then must
 * tear the tunnel down — but the frame needs a few ticks to travel hub → carrier
 * socket → connector → seal → relay → phone. Stopping the connector in the same
 * synchronous tick drops the frame with it, so the phone only ever learns its peer
 * vanished (indistinguishable from a sleeping laptop) and retries forever.
 *
 * Deferring the teardown by a bounded window lets the frame flush first. It is safe:
 * the device is already out of the registry (any request through the still-open
 * tunnel is rejected 401/403) and its stream subscriber was dropped synchronously by
 * `hub.disconnectDevice`. The connector carries nothing but the goodbye frame during
 * the linger, and `stop()` tears any lingering connector down at once.
 */
const REVOCATION_LINGER_MS = 1_000;

export interface BuildOptions {
  /** Directory holding identity, devices, TLS material, and the audit log. */
  stateDir: string;
  /** dsh web origin. Must be loopback. */
  dshUrl: string;
  /** Port for the phone-facing HTTPS listener. */
  port: number;
  /** Interface for the phone-facing listener. `0.0.0.0` to serve the LAN. */
  host: string;
  /** Hostnames and IPs to put in the self-signed certificate's SAN. */
  certHosts?: string[];
  bridgeName?: string;
  /** Mirror audit entries to stderr. */
  echoAudit?: boolean;
  rateLimitPerMinute?: number;
  /** Relay URL to dial out to. Omitted means LAN-only. */
  relayUrl?: string;
  /**
   * Where {@link relayUrl} came from, when it was supplied here rather than read
   * from the on-disk identity. A relay pinned by plugin config/env or a CLI flag
   * OVERRIDES the on-disk value at every start (see the `?? identity.relayUrl`
   * fallback below), so a panel write to disk can never take effect while the pin
   * stands. Recording the source lets the management panel say so honestly instead
   * of promising a restart would adopt a change it silently cannot. Omitted (or
   * `undefined`) when `relayUrl` is not set here: the on-disk value is then the only
   * source and the panel may edit it freely.
   */
  relaySource?: 'config' | 'env' | 'cli';
  /**
   * How long a revoked device's relay connector lingers so its `device-revoked`
   * frame can flush before the tunnel is torn down. Defaults to
   * {@link REVOCATION_LINGER_MS}. Exposed mostly so tests need not wait a full
   * second; production has no reason to change it.
   */
  revocationLingerMs?: number;
  /** Unix socket path for the relay carrier. Defaults inside `stateDir`. */
  carrierSocketPath?: string;
}

export interface BuiltBridge {
  identity: IdentityStore;
  registry: DeviceRegistry;
  auth: AuthService;
  pairing: PairingManager;
  hub: StreamHub;
  client: DshApiClient;
  connection: DshConnection;
  bridge: BridgeServer;
  audit: AuditLog;
  tlsFingerprint: string;
  /** Phone-facing HTTPS server. Not yet listening. */
  httpsServer: Server;
  /** Loopback carrier for the relay connector. Not yet listening. */
  carrierServer: Server;
  carrierSocketPath: string;
  /** One connector per paired device with a relay route. Empty in LAN-only mode. */
  connectors: Map<string, RelayConnector>;
  start(): Promise<void>;
  stop(): Promise<void>;
  /** Bring relay connectors in line with the current device routes. */
  syncConnectors(): void;
  /** Handlers the control socket exposes. Also usable directly in tests. */
  controlHandlers: ControlHandlers;
}

export function buildBridge(options: BuildOptions): BuiltBridge {
  mkdirSync(options.stateDir, { recursive: true, mode: 0o700 });

  const identity = IdentityStore.open(options.stateDir);
  const registry = DeviceRegistry.open(options.stateDir);
  const audit = new AuditLog({ stateDir: options.stateDir, echo: options.echoAudit ?? false });
  const hub = new StreamHub();

  const client = new DshApiClient({ baseUrl: options.dshUrl });
  const downlink = new DshDownlink({ baseUrl: options.dshUrl });
  const connection = new DshConnection({
    client,
    downlink,
    sinks: {
      // Readiness is what gates `/m1/stream`; a rebuild clears the resume window
      // because bseq numbering is only meaningful within one dsh generation.
      onConnected: () => hub.onDshReady(),
      onDisconnected: (reason) => hub.onDshDisconnected(reason),
      onMuxFrame: (envelope) => hub.ingestMux(envelope),
      onHostFrame: (envelope) => hub.ingestHost(envelope),
    },
  });

  const auth = new AuthService({ registry, bridgeId: identity.bridgeId });
  const pairing = new PairingManager({
    registry,
    bridgeId: identity.bridgeId,
    bridgeName: options.bridgeName ?? 'dsh bridge',
    // Pairing into a bridge that cannot reach dsh produces a phone that appears
    // broken, so it is refused up front.
    isDshReachable: () => connection.getState() === 'connected',
  });

  // Split the SAN entries by kind: a phone pins the SPKI, but it still validates
  // the name it dialled, and an IP in a DNS SAN does not match.
  const certHosts = options.certHosts ?? ['localhost', '127.0.0.1'];
  const isIp = (value: string): boolean => /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
  const tls = loadOrCreateTlsIdentity({
    stateDir: options.stateDir,
    dnsNames: certHosts.filter((host) => !isIp(host)),
    ipAddresses: certHosts.filter(isIp),
  });
  const tlsFingerprint = spkiFingerprintOf(tls.certPem);
  const httpsServer = createTlsServer(tls);

  const bridge = new BridgeServer({
    server: httpsServer,
    client,
    connection,
    hub,
    registry,
    auth,
    pairing,
    gate: new PolicyGate(),
    audit,
    bridgeId: identity.bridgeId,
    bridgeName: options.bridgeName ?? 'dsh bridge',
    bridgeVersion: BRIDGE_VERSION,
    bridgeKeyFingerprint: tlsFingerprint,
    ...(options.rateLimitPerMinute === undefined ? {} : { rateLimitPerMinute: options.rateLimitPerMinute }),
  });

  // The relay carrier serves the same routes on a Unix socket. Loopback-only by
  // construction: a Unix socket has no address to reach from another host.
  const carrierServer = createServer();
  bridge.attach(carrierServer);
  const carrierSocketPath = options.carrierSocketPath ?? `${options.stateDir}/carrier.sock`;

  const connectors = new Map<string, RelayConnector>();
  // A relay supplied through BuildOptions (plugin config/env or a CLI flag) is a
  // PIN: it wins over the on-disk value here and again at the next start, so the
  // panel's disk writes are inert until the pin is removed. `relaySource` is only
  // meaningful when the pin is actually in force.
  const relayPinned = options.relayUrl !== undefined;
  const relaySource = relayPinned ? options.relaySource ?? 'config' : undefined;
  const relayUrl = options.relayUrl ?? identity.relayUrl;
  const revocationLingerMs = options.revocationLingerMs ?? REVOCATION_LINGER_MS;

  // Connectors kept alive past revocation just long enough to flush the
  // `device-revoked` frame. Tracked separately from `connectors` (they are removed
  // from the map the moment they are scheduled) so `stop()` can still tear them down
  // at once rather than leaking a socket for the length of the linger.
  const lingeringConnectors = new Set<RelayConnector>();

  const syncConnectors = (): void => {
    if (relayUrl === undefined) return;
    const backend = new LocalBridgeBackend({ target: { socketPath: carrierSocketPath } });
    const routes = identity.routes();

    // Stop connectors for devices that are gone or revoked. A revoked device must
    // not keep an outbound tunnel alive.
    for (const [deviceId, connector] of connectors) {
      if (routes[deviceId] === undefined || registry.getActive(deviceId) === undefined) {
        connector.stop();
        connectors.delete(deviceId);
      }
    }

    for (const [deviceId, route] of Object.entries(routes)) {
      if (connectors.has(deviceId)) continue;
      if (registry.getActive(deviceId) === undefined) continue;
      const connector = new RelayConnector({
        relayUrl,
        routingId: route.routingId,
        peerRoutingId: route.peerRoutingId,
        ownStaticPublicKey: identity.publicKeyB64,
        ownStaticPrivateKey: identity.privateKey(),
        peerStaticPublicKey: route.peerStaticPublicKey,
        backend,
      });
      connectors.set(deviceId, connector);
      connector.start();
    }
  };

  /**
   * Tear a revoked device's connector down after a bounded linger.
   *
   * The connector leaves `connectors` immediately (so a re-sync never treats it as
   * live and nothing dials through it again) but keeps running until the timer
   * fires, which is what lets the already-queued `device-revoked` frame reach the
   * phone. See {@link REVOCATION_LINGER_MS}.
   */
  const scheduleConnectorTeardown = (deviceId: string): void => {
    const connector = connectors.get(deviceId);
    if (connector === undefined) return;
    connectors.delete(deviceId);
    lingeringConnectors.add(connector);
    const timer = setTimeout(() => {
      connector.stop();
      lingeringConnectors.delete(connector);
    }, revocationLingerMs);
    timer.unref?.();
  };

  // Revocation is the security-critical path: drop the tunnel, do not merely fail
  // the next request through it. The drop is deferred by a linger so the
  // `device-revoked` frame (queued by the hub's own revocation listener) is not
  // torn down before it reaches the phone.
  registry.onRevocation((deviceId) => scheduleConnectorTeardown(deviceId));

  // ── control handlers ──────────────────────────────────────────────────────

  const controlHandlers: ControlHandlers = {
    status: () => ({
      bridgeId: identity.bridgeId,
      bridgeVersion: BRIDGE_VERSION,
      bridgeKey: identity.publicKeyB64,
      spkiPin: tlsFingerprint,
      listen: { host: options.host, port: options.port },
      dsh: { url: options.dshUrl, state: connection.getState() },
      relay: {
        url: relayUrl ?? null,
        // `pinned` tells the panel the running relay is fixed by config/env or a CLI
        // flag and cannot be changed from the panel; `source` says which, so the UI
        // can name where to change it. Both are absent (false/null) in the normal
        // case where the on-disk value is authoritative and the panel may edit it.
        pinned: relayPinned,
        source: relaySource ?? null,
        connectors: [...connectors.entries()].map(([deviceId, connector]) => ({
          deviceId,
          ...connector.stats(),
        })),
      },
      stream: hub.stats(),
      devices: registry.list().length,
      activeDevices: registry.list().filter((device) => device.revokedAt === undefined).length,
      pairingOpen: pairing.isOpen(),
      recentAudit: audit.tail(20),
    }),

    list: () =>
      registry.list().map((device) => ({
        deviceId: device.deviceId,
        label: device.label,
        tier: device.tier,
        pairedAt: device.createdAt,
        lastSeenAt: device.lastSeenAt ?? null,
        revokedAt: device.revokedAt ?? null,
        relayRoute: identity.routeFor(device.deviceId) !== undefined,
      })),

    revoke: (deviceId) => {
      const device = registry.get(deviceId);
      if (device === undefined) return { ok: false, message: `no such device: ${deviceId}` };
      if (device.revokedAt !== undefined) return { ok: false, message: `already revoked: ${deviceId}` };
      // `revoke` fires the registry's revocation listeners, which is what drops the
      // live stream (immediately) and schedules the relay tunnel's teardown (after a
      // linger, so the `device-revoked` frame reaches the phone first). Order
      // matters: nothing is reported as revoked before it actually is.
      registry.revoke(deviceId);
      // Drop the standing invitation to redial. The connector itself is torn down by
      // the deferred teardown the revocation listener scheduled; tearing it down here
      // would race the goodbye frame off the wire, which is the bug this avoids.
      identity.removeRoute(deviceId);
      return { ok: true, message: `revoked ${deviceId} (${device.label})` };
    },

    /**
     * Open a pairing window.
     *
     * Relay mode no longer needs a phone routing id: the rendezvous id is derived
     * from the token both sides already have. See relay/rendezvous.ts for the
     * sequence and why it is sound.
     */
    beginPair: (input, emit) => {
      const session = pairing.begin();
      const wantsRelay = input.relay;

      if (wantsRelay && relayUrl === undefined) {
        pairing.cancel();
        emit({ type: 'pair-failed', reason: 'relay pairing needs a relay URL (--relay-url or a saved one)' });
        return { confirm: () => {}, cancel: () => {} };
      }

      const rendezvousId = wantsRelay ? deriveRendezvousRoutingId(session.token, identity.bridgeId) : undefined;

      const uri = buildPairingUri({
        bridgeId: identity.bridgeId,
        token: session.token,
        bridgeKey: identity.publicKeyB64,
        // Mode A pins the TLS SPKI; mode B carries the relay and the token-derived
        // rendezvous id. The bridge's static key is in both, so a relay can never
        // substitute itself.
        ...(wantsRelay
          ? { ...(relayUrl === undefined ? {} : { relay: relayUrl }), ...(rendezvousId === undefined ? {} : { routingId: rendezvousId }) }
          : { fingerprint: tlsFingerprint }),
      });

      let finished = false;
      let announced = false;
      let paired = false;
      // Set when the operator declines the SAS. The rendezvous then lingers (so the
      // phone's next poll reads the 403 `pairing-rejected`) and the pairing session
      // must survive a control-socket close — see `cancel` below.
      let declined = false;

      const poll = setInterval(() => {
        if (finished) return;
        const current = pairing.current();
        if (current === undefined) {
          finished = true;
          clearInterval(poll);
          emit({ type: 'pair-failed', reason: 'pairing window closed' });
          return;
        }
        if (current.state === 'expired' || current.state === 'failed') {
          finished = true;
          clearInterval(poll);
          emit({ type: 'pair-failed', reason: current.state === 'expired' ? 'token expired' : 'claim rejected' });
          return;
        }
        if (current.state === 'awaiting-confirmation' && !announced && current.sas !== undefined) {
          announced = true;
          const pendingDevice = current.pending;
          emit({
            type: 'pair-claimed',
            sas: current.sas,
            deviceId: pendingDevice === undefined ? '' : deviceIdOf(pendingDevice.publicKey),
            label: pendingDevice?.label ?? '',
            expiresAt: current.expiresAt,
          });
        }
      }, 200);
      poll.unref?.();

      // Record the route for a device that just proved itself over the rendezvous.
      // Called from inside the sealed channel, after the deferred device-key proof
      // passed, so `devicePublicKey` is authenticated by the time we get here.
      const assignRoute = (claim: { devicePublicKey: string; peerRoutingId: string }): string | undefined => {
        const device = registry.findByPublicKey(claim.devicePublicKey);
        // Refuse for an unknown or revoked device: a route is a standing invitation
        // to dial in, and a revoked device must not receive one.
        if (device === undefined || device.revokedAt !== undefined) return undefined;
        const route = identity.addRoute(device.deviceId, {
          peerRoutingId: claim.peerRoutingId,
          peerStaticPublicKey: claim.devicePublicKey,
        });
        syncConnectors();
        return route.routingId;
      };

      let rendezvous: RendezvousListener | undefined;
      if (rendezvousId !== undefined && relayUrl !== undefined) {
        rendezvous = new RendezvousListener({
          relayUrl,
          rendezvousId,
          token: session.token,
          bridgeId: identity.bridgeId,
          ownStaticPublicKey: identity.publicKeyB64,
          ownStaticPrivateKey: identity.privateKey(),
          backend: new LocalBridgeBackend({ target: { socketPath: carrierSocketPath } }),
          assignRoute,
        });
      }

      const finish = (message: ControlResponse): void => {
        if (finished) return;
        finished = true;
        clearInterval(poll);
        // Hold the rendezvous open briefly whenever the phone still has something to
        // learn from a poll it may be mid-flight on:
        //   - after a successful pairing, the bridge routing id it has no other way
        //     to obtain;
        //   - after an operator decline, the 403 `pairing-rejected` that turns "the
        //     tunnel vanished" into "declined on the workstation".
        // Closing immediately would strand a phone mid-poll and, on decline, cost the
        // only signal that distinguishes a refusal from an unreachable relay.
        const lingerForPoll = message.type === 'pair-done' || declined;
        if (lingerForPoll && rendezvous !== undefined) {
          const linger = setTimeout(() => rendezvous?.close(), RENDEZVOUS_LINGER_MS);
          linger.unref?.();
        } else {
          rendezvous?.close();
        }
        emit(message);
      };

      // Emit `pair-open` only once the rendezvous is actually registered. A QR the
      // phone cannot dial is worse than a clear failure, because the operator would
      // spend the whole 120-second window not knowing why nothing happened.
      if (rendezvous === undefined) {
        emit({ type: 'pair-open', uri, token: session.token, expiresAt: session.expiresAt });
      } else {
        void rendezvous.start().then((started) => {
          if (finished) return;
          if (!started.ok) {
            pairing.cancel();
            finish({ type: 'pair-failed', reason: `relay rendezvous failed: ${started.reason}` });
            return;
          }
          emit({ type: 'pair-open', uri, token: session.token, expiresAt: session.expiresAt });
        });
      }

      return {
        confirm: (accept: boolean) => {
          if (!accept) {
            // Decline: keep the pairing session in `failed` (via `reject`, not
            // `cancel`, which would erase it) and let `finish` linger the rendezvous
            // so the phone's proof-authenticated poll can read `pairing-rejected`.
            declined = true;
            pairing.reject();
            finish({ type: 'pair-failed', reason: 'rejected by operator' });
            return;
          }
          const pendingKey = pairing.current()?.pending?.publicKey;
          const device = pairing.confirm({ tier: input.tier as ScopeTier });
          if (device === undefined) {
            finish({ type: 'pair-failed', reason: 'nothing awaiting confirmation' });
            return;
          }
          paired = true;
          // Record the relay route here as well as on the phone's final poll. The
          // poll is how the phone LEARNS the routing id; this is what guarantees the
          // route EXISTS even if the phone never polls again. Registering a device
          // with no route would look like a successful pairing that cannot connect.
          const proven = rendezvous?.provenClaim();
          if (proven !== undefined && pendingKey !== undefined && proven.devicePublicKey === pendingKey) {
            identity.addRoute(device.deviceId, {
              peerRoutingId: proven.peerRoutingId,
              peerStaticPublicKey: pendingKey,
            });
            syncConnectors();
          }
          finish({ type: 'pair-done', deviceId: device.deviceId, label: device.label, tier: device.tier });
        },
        cancel: () => {
          // A completed pairing must not be undone by the CLI hanging up: the device
          // is registered, the operator already confirmed it, and the rendezvous may
          // still be lingering so the phone can collect its routing id. A declined
          // one is the same story in reverse — the session is deliberately kept in
          // `failed` so the phone's poll reads `pairing-rejected`, and `pairing.cancel`
          // would erase it back to an indistinguishable `unknown`.
          if (paired || declined) {
            finished = true;
            clearInterval(poll);
            return;
          }
          pairing.cancel();
          finish({ type: 'pair-failed', reason: 'cancelled' });
        },
      };
    },
  };

  const control = new ControlServer(options.stateDir, controlHandlers);
  let maintainTimer: NodeJS.Timeout | undefined;

  const start = async (): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
      httpsServer.once('error', reject);
      httpsServer.listen(options.port, options.host, () => {
        httpsServer.removeListener('error', reject);
        resolve();
      });
    });

    if (relayUrl !== undefined) {
      await new Promise<void>((resolve, reject) => {
        carrierServer.once('error', reject);
        carrierServer.listen(carrierSocketPath, () => {
          carrierServer.removeListener('error', reject);
          // Owner-only, explicitly, exactly as the control socket does. `stateDir`
          // is created 0o700, but `mkdirSync` does not reapply a mode to a
          // directory that already exists — so an operator pointing --state-dir
          // at a pre-existing 0o755 directory would otherwise expose the full
          // `/m1` router to every local user. The socket carries no credential,
          // but pre-auth routes and the pairing window are reachable through it.
          chmodSync(carrierSocketPath, 0o600);
          resolve();
        });
      });
      syncConnectors();
    }

    await control.listen();
    connection.start();
    // Token sweep and expiry warnings. Unref'd so it never holds the process open.
    maintainTimer = setInterval(() => bridge.maintain(), 30_000);
    maintainTimer.unref?.();
  };

  const stop = async (): Promise<void> => {
    if (maintainTimer !== undefined) clearInterval(maintainTimer);
    await control.close();
    for (const connector of connectors.values()) connector.stop();
    connectors.clear();
    // Connectors mid-linger after a revocation: their teardown timer has not fired
    // yet, so tear them down now rather than leak a socket past shutdown.
    for (const connector of lingeringConnectors) connector.stop();
    lingeringConnectors.clear();
    bridge.closeSockets('bridge shutting down');
    await connection.stop();
    await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    await new Promise<void>((resolve) => carrierServer.close(() => resolve()));
  };

  return {
    identity,
    registry,
    auth,
    pairing,
    hub,
    client,
    connection,
    bridge,
    audit,
    tlsFingerprint,
    httpsServer,
    carrierServer,
    carrierSocketPath,
    connectors,
    start,
    stop,
    syncConnectors,
    controlHandlers,
  };
}

/** Device id for a public key, for progress reporting before registration. */
function deviceIdOf(publicKeyB64: string): string {
  return deviceIdFromPublicKey(publicKeyB64) ?? '';
}

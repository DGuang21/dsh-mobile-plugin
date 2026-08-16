/**
 * [OUR DESIGN] Mode B first-pair rendezvous listener.
 *
 * ## The problem this exists to solve
 *
 * Relay transport needs two routing ids, one per side. Steady state has both: they
 * were agreed when the device paired. A *first* pairing does not, and the previous
 * design papered over it by requiring the operator to pass `--peer-routing-id` to
 * `pair --relay` — the phone's routing id, before the phone has ever connected.
 * That value does not exist yet and cannot be known, so out-of-LAN first pairing
 * was not actually reachable.
 *
 * ## The sequence
 *
 * Both sides derive a rendezvous id from the single-use pairing token, so neither
 * has to be told the other's id in advance:
 *
 *   1. Bridge opens a pairing window, derives `R = HKDF(token, bridgeId)`, and
 *      registers `R` at the relay in `rendezvous` mode — no peer named.
 *   2. QR carries `relay`, `rid = R`, `bk` (the bridge's static key), and `tok`.
 *   3. Phone recomputes `R` from `tok` and refuses if it differs from `rid`.
 *      It mints its OWN random routing id `P`, registers `P` in `peer` mode naming
 *      `R`, and opens a sealed pairing handshake (see seal.ts).
 *   4. Inside that sealed channel the phone POSTs the ordinary `/m1/pair/claim`
 *      body, plus its `relayRoutingId = P`.
 *   5. The bridge verifies the retained handshake signature against the device key
 *      the claim just revealed, then runs the SAME claim path a LAN phone uses:
 *      token check, proof check, SAS, operator confirmation.
 *   6. On confirmation the bridge mints its durable routing id `B` for that device,
 *      persists the `(B, P, deviceKey)` route, and returns `B` in the poll
 *      response — inside the sealed channel.
 *   7. Both sides drop the rendezvous and connect `B ↔ P` with the mutually
 *      authenticated steady-state seal.
 *
 * ## Why this is sound
 *
 * - The bridge's identity is authenticated from step 3 onward: it signs the
 *   handshake transcript with the static key the phone pinned from the QR. A
 *   hostile relay cannot man-in-the-middle the pairing exchange.
 * - The phone's identity is authenticated at step 5, retroactively but before
 *   anything is registered: the retained transcript signature must verify against
 *   the device key in the claim, so the channel and the device being registered are
 *   provably the same principal.
 * - Authorization is unchanged. Everything still funnels through `/m1/pair/claim`,
 *   so the single-use token, the atomic consume, the signed proof and the mandatory
 *   operator SAS all apply exactly as on the LAN. This listener adds transport, not
 *   trust.
 * - Reaching the rendezvous requires the token, and the only thing it grants is the
 *   right to attempt one claim that a human must then confirm.
 *
 * `[NOT INTEGRATION-TESTED]` against a real phone or a deployed relay: exercised
 * against the in-repo relay over a real WebSocket.
 */

import type { KeyObject } from 'node:crypto';
import { RELAY_SUBPROTOCOL, type RelayServerMessage, isValidRoutingId } from './protocol.ts';
import {
  type DeferredPeerProof,
  type SealHandshake,
  type SealedChannel,
  beginPairingHandshake,
  completePairingHandshakeAsBridge,
  pairingTokenBinder,
  signHandshake,
  verifyDeferredPeerProof,
} from './seal.ts';
import { TUNNEL_MAX_MESSAGE_BYTES, type TunnelServerMessage, parseTunnelClientMessage } from './tunnel.ts';
import type { TunnelBackend } from './backend.ts';
import type { WebSocketLike } from './connector.ts';
import { M1_PATHS } from '../m1/wire.ts';

/** Paths a phone may reach through a rendezvous. Deliberately just the one. */
const PAIRING_ALLOWED_PATHS: ReadonlySet<string> = new Set([M1_PATHS.pairClaim]);

export type RendezvousState = 'idle' | 'dialing' | 'listening' | 'closed';

/**
 * How long to wait for the relay to acknowledge the registration.
 *
 * Well inside the 120-second pairing window, so a failure still leaves the operator
 * time to fix the relay and re-run `pair`.
 */
const DEFAULT_REGISTER_TIMEOUT_MS = 10_000;

export interface RendezvousOptions {
  relayUrl: string;
  /** The token-derived rendezvous id. */
  rendezvousId: string;
  /** The live pairing token, used only to derive the seal binder. */
  token: string;
  bridgeId: string;
  ownStaticPublicKey: string;
  ownStaticPrivateKey: KeyObject;
  /** Serves `/m1/pair/claim` over the loopback carrier. */
  backend: TunnelBackend;
  /**
   * Called when a claim is accepted for a device, so the bridge can mint and
   * persist the durable route. Returns the bridge's routing id for that device.
   */
  assignRoute: (input: { devicePublicKey: string; peerRoutingId: string }) => string | undefined;
  webSocketFactory?: (url: string, protocols: string[]) => WebSocketLike;
  onStateChange?: (state: RendezvousState) => void;
  /** Overrides {@link DEFAULT_REGISTER_TIMEOUT_MS}. Tests use a short value. */
  registerTimeoutMs?: number;
  verbose?: boolean;
}

/** One phone talking to the rendezvous. */
interface Claimant {
  routingId: string;
  handshake: SealHandshake | undefined;
  channel: SealedChannel | undefined;
  handshakeSigned: boolean;
  deferred: DeferredPeerProof | undefined;
  /** Set once a claim on this channel proved it holds this device key. */
  provenDeviceKey: string | undefined;
  /** The routing id the phone declared inside the sealed claim. */
  declaredRoutingId: string | undefined;
}

/**
 * Listens on a rendezvous id for the duration of one pairing window.
 *
 * Deliberately short-lived: `close()` is called when the window ends, whether it
 * succeeded, was rejected, or expired. A rendezvous that outlived its token would be
 * a listener nobody is watching.
 */
export class RendezvousListener {
  private readonly options: RendezvousOptions;
  private readonly binder: string;
  private readonly claimants = new Map<string, Claimant>();
  private socket: WebSocketLike | undefined;
  private state: RendezvousState = 'idle';
  private closed = false;
  private lastError: string | undefined;

  constructor(options: RendezvousOptions) {
    if (!isValidRoutingId(options.rendezvousId)) {
      throw new Error('rendezvous id must be a 22-char base64url value');
    }
    this.options = options;
    this.binder = pairingTokenBinder(options.token, options.bridgeId);
  }

  getState(): RendezvousState {
    return this.state;
  }

  stats(): { state: RendezvousState; claimants: number; lastError: string | undefined } {
    return { state: this.state, claimants: this.claimants.size, lastError: this.lastError };
  }

  /**
   * The device key and routing id of the claimant that proved itself, if any.
   *
   * Lets the bridge record the route at operator-confirmation time instead of
   * depending on the phone polling once more. A phone that closes the app right
   * after tapping confirm would otherwise be registered with no route, which looks
   * like a successful pairing that cannot connect — the worst possible outcome.
   */
  provenClaim(): { devicePublicKey: string; peerRoutingId: string } | undefined {
    for (const claimant of this.claimants.values()) {
      if (claimant.provenDeviceKey === undefined || claimant.declaredRoutingId === undefined) continue;
      return { devicePublicKey: claimant.provenDeviceKey, peerRoutingId: claimant.declaredRoutingId };
    }
    return undefined;
  }

  /**
   * Dial the relay and register the rendezvous.
   *
   * Resolves once registered, so the caller can avoid printing a QR for a
   * rendezvous that is not actually reachable — a QR the phone cannot dial is worse
   * than a clear failure.
   */
  start(): Promise<{ ok: true } | { ok: false; reason: string }> {
    return new Promise((resolve) => {
      let settled = false;
      const settle = (result: { ok: true } | { ok: false; reason: string }): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      };

      // A relay that accepts the TCP connection and then says nothing would
      // otherwise leave the operator staring at no QR and no error for the entire
      // pairing window.
      const timer = setTimeout(() => {
        this.note('relay did not acknowledge the rendezvous registration');
        this.close();
        settle({ ok: false, reason: 'relay did not acknowledge the rendezvous registration' });
      }, this.options.registerTimeoutMs ?? DEFAULT_REGISTER_TIMEOUT_MS);
      timer.unref?.();

      this.setState('dialing');
      let socket: WebSocketLike;
      try {
        const factory =
          this.options.webSocketFactory ??
          ((url: string, protocols: string[]) => new WebSocket(url, protocols) as unknown as WebSocketLike);
        socket = factory(this.options.relayUrl, [RELAY_SUBPROTOCOL]);
      } catch (error) {
        const reason = `relay dial failed: ${error instanceof Error ? error.message : String(error)}`;
        this.note(reason);
        this.setState('closed');
        settle({ ok: false, reason });
        return;
      }
      this.socket = socket;

      socket.addEventListener('open', () => {
        this.send({
          v: 1,
          type: 'relay/register',
          role: 'bridge',
          routingId: this.options.rendezvousId,
          mode: 'rendezvous',
        });
      });

      socket.addEventListener('message', (event) => {
        if (typeof event.data !== 'string') return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(event.data);
        } catch {
          this.note('relay sent non-JSON');
          return;
        }
        const message = parsed as Partial<RelayServerMessage> | null;
        if (typeof message !== 'object' || message === null || message.v !== 1) return;

        if (message.type === 'relay/registered') {
          this.setState('listening');
          settle({ ok: true });
          return;
        }
        if (message.type === 'relay/error') {
          const reason = `relay error ${String(message.code)}: ${String(message.message ?? '')}`;
          this.note(reason);
          // A rendezvous id already in use during our own window means something
          // else is answering for it. Refuse rather than pair through it.
          if (message.code === 'routing-id-taken') {
            this.setState('closed');
            settle({ ok: false, reason });
          }
          return;
        }
        void this.onRelayMessage(message as RelayServerMessage);
      });

      socket.addEventListener('close', () => {
        this.setState('closed');
        settle({ ok: false, reason: this.lastError ?? 'relay closed the rendezvous' });
      });

      // A refused dial fires `error` with NO following `close`, so settling only on
      // `close` would hang here — which is exactly what a bridge printing a QR must
      // never do.
      socket.addEventListener('error', () => {
        this.note('relay socket error');
        this.setState('closed');
        settle({ ok: false, reason: 'could not reach the relay' });
      });
    });
  }

  /** Drop the rendezvous and zero every pairing channel. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const claimant of this.claimants.values()) claimant.channel?.close();
    this.claimants.clear();
    const socket = this.socket;
    this.socket = undefined;
    if (socket !== undefined) {
      try {
        socket.close(1000, 'pairing window closed');
      } catch {
        // Already gone.
      }
    }
    this.setState('closed');
  }

  // ── relay layer ───────────────────────────────────────────────────────────

  private async onRelayMessage(message: RelayServerMessage): Promise<void> {
    if (message.type === 'relay/handshake') {
      // `from` is how a rendezvous learns who is calling. Without it there is
      // nothing to answer, so the frame is unusable.
      if (!isValidRoutingId(message.from)) return;
      this.onHandshake(message.from, message.hs);
      return;
    }
    if (message.type === 'relay/data') {
      if (!isValidRoutingId(message.from)) return;
      await this.onSealedRecord(message.from, message.record);
      return;
    }
    if (message.type === 'relay/peer-offline') {
      // The relay does not say which claimant left; drop channels that have not
      // proven a device key, since an unproven one has no value to preserve.
      for (const [id, claimant] of [...this.claimants]) {
        if (claimant.provenDeviceKey !== undefined) continue;
        claimant.channel?.close();
        this.claimants.delete(id);
      }
    }
  }

  private claimantFor(routingId: string): Claimant {
    const existing = this.claimants.get(routingId);
    if (existing !== undefined) return existing;
    const claimant: Claimant = {
      routingId,
      handshake: undefined,
      channel: undefined,
      handshakeSigned: false,
      deferred: undefined,
      provenDeviceKey: undefined,
      declaredRoutingId: undefined,
    };
    this.claimants.set(routingId, claimant);
    return claimant;
  }

  /**
   * Run the pairing handshake for one claimant.
   *
   * The bridge is the responder here, matching steady state, so the transcript's
   * canonical ordering is identical and there is one set of rules to reason about.
   */
  private onHandshake(from: string, raw: Record<string, unknown>): void {
    const claimant = this.claimantFor(from);
    if (claimant.channel !== undefined) {
      // A second handshake on an established pairing channel is either a confused
      // phone or an attempt to force a renegotiation. Drop it.
      this.drop(from, 'handshake on an established pairing channel');
      return;
    }
    if (typeof raw.eph !== 'string') {
      this.drop(from, 'malformed pairing handshake');
      return;
    }

    if (claimant.handshake === undefined) {
      claimant.handshake = beginPairingHandshake({
        role: 'responder',
        // Binds both routing ids, so a record from one pairing attempt cannot be
        // opened in another.
        sessionId: `${from}:${this.options.rendezvousId}`,
        bridgeStaticPublicKey: this.options.ownStaticPublicKey,
        tokenBinder: this.binder,
      });
    }
    const handshake = claimant.handshake;

    // Round one: answer the phone's ephemeral with our signed transcript. Signing
    // with the bridge's static key is what the phone verifies against the pinned
    // `bk` from the QR.
    if (!claimant.handshakeSigned) {
      claimant.handshakeSigned = true;
      const sig = signHandshake(handshake, raw.eph, this.options.ownStaticPrivateKey);
      this.send({
        v: 1,
        type: 'relay/handshake',
        hs: { v: 1, eph: handshake.message.eph, sig },
        to: from,
      });
    }

    // Round two: a signed peer message completes the exchange.
    if (typeof raw.sig !== 'string' || raw.sig.length === 0) return;

    const completed = completePairingHandshakeAsBridge(handshake, { v: 1, eph: raw.eph, sig: raw.sig });
    if (!completed.ok) {
      this.drop(from, `pairing handshake failed: ${completed.reason}`);
      return;
    }
    claimant.channel = completed.channel;
    claimant.deferred = completed.deferred;
    claimant.handshake = undefined;
    this.log(`pairing channel established with ${from}`);
  }

  private async onSealedRecord(from: string, record: unknown): Promise<void> {
    const claimant = this.claimants.get(from);
    if (claimant?.channel === undefined) {
      // Data before a channel exists cannot be read. Not fatal: a phone may have
      // sent early.
      this.note('sealed record before the pairing channel was established');
      return;
    }
    const opened = claimant.channel.openJson(record);
    if (!opened.ok) {
      // An unopenable record on a pairing channel means the path is not behaving.
      this.drop(from, `sealed record rejected: ${opened.reason}`);
      return;
    }

    const parsed = parseTunnelClientMessage(opened.value);
    if (!parsed.ok) {
      this.reply(from, claimant, { v: 1, type: 'tunnel/error', message: parsed.reason });
      return;
    }
    const message = parsed.message;

    if (message.type === 'tunnel/ping') {
      this.reply(from, claimant, { v: 1, type: 'tunnel/pong', at: message.at });
      return;
    }
    if (message.type !== 'tunnel/request') {
      // Streams and subscriptions require a paired device and a token. Neither
      // exists yet, and allowing them here would be a second way in.
      this.reply(from, claimant, { v: 1, type: 'tunnel/error', message: 'only pairing requests are allowed before pairing' });
      return;
    }
    if (!PAIRING_ALLOWED_PATHS.has(message.path) || message.method !== 'POST') {
      this.reply(from, claimant, {
        v: 1,
        type: 'tunnel/response',
        id: message.id,
        status: 404,
        body: { ok: false, error: { code: 'bad-request', message: 'not found' } },
      });
      return;
    }

    const body = message.body;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      this.reply(from, claimant, {
        v: 1,
        type: 'tunnel/response',
        id: message.id,
        status: 400,
        body: { ok: false, error: { code: 'bad-request', message: 'body must be an object' } },
      });
      return;
    }
    const fields = body as Record<string, unknown>;
    const devicePublicKey = typeof fields.devicePublicKey === 'string' ? fields.devicePublicKey : undefined;
    // The phone declares its own routing id inside the sealed channel. That is the
    // value we persist — NOT the relay-asserted `from` — because the channel is
    // bound to the device key, so this field is authenticated by that key once the
    // deferred proof passes. A relay lying about `from` can therefore misdeliver a
    // frame but cannot make us record a route it chose.
    const declaredRoutingId = typeof fields.relayRoutingId === 'string' ? fields.relayRoutingId : undefined;

    if (devicePublicKey === undefined || declaredRoutingId === undefined || !isValidRoutingId(declaredRoutingId)) {
      this.reply(from, claimant, {
        v: 1,
        type: 'tunnel/response',
        id: message.id,
        status: 400,
        body: {
          ok: false,
          error: { code: 'bad-request', message: 'devicePublicKey and a valid relayRoutingId are required over a relay' },
        },
      });
      return;
    }

    // The load-bearing check. The retained transcript signature must verify against
    // the key being claimed, which proves the holder of this channel holds that
    // device private key. Without it, anyone with the token could open a channel and
    // submit somebody else's captured claim body.
    const deferred = claimant.deferred;
    if (deferred === undefined || !verifyDeferredPeerProof(deferred, devicePublicKey)) {
      this.drop(from, 'pairing channel was not established by the claimed device key');
      return;
    }
    claimant.provenDeviceKey = devicePublicKey;
    claimant.declaredRoutingId = declaredRoutingId;

    // Strip our transport-only field before replaying the claim, so the `/m1`
    // handler sees exactly the body a LAN phone sends and there is one shape to
    // validate.
    const forwarded: Record<string, unknown> = { ...fields };
    delete forwarded.relayRoutingId;

    const response = await this.options.backend.request({
      method: 'POST',
      path: message.path,
      body: forwarded,
    });

    // On a completed pairing, mint and persist the durable route and hand the
    // bridge's routing id back inside the sealed channel. This is the value the
    // phone could not have known in advance, and the reason it never has to.
    let augmented = response.body;
    const status = response.status;
    if (status === 200 && isPairedResult(response.body)) {
      const assigned = this.options.assignRoute({ devicePublicKey, peerRoutingId: declaredRoutingId });
      if (assigned === undefined) {
        this.reply(from, claimant, {
          v: 1,
          type: 'tunnel/response',
          id: message.id,
          status: 500,
          body: { ok: false, error: { code: 'internal', message: 'could not record the relay route' } },
        });
        return;
      }
      const envelope = response.body as { ok: true; value: Record<string, unknown> };
      augmented = { ...envelope, value: { ...envelope.value, relay: { bridgeRoutingId: assigned, peerRoutingId: declaredRoutingId } } };
      this.log(`pairing completed for ${from}, route assigned`);
    }

    this.reply(from, claimant, { v: 1, type: 'tunnel/response', id: message.id, status, body: augmented });
  }

  private reply(to: string, claimant: Claimant, message: TunnelServerMessage): void {
    const channel = claimant.channel;
    if (channel === undefined || channel.isClosed()) return;
    let plaintext: Buffer;
    try {
      plaintext = Buffer.from(JSON.stringify(message), 'utf8');
    } catch {
      return;
    }
    if (plaintext.byteLength > TUNNEL_MAX_MESSAGE_BYTES) return;
    try {
      this.send({ v: 1, type: 'relay/data', record: channel.seal(plaintext), to });
    } catch (error) {
      this.note(`seal failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /** Abandon one claimant without disturbing the rendezvous or the others. */
  private drop(routingId: string, reason: string): void {
    const claimant = this.claimants.get(routingId);
    if (claimant !== undefined) {
      claimant.channel?.close();
      this.claimants.delete(routingId);
    }
    this.note(reason);
    this.log(`dropped claimant ${routingId}: ${reason}`);
  }

  private send(message: unknown): void {
    const socket = this.socket;
    if (socket === undefined) return;
    try {
      socket.send(JSON.stringify(message));
    } catch (error) {
      this.note(`send failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private setState(state: RendezvousState): void {
    if (this.state === state) return;
    this.state = state;
    this.options.onStateChange?.(state);
  }

  private note(reason: string): void {
    this.lastError = reason;
  }

  private log(line: string): void {
    if (this.options.verbose === true) console.error(`[rendezvous] ${line}`);
  }
}

/** Whether an `/m1/pair/claim` response reports a completed pairing. */
function isPairedResult(body: unknown): boolean {
  if (typeof body !== 'object' || body === null) return false;
  const envelope = body as { ok?: unknown; value?: unknown };
  if (envelope.ok !== true) return false;
  const value = envelope.value;
  if (typeof value !== 'object' || value === null) return false;
  return (value as { status?: unknown }).status === 'paired';
}

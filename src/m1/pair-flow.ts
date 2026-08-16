/**
 * [OUR DESIGN] The pairing run, from a scanned QR to a durable stored route.
 *
 * One function for both modes, because the claim body, the SAS and the operator
 * confirmation are identical on the LAN and through a relay — only the carrier
 * differs. Mode B's extra work (recompute the rendezvous id, mint our own routing
 * id, seal the channel, read the durable route out of the response) is confined to
 * `openRelayPairingTransport`.
 *
 * Three things this file is careful about, all of them the difference between
 * pairing and being paired with something else:
 *
 *   - **The QR's `rid` is never durable.** It is recomputed from the token and
 *     checked, used for exactly one rendezvous, and dropped. The durable
 *     `bridgeRoutingId` is read only from `value.relay.bridgeRoutingId` inside the
 *     sealed response.
 *   - **The bridge proves itself before the claim.** In Mode B the seal handshake
 *     verifies a signature by the pinned `bk`, so a hostile relay cannot see or
 *     alter the claim. In Mode A the pin is checked after the fact, when the
 *     bridge signs the auth challenge — the honest gap noted in `lan-transport.ts`.
 *   - **Polling is a re-POST of the same claim.** The token is spent by the first
 *     claim; the bridge answers a repeat by proof-authenticated read
 *     (`pollClaim`). So the body must be byte-identical each time, which is why it
 *     is built once and reused.
 */

import { fromBase64Url } from './bytes';
import { signDomain } from './crypto';
import type { DeviceIdentity } from './crypto';
import { M1_BRIDGE_ERROR_CODES, M1_PATHS } from './paths';
import {
  deriveRendezvousRoutingId,
  type PairingUriProblem,
  parsePairingUriStrict,
} from './pairing';
import { LanTransport } from './lan-transport';
import { RelayClient, type WebSocketFactory } from './relay';
import { classify } from './relay-transport';
import { newRoutingId, pairingTokenBinder } from './seal';
import { TunnelClient, TunnelError } from './tunnel';
import {
  type M1Transport,
  type StreamHandlers,
  type StreamSubscription,
  TransportError,
} from './transport';
import type {
  BridgeErrorCode,
  M1Response,
  PairClaimRequest,
  PairClaimResult,
  PairedRelayRoute,
  PinMismatchDetail,
  ScopeTier,
} from './types';
import type { StoredBridge } from '../storage';

/** How long to keep polling for the operator's confirmation. */
const DEFAULT_CONFIRM_TIMEOUT_MS = 130_000;
/** Gap between polls. Short enough to feel immediate, slow enough to be polite. */
const DEFAULT_POLL_INTERVAL_MS = 1_500;

export type PairFailure =
  /** The QR is not a usable pairing URI. Terminal for this code. */
  | { kind: 'bad-uri'; problem: PairingUriProblem }
  /** Token unknown, expired or already spent. A fresh QR will work. */
  | { kind: 'pairing-invalid'; message: string }
  /** The operator refused at the workstation. Terminal; needs a new QR. */
  | { kind: 'pairing-rejected'; message: string }
  /** The operator never answered inside the window. */
  | { kind: 'timeout'; message: string }
  /** Could not reach the bridge (Mode A) or the relay (Mode B). */
  | { kind: 'unreachable'; message: string }
  /** Mode B: the relay refused. `code` decides whether this is terminal. */
  | { kind: 'relay'; code: string; message: string }
  /** Mode B: the rendezvous already has as many claimants as it will take. */
  | { kind: 'rendezvous-busy'; message: string }
  /**
   * The pinned key did not verify. Terminal, and never retried: this is what a
   * man in the middle looks like.
   */
  | { kind: 'pin-mismatch'; detail: PinMismatchDetail; message: string }
  /** The bridge refused for a reason of its own, e.g. dsh is down. */
  | { kind: 'bridge-error'; code: string; message: string }
  /** The caller cancelled, or the screen was dismissed. */
  | { kind: 'cancelled'; message: string }
  /** A response that did not fit the contract. */
  | { kind: 'protocol'; message: string };

export type PairOutcome = { ok: true; bridge: StoredBridge } | { ok: false; failure: PairFailure };

export interface PairFlowHooks {
  /** The claim was accepted; show `sas` until `expiresAt`. */
  onAwaitingConfirmation: (input: { sas: string; bridgeName: string; expiresAt: number }) => void;
  /** Progress worth a label: dialing the relay, sealing, claiming. */
  onProgress?: (stage: 'connecting' | 'sealing' | 'claiming' | 'awaiting') => void;
  onDiagnostic?: (level: 'info' | 'warn' | 'error', message: string) => void;
}

export interface PairFlowOptions {
  /** The raw scanned string. Parsed and validated here, not by the caller. */
  uri: string;
  identity: DeviceIdentity;
  /** Human label shown on the workstation. */
  label: string;
  hooks: PairFlowHooks;
  /**
   * Mode A only: the bridge origin. The QR carries no host — a pairing URI is a
   * secret and an address is not — so the user supplies it.
   */
  baseUrl?: string;
  createSocket?: WebSocketFactory;
  fetchImpl?: typeof fetch;
  webSocketImpl?: typeof WebSocket;
  /** Cooperative cancellation, for a dismissed screen. */
  signal?: { aborted: boolean };
  confirmTimeoutMs?: number;
  pollIntervalMs?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Run one pairing attempt to completion.
 *
 * Always resolves — a failure is a value, not an exception — because every failure
 * here maps to a state the UI must render, and an exception would invite a caller
 * to collapse them into one "pairing failed".
 */
export async function runPairing(options: PairFlowOptions): Promise<PairOutcome> {
  const parsed = parsePairingUriStrict(options.uri);
  if (!parsed.ok) return { ok: false, failure: { kind: 'bad-uri', problem: parsed.problem } };
  const { uri, mode } = parsed;

  const now = options.now ?? (() => Date.now());
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const deadline = now() + (options.confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS);

  // Built once and reused verbatim for every poll: the bridge re-verifies this
  // exact proof against the pending key, so a re-signed body would read as an
  // unknown claim.
  const claim: PairClaimRequest = {
    v: 1,
    token: uri.tok,
    devicePublicKey: options.identity.publicKey,
    label: options.label,
    proof: signDomain(options.identity, 'pair', uri.tok, uri.bid),
  };

  options.hooks.onProgress?.('connecting');

  let carrier: PairingCarrier;
  if (mode === 'relay') {
    const opened = await openRelayPairingTransport({ uri, options, claim });
    if (!opened.ok) return { ok: false, failure: opened.failure };
    carrier = opened.carrier;
  } else {
    const baseUrl = options.baseUrl?.trim();
    if (baseUrl === undefined || baseUrl.length === 0) {
      return {
        ok: false,
        failure: { kind: 'protocol', message: 'a bridge address is required to pair over the LAN' },
      };
    }
    const transport = new LanTransport({
      baseUrl,
      ...(options.fetchImpl === undefined ? {} : { fetchImpl: options.fetchImpl }),
      ...(options.webSocketImpl === undefined ? {} : { webSocketImpl: options.webSocketImpl }),
      ...(options.hooks.onDiagnostic === undefined ? {} : { onDiagnostic: options.hooks.onDiagnostic }),
    });
    carrier = { transport, baseUrl, deviceRoutingId: undefined };
  }

  try {
    return await claimAndConfirm({ uri, mode, options, claim, carrier, deadline, now, sleep });
  } finally {
    // The pairing carrier is single-purpose. Steady state opens its own transport
    // with the durable route, so holding this one open would leave a socket and a
    // sealed channel alive for a rendezvous that no longer exists.
    carrier.transport.close();
  }
}

interface PairingCarrier {
  transport: M1Transport;
  /** Mode A: the origin to store. */
  baseUrl?: string;
  /** Mode B: the id we minted and declared, to store if pairing completes. */
  deviceRoutingId?: string;
}

/**
 * POST the claim, then poll the same body until the operator decides.
 *
 * Both the first claim and every poll go through one code path because the bridge
 * treats them the same way, and a separate poll path would be a second place for
 * the response handling to drift.
 */
async function claimAndConfirm(input: {
  uri: { bid: string; tok: string; bk: string; fp?: string; relay?: string };
  mode: 'lan' | 'relay';
  options: PairFlowOptions;
  claim: PairClaimRequest;
  carrier: PairingCarrier;
  deadline: number;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}): Promise<PairOutcome> {
  const { uri, mode, options, claim, carrier, deadline, now, sleep } = input;
  const pollInterval = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  // Mode B adds the routing id it wants recorded. The rendezvous strips it before
  // replaying the claim, so the `/m1` handler sees the LAN body.
  const body =
    carrier.deviceRoutingId === undefined ? claim : { ...claim, relayRoutingId: carrier.deviceRoutingId };

  let announced = false;
  options.hooks.onProgress?.('claiming');

  for (;;) {
    if (options.signal?.aborted === true) {
      return { ok: false, failure: { kind: 'cancelled', message: 'pairing was cancelled' } };
    }

    let response: { status: number; body: unknown };
    try {
      response = await carrier.transport.request({ method: 'POST', path: M1_PATHS.pairClaim, body });
    } catch (error) {
      return { ok: false, failure: failureFromTransport(error) };
    }

    const parsed = asPairClaimResponse(response.body);
    if (parsed === undefined) {
      return {
        ok: false,
        failure: { kind: 'protocol', message: `bridge answered ${response.status} with an unrecognized body` },
      };
    }

    if (!parsed.ok) {
      const error = parsed.error;
      switch (error.code) {
        case 'pairing-rejected':
          return { ok: false, failure: { kind: 'pairing-rejected', message: error.message } };
        case 'pairing-invalid':
          return { ok: false, failure: { kind: 'pairing-invalid', message: error.message } };
        case 'pairing-unconfirmed':
          // Documented as 409, though the current bridge answers a pending claim
          // with `awaiting-confirmation` instead. Handled so either shape polls.
          break;
        default:
          return { ok: false, failure: { kind: 'bridge-error', code: error.code, message: error.message } };
      }
    } else if (parsed.value.status === 'paired') {
      const confirmed = parsed.value;
      // The bridge must be the one we pinned. A different `bridgeId` here means
      // something else answered the claim, whatever the transport looked like.
      if (confirmed.bridgeId !== uri.bid) {
        return {
          ok: false,
          failure: {
            kind: 'pin-mismatch',
            detail: 'bridge-identity',
            message: 'the bridge that completed pairing is not the one in the QR code',
          },
        };
      }
      const stored = buildStoredBridge({ uri, mode, carrier, confirmed });
      if (!stored.ok) return { ok: false, failure: stored.failure };
      return { ok: true, bridge: stored.bridge };
    } else {
      const pending = parsed.value;
      // Check the identity here too, not just on `paired`. This response is what
      // produces the SAS digits the operator is about to compare, so if something
      // other than the pinned bridge answered, the user must not be shown a code to
      // confirm at all — confirming it would be confirming the wrong workstation.
      if (pending.bridgeId !== uri.bid) {
        return {
          ok: false,
          failure: {
            kind: 'pin-mismatch',
            detail: 'bridge-identity',
            message: 'the bridge answering this pairing is not the one in the QR code',
          },
        };
      }
      if (!announced) {
        announced = true;
        options.hooks.onProgress?.('awaiting');
        options.hooks.onAwaitingConfirmation({
          sas: pending.sas,
          bridgeName: pending.bridgeName,
          expiresAt: pending.expiresAt,
        });
      }
    }

    if (now() >= deadline) {
      return { ok: false, failure: { kind: 'timeout', message: 'the workstation did not confirm in time' } };
    }
    await sleep(pollInterval);
  }
}

/**
 * Assemble the durable record.
 *
 * The Mode B branch is where the rendezvous id would leak into storage if this were
 * careless, so it reads `bridgeRoutingId` only from the sealed response and checks
 * the echoed `peerRoutingId` against the id we actually minted. A mismatch means the
 * bridge recorded a different phone, and connecting would silently fail forever.
 */
function buildStoredBridge(input: {
  uri: { bid: string; bk: string; fp?: string; relay?: string };
  mode: 'lan' | 'relay';
  carrier: PairingCarrier;
  confirmed: {
    deviceId: string;
    bridgeId: string;
    bridgeName: string;
    scopeTier: ScopeTier;
    bridgeKeyFingerprint?: string;
    relay?: PairedRelayRoute;
  };
}): { ok: true; bridge: StoredBridge } | { ok: false; failure: PairFailure } {
  const { uri, mode, carrier, confirmed } = input;
  const base: StoredBridge = {
    mode,
    bridgeId: confirmed.bridgeId,
    bridgeName: confirmed.bridgeName,
    deviceId: confirmed.deviceId,
    bridgeKey: uri.bk,
    scopeTier: confirmed.scopeTier,
  };

  if (mode === 'lan') {
    if (carrier.baseUrl === undefined) {
      return { ok: false, failure: { kind: 'protocol', message: 'LAN pairing completed without an address' } };
    }
    base.baseUrl = carrier.baseUrl;
    // Prefer the QR's `fp`: it was seen out of band, on a screen, while the
    // response arrived over the very connection the pin is meant to protect.
    const fingerprint = uri.fp ?? confirmed.bridgeKeyFingerprint;
    if (fingerprint !== undefined) base.tlsFingerprint = fingerprint;
    return { ok: true, bridge: base };
  }

  const route = confirmed.relay;
  if (route === undefined) {
    return {
      ok: false,
      failure: {
        kind: 'protocol',
        message: 'relay pairing completed without a durable route; the bridge is too old for Mode B',
      },
    };
  }
  if (carrier.deviceRoutingId === undefined || route.peerRoutingId !== carrier.deviceRoutingId) {
    return {
      ok: false,
      failure: {
        kind: 'protocol',
        message: 'the bridge recorded a different phone routing id than the one requested',
      },
    };
  }
  if (uri.relay === undefined) {
    return { ok: false, failure: { kind: 'protocol', message: 'relay pairing completed without a relay URL' } };
  }
  base.relayUrl = uri.relay;
  base.bridgeRoutingId = route.bridgeRoutingId;
  base.deviceRoutingId = carrier.deviceRoutingId;
  return { ok: true, bridge: base };
}

/**
 * Open the Mode B pairing carrier: rendezvous, sealed channel, tunnel.
 *
 * Deliberately not a `RelayTransport`: that one registers a mutual `peer` pair with
 * a durable id and a device-key handshake. Pairing registers a fresh id against a
 * token-derived rendezvous and signs with the token binder in the static slot, and
 * folding both into one class would mean a runtime branch inside the handshake.
 */
async function openRelayPairingTransport(input: {
  uri: { bid: string; tok: string; bk: string; relay?: string; rid?: string };
  options: PairFlowOptions;
  claim: PairClaimRequest;
}): Promise<{ ok: true; carrier: PairingCarrier } | { ok: false; failure: PairFailure }> {
  const { uri, options } = input;
  const relayUrl = uri.relay;
  if (relayUrl === undefined) {
    return { ok: false, failure: { kind: 'protocol', message: 'relay pairing needs a relay URL' } };
  }
  const createSocket = options.createSocket;
  if (createSocket === undefined) {
    return { ok: false, failure: { kind: 'protocol', message: 'no WebSocket factory was provided' } };
  }

  // Recompute the rendezvous id rather than trusting the QR's. `parsePairingUriStrict`
  // already refuses a mismatch; recomputing here means the value we dial is derived
  // from the token even if a caller assembled the URI object itself.
  const rendezvousId = deriveRendezvousRoutingId(uri.tok, uri.bid);
  if (uri.rid !== undefined && uri.rid !== rendezvousId) {
    return { ok: false, failure: { kind: 'bad-uri', problem: 'rendezvous-mismatch' } };
  }

  const deviceRoutingId = newRoutingId();
  const binder = pairingTokenBinder(uri.tok, uri.bid);

  return await new Promise((resolve) => {
    let settled = false;
    const finish = (outcome: { ok: true; carrier: PairingCarrier } | { ok: false; failure: PairFailure }): void => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };

    let tunnel: TunnelClient | undefined;
    const relay = new RelayClient({
      relayUrl,
      routingId: deviceRoutingId,
      peerRoutingId: rendezvousId,
      bridgeStaticPublicKey: uri.bk,
      // The binder occupies the static slot in the transcript, but the signature is
      // still made with the device key — that is what the bridge verifies once the
      // claim reveals `devicePublicKey`.
      identity: { publicKey: options.identity.publicKey, privateKey: options.identity.privateKey },
      tokenBinder: binder,
      createSocket,
      onChannel: () => {
        options.hooks.onProgress?.('sealing');
        const client = new TunnelClient({
          transport: { send: (value) => relay.send(value), isSealed: () => relay.isSealed() },
          ...(options.hooks.onDiagnostic === undefined ? {} : { onDiagnostic: options.hooks.onDiagnostic }),
        });
        tunnel = client;
        finish({
          ok: true,
          carrier: {
            transport: new PairingTunnelTransport(client, relay),
            deviceRoutingId,
          },
        });
      },
      onRecord: (value) => tunnel?.handle(value),
      onClosed: (reason) => {
        // Once the carrier is handed over, a close surfaces as a failed request —
        // `TunnelClient.close` rejects everything outstanding. Before that, this is
        // the only channel to report on.
        tunnel?.close('relay session ended');
        finish({ ok: false, failure: failureFromTransport(classify(reason)) });
      },
      ...(options.hooks.onDiagnostic === undefined ? {} : { onDiagnostic: options.hooks.onDiagnostic }),
    });

    if (options.signal?.aborted === true) {
      finish({ ok: false, failure: { kind: 'cancelled', message: 'pairing was cancelled' } });
      return;
    }
    relay.connect();
  });
}

/** A tunnel that can carry the claim and nothing else — pairing has no stream. */
class PairingTunnelTransport implements M1Transport {
  readonly mode = 'relay' as const;
  private readonly tunnel: TunnelClient;
  private readonly relay: RelayClient;

  constructor(tunnel: TunnelClient, relay: RelayClient) {
    this.tunnel = tunnel;
    this.relay = relay;
  }

  async start(): Promise<void> {
    // The channel was already sealed before this transport existed.
  }

  async request(request: {
    method: 'GET' | 'POST';
    path: string;
    token?: string;
    body?: unknown;
  }): Promise<{ status: number; body: unknown }> {
    try {
      return await this.tunnel.request(request);
    } catch (error) {
      if (error instanceof TunnelError) {
        const kind = error.failure.kind === 'timeout' ? 'timeout' : error.failure.kind === 'offline' ? 'offline' : 'transport';
        throw new TransportError(kind, error.failure.message);
      }
      throw new TransportError('transport', error instanceof Error ? error.message : String(error));
    }
  }

  subscribe(request: { token: string; after: number; handlers: StreamHandlers }): StreamSubscription {
    // A rendezvous refuses anything but the claim, so this cannot succeed. Failing
    // locally is clearer than letting the bridge answer `tunnel/error`.
    request.handlers.onClosed('a pairing channel carries no event stream');
    return { stop: () => undefined };
  }

  close(): void {
    this.tunnel.close('pairing finished');
    this.relay.close('pairing finished');
  }
}

/** Map a transport failure onto the pairing taxonomy. */
export function failureFromTransport(error: unknown): PairFailure {
  if (!(error instanceof TransportError)) {
    return { kind: 'unreachable', message: error instanceof Error ? error.message : String(error) };
  }
  if (error.kind === 'pin-mismatch') {
    return {
      kind: 'pin-mismatch',
      detail: error.pinDetail ?? 'bridge-static-key',
      message: error.message,
    };
  }
  if (error.relayCode === 'rendezvous-busy') {
    return { kind: 'rendezvous-busy', message: error.message };
  }
  if (error.relayCode !== undefined) {
    return { kind: 'relay', code: error.relayCode, message: error.message };
  }
  if (error.kind === 'timeout') return { kind: 'timeout', message: error.message };
  return { kind: 'unreachable', message: error.message };
}

/**
 * Validate a `/m1/pair/claim` response body.
 *
 * Structural, because this arrives before any trust is established and a
 * half-shaped `paired` result would be stored as a route that can never
 * authenticate.
 */
export function asPairClaimResponse(value: unknown): M1Response<PairClaimResult> | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;

  if (record.ok === false) {
    const error = record.error;
    if (typeof error !== 'object' || error === null) return undefined;
    const fields = error as Record<string, unknown>;
    if (typeof fields.code !== 'string') return undefined;
    return {
      ok: false,
      error: {
        // An unrecognized code folds to `internal` rather than being rejected: a
        // newer bridge adding a code should read as "the bridge refused", not as a
        // protocol violation.
        code: (M1_BRIDGE_ERROR_CODES as readonly string[]).includes(fields.code)
          ? (fields.code as BridgeErrorCode)
          : 'internal',
        message: typeof fields.message === 'string' ? fields.message : '',
      },
    };
  }
  if (record.ok !== true) return undefined;

  const value_ = record.value;
  if (typeof value_ !== 'object' || value_ === null) return undefined;
  const fields = value_ as Record<string, unknown>;

  if (fields.status === 'awaiting-confirmation') {
    if (typeof fields.sas !== 'string' || fields.sas.length === 0) return undefined;
    if (typeof fields.bridgeId !== 'string' || fields.bridgeId.length === 0) return undefined;
    return {
      ok: true,
      value: {
        status: 'awaiting-confirmation',
        sas: fields.sas,
        bridgeName: typeof fields.bridgeName === 'string' ? fields.bridgeName : 'workstation',
        bridgeId: fields.bridgeId,
        expiresAt: typeof fields.expiresAt === 'number' ? fields.expiresAt : 0,
      },
    };
  }

  if (fields.status !== 'paired') return undefined;
  if (typeof fields.deviceId !== 'string' || fields.deviceId.length === 0) return undefined;
  if (typeof fields.bridgeId !== 'string' || fields.bridgeId.length === 0) return undefined;
  const scopeTier = fields.scopeTier === 'extended' ? 'extended' : 'default';
  const route = asPairedRelayRoute(fields.relay);
  const confirmed: PairClaimResult = {
    status: 'paired',
    deviceId: fields.deviceId,
    bridgeId: fields.bridgeId,
    bridgeName: typeof fields.bridgeName === 'string' ? fields.bridgeName : 'workstation',
    scopeTier,
    ...(typeof fields.bridgeKeyFingerprint === 'string'
      ? { bridgeKeyFingerprint: fields.bridgeKeyFingerprint }
      : {}),
    ...(route === undefined ? {} : { relay: route }),
  };
  return { ok: true, value: confirmed };
}

function asPairedRelayRoute(value: unknown): PairedRelayRoute | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  const bridgeRoutingId = record.bridgeRoutingId;
  const peerRoutingId = record.peerRoutingId;
  if (typeof bridgeRoutingId !== 'string' || typeof peerRoutingId !== 'string') return undefined;
  // Shape-checked here as well as in storage: a malformed id would be dialed
  // before it was ever read back.
  if (fromBase64Url(bridgeRoutingId)?.length !== 16) return undefined;
  if (fromBase64Url(peerRoutingId)?.length !== 16) return undefined;
  return { bridgeRoutingId, peerRoutingId };
}

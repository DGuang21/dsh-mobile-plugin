/**
 * [OUR DESIGN] Phone-side relay control client.
 *
 * Owns one WebSocket to the relay and nothing above it: register a routing id,
 * exchange opaque handshake blobs and sealed records with one peer, notice when
 * the peer comes and goes. It deliberately does not know what a tunnel request is
 * — that lives in `tunnel.ts`, on top of the sealed channel this establishes.
 *
 * The relay is hostile by assumption. Concretely, that shapes three things here:
 *
 *   - **Nothing the relay says is trusted as fact.** `peer-online` is a hint to
 *     start a handshake, not evidence that the bridge is real. Only the pinned
 *     Ed25519 static key decides that, in `seal.ts`.
 *   - **The first frame matters.** A relay admits a phone to a rendezvous's
 *     claimant set on its FIRST frame (`bridge/src/relay/server.ts`), so the
 *     handshake is sent immediately on `relay/registered` rather than waiting for
 *     a peer notification that never comes for a rendezvous.
 *   - **A handshake frame is single-shot per attempt.** A second one, from a
 *     confused bridge or a relay trying to force a renegotiation it could observe,
 *     tears the session down instead of re-deriving keys.
 *
 * The socket is injected (`WebSocketLike`) rather than constructed, so this runs
 * unchanged on RN, in a browser, and under Node in tests with `ws`.
 */

import {
  type CompleteResult,
  type SealHandshake,
  SealedChannel,
  type SealedRecord,
  beginHandshake,
  beginPairingHandshake,
  completeHandshake,
  isValidRoutingId,
  signHandshake,
} from './seal';
import type { RelayErrorCode } from './types';

export const RELAY_PROTOCOL_VERSION = 1;
export const RELAY_SUBPROTOCOL = 'dshm.relay.v1';

export type RelayRole = 'bridge' | 'phone';
export type RelayRegisterMode = 'peer' | 'rendezvous';

/**
 * The subset of `WebSocket` this needs.
 *
 * Matches `bridge/src/relay/connector.ts`'s own `WebSocketLike` so a test can
 * drive both ends with the same fake.
 */
export interface WebSocketLike {
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'open', listener: () => void): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'close', listener: () => void): void;
  addEventListener(type: 'error', listener: (event: unknown) => void): void;
}

export type WebSocketFactory = (url: string, subprotocols: readonly string[]) => WebSocketLike;

/** Why a relay session ended. */
export type RelayCloseReason =
  /** The socket closed, or never opened. Retryable. */
  | { kind: 'transport'; message: string }
  /** The relay reported an error code. */
  | { kind: 'relay-error'; code: RelayErrorCode; message: string }
  /**
   * The sealed handshake failed. This is the branch a man-in-the-middle lands in:
   * the peer could not sign the transcript with the pinned key.
   */
  | { kind: 'handshake'; reason: string }
  /** A sealed record would not open. The path is not behaving; fail closed. */
  | { kind: 'seal'; reason: string }
  /** We closed it deliberately. */
  | { kind: 'local'; message: string };

export interface RelayClientOptions {
  /** Relay origin, e.g. `https://relay.example`. Scheme is upgraded to wss. */
  relayUrl: string;
  /** Our own routing id: durable in steady state, freshly minted for pairing. */
  routingId: string;
  /**
   * The peer to talk to. In steady state this is the durable `bridgeRoutingId`;
   * for pairing it is the rendezvous id recomputed from the token.
   */
  peerRoutingId: string;
  /** base64url raw Ed25519 static key of the bridge, pinned from the QR. */
  bridgeStaticPublicKey: string;
  /**
   * Steady state: our device public key and the private key to sign with. Absent
   * for pairing, where the token binder stands in for our static key.
   */
  identity?: { publicKey: string; privateKey: Uint8Array };
  /**
   * Pairing only: the token binder from `pairingTokenBinder`. Its presence is what
   * selects the pairing handshake variant.
   */
  tokenBinder?: string;
  createSocket: WebSocketFactory;
  onChannel: (channel: SealedChannel) => void;
  onRecord: (plaintext: unknown) => void;
  onClosed: (reason: RelayCloseReason) => void;
  onDiagnostic?: (level: 'info' | 'warn' | 'error', message: string) => void;
}

type Phase = 'idle' | 'opening' | 'registering' | 'handshaking' | 'sealed' | 'closed';

/**
 * One attempt at a relay session. Not reusable: `close()` is terminal, and a
 * reconnect constructs a new instance so no state can leak across attempts.
 */
export class RelayClient {
  private readonly options: RelayClientOptions;
  private socket: WebSocketLike | undefined;
  private phase: Phase = 'idle';
  private handshake: SealHandshake | undefined;
  private handshakeSigned = false;
  /** The peer ephemeral we committed to. A change mid-handshake is hostile. */
  private peerEphemeral: string | undefined;
  private channel: SealedChannel | undefined;
  private closeReported = false;

  constructor(options: RelayClientOptions) {
    this.options = options;
  }

  /** Open the socket and register. Returns immediately; progress is via callbacks. */
  connect(): void {
    if (this.phase !== 'idle') return;
    this.phase = 'opening';

    let socket: WebSocketLike;
    try {
      socket = this.options.createSocket(relayWebSocketUrl(this.options.relayUrl), [RELAY_SUBPROTOCOL]);
    } catch (error) {
      this.finish({ kind: 'transport', message: `could not open a relay socket: ${errorText(error)}` });
      return;
    }
    this.socket = socket;

    socket.addEventListener('open', () => this.onOpen());
    socket.addEventListener('message', (event) => this.onMessage(event.data));
    socket.addEventListener('close', () => {
      // A close during a healthy session is still a close: the tunnel is gone and
      // the caller has to reconnect.
      this.finish({ kind: 'transport', message: 'relay socket closed' });
    });
    socket.addEventListener('error', () => {
      // Browsers and RN deliberately withhold the cause of a WebSocket error, so
      // there is nothing more specific to report here.
      this.finish({ kind: 'transport', message: 'relay socket error' });
    });
  }

  /** Seal and send an application frame. False when there is no live channel. */
  send(value: unknown): boolean {
    const channel = this.channel;
    if (channel === undefined || channel.isClosed()) return false;
    let record: SealedRecord;
    try {
      record = channel.sealJson(value);
    } catch (error) {
      // Counter exhaustion or a closed channel. Either way this session is done.
      this.finish({ kind: 'seal', reason: `could not seal a frame: ${errorText(error)}` });
      return false;
    }
    this.sendControl({ v: 1, type: 'relay/data', record, ...this.targetField() });
    return true;
  }

  /** Control-layer liveness, usable before a tunnel exists. */
  ping(): void {
    if (this.phase === 'closed') return;
    this.sendControl({ v: 1, type: 'relay/ping', at: Date.now() });
  }

  /** Close politely. Idempotent. */
  close(message = 'closed locally'): void {
    if (this.phase === 'closed') return;
    if (this.socket !== undefined && this.phase !== 'opening') {
      this.sendControl({ v: 1, type: 'relay/bye' });
    }
    this.finish({ kind: 'local', message });
  }

  isSealed(): boolean {
    return this.phase === 'sealed';
  }

  private onOpen(): void {
    this.phase = 'registering';
    // Steady state is always a mutual `peer` registration. A phone may never
    // register a rendezvous — the relay refuses it, and wanting to would mean
    // wanting to receive someone else's pairing traffic.
    this.sendControl({
      v: 1,
      type: 'relay/register',
      role: 'phone',
      routingId: this.options.routingId,
      mode: 'peer' satisfies RelayRegisterMode,
      peerRoutingId: this.options.peerRoutingId,
    });
  }

  private onMessage(data: unknown): void {
    if (this.phase === 'closed') return;
    if (typeof data !== 'string') {
      // The relay protocol is JSON text. A binary frame means we are not talking
      // to the relay we think we are.
      this.finish({ kind: 'transport', message: 'relay sent a non-text frame' });
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      this.finish({ kind: 'transport', message: 'relay sent non-JSON' });
      return;
    }
    const message = parsed as Record<string, unknown> | null;
    if (typeof message !== 'object' || message === null || message.v !== RELAY_PROTOCOL_VERSION) {
      this.finish({ kind: 'transport', message: 'relay sent an unsupported message' });
      return;
    }

    switch (message.type) {
      case 'relay/registered':
        this.onRegistered(message.peerPresent === true);
        return;
      case 'relay/peer-online':
        // Steady state: the bridge just arrived. It will send its own ephemeral,
        // but starting ours now saves a round trip.
        this.beginSeal();
        return;
      case 'relay/peer-offline':
        // The bridge is gone. Tearing the session down rather than holding keys
        // open means a returning bridge must prove itself again.
        this.finish({ kind: 'transport', message: 'bridge went offline' });
        return;
      case 'relay/handshake':
        this.onHandshakeFrame(message.hs);
        return;
      case 'relay/data':
        this.onSealedRecord(message.record);
        return;
      case 'relay/pong':
        return;
      case 'relay/error':
        this.onRelayError(message.code, message.message);
        return;
      default:
        this.finish({ kind: 'transport', message: 'relay sent an unknown message type' });
    }
  }

  /**
   * Registered. Start the handshake now, without waiting.
   *
   * This is the asymmetry that matters for pairing: a bridge holding a rendezvous
   * gets no `peer-online` for us, and the relay only admits us to its claimant set
   * when it sees our first frame. Waiting for a notification would deadlock. In
   * steady state sending early is harmless — the bridge treats an early handshake
   * as the trigger to begin its own.
   */
  private onRegistered(peerPresent: boolean): void {
    this.note('info', `registered at the relay, bridge ${peerPresent ? 'present' : 'absent'}`);
    this.beginSeal();
  }

  private beginSeal(): void {
    if (this.channel !== undefined) return;
    if (this.handshake !== undefined) return;
    this.phase = 'handshaking';

    // Session id must match what the bridge computes, or no signature verifies.
    // Pairing: `<phone>:<rendezvous>` (rendezvous.ts). Steady state: the bridge
    // builds `${peerRoutingId}:${routingId}` from its own point of view, which is
    // phone-first — the same string.
    const sessionId = `${this.options.routingId}:${this.options.peerRoutingId}`;

    if (this.options.tokenBinder !== undefined) {
      this.handshake = beginPairingHandshake({
        role: 'initiator',
        sessionId,
        bridgeStaticPublicKey: this.options.bridgeStaticPublicKey,
        tokenBinder: this.options.tokenBinder,
      });
    } else {
      const identity = this.options.identity;
      if (identity === undefined) {
        // Neither a binder nor an identity: nothing could sign a transcript. A
        // caller bug, caught here rather than producing an unexplained failure.
        this.finish({ kind: 'handshake', reason: 'no device identity and no pairing binder' });
        return;
      }
      this.handshake = beginHandshake({
        role: 'initiator',
        sessionId,
        ownStaticPublicKey: identity.publicKey,
        peerStaticPublicKey: this.options.bridgeStaticPublicKey,
      });
    }

    this.handshakeSigned = false;
    this.sendControl({
      v: 1,
      type: 'relay/handshake',
      hs: { v: 1, eph: this.handshake.message.eph, sig: '' },
      ...this.targetField(),
    });
  }

  private onHandshakeFrame(raw: unknown): void {
    if (this.channel !== undefined) {
      // A second handshake on an established tunnel is either a confused bridge or
      // a relay trying to force a renegotiation it could observe.
      this.finish({ kind: 'handshake', reason: 'handshake on an established tunnel' });
      return;
    }
    if (this.handshake === undefined) this.beginSeal();
    const handshake = this.handshake;
    if (handshake === undefined) return;

    const message = raw as { eph?: unknown; sig?: unknown } | null;
    if (typeof message !== 'object' || message === null || typeof message.eph !== 'string') {
      this.finish({ kind: 'handshake', reason: 'malformed peer handshake' });
      return;
    }

    // Pin the peer ephemeral on first sight. The transcript we sign commits to it,
    // so letting it change mid-exchange would let a relay harvest our signature
    // over transcripts of its choosing.
    if (this.peerEphemeral === undefined) this.peerEphemeral = message.eph;
    else if (this.peerEphemeral !== message.eph) {
      this.finish({ kind: 'handshake', reason: 'peer changed its ephemeral key mid-handshake' });
      return;
    }

    // Round one: now that the peer ephemeral is known, sign and answer. Our
    // signature is what the bridge verifies — immediately in steady state, or
    // deferred until the claim reveals our device key during pairing.
    if (!this.handshakeSigned) {
      this.handshakeSigned = true;
      const signingKey = this.signingKey();
      if (signingKey === undefined) {
        this.finish({ kind: 'handshake', reason: 'no key available to sign the handshake' });
        return;
      }
      this.sendControl({
        v: 1,
        type: 'relay/handshake',
        hs: { v: 1, eph: handshake.message.eph, sig: signHandshake(handshake, message.eph, signingKey) },
        ...this.targetField(),
      });
    }

    // Round two: an unsigned frame was just the peer's ephemeral.
    if (typeof message.sig !== 'string' || message.sig.length === 0) return;

    // Both variants land here: the phone always holds the bridge's pinned key, so
    // it always verifies in full. There is no path that skips this.
    const completed: CompleteResult = completeHandshake(handshake, { v: 1, eph: message.eph, sig: message.sig });
    if (!completed.ok) {
      this.finish({ kind: 'handshake', reason: completed.reason });
      return;
    }

    this.channel = completed.channel;
    this.handshake = undefined;
    this.phase = 'sealed';
    this.note('info', 'sealed tunnel established');
    this.options.onChannel(completed.channel);
  }

  private onSealedRecord(record: unknown): void {
    const channel = this.channel;
    if (channel === undefined) {
      // Data before the handshake completed cannot be read. Not fatal on its own:
      // a bridge may have sent early.
      this.note('warn', 'sealed record arrived before the tunnel was established');
      return;
    }
    const opened = channel.openJson(record);
    if (!opened.ok) {
      // Fail closed. A record that will not open means the path is not behaving —
      // tampering, misrouting, or a replay — and continuing would mean trusting a
      // stream we cannot authenticate.
      this.finish({ kind: 'seal', reason: opened.reason });
      return;
    }
    this.options.onRecord(opened.value);
  }

  /**
   * The relay reported an error.
   *
   * Only the codes that make this session unusable end it. `peer-offline` on a send
   * is transient — the bridge may be reconnecting — but there is nothing to do with
   * a tunnel whose peer is not there, so it ends the attempt and lets the caller
   * back off. `routing-id-taken` is the one code that will not fix itself, and the
   * caller distinguishes it to reach `routing-collision`.
   */
  private onRelayError(rawCode: unknown, rawMessage: unknown): void {
    const code = normalizeRelayErrorCode(rawCode);
    const message = typeof rawMessage === 'string' ? rawMessage : '';
    this.note('warn', `relay error ${code}: ${message}`);
    this.finish({ kind: 'relay-error', code, message });
  }

  /**
   * The signing key for our transcript.
   *
   * During pairing the binder occupies our static slot in the transcript, but the
   * signature is still made with the real device key — that is what lets the bridge
   * bind this channel to the key in the claim. So the same key signs in both modes.
   */
  private signingKey(): Uint8Array | undefined {
    return this.options.identity?.privateKey;
  }

  /**
   * `to` is required when the peer is a rendezvous holder, which has no single
   * fixed peer, and harmless otherwise. Always naming it keeps one code path.
   */
  private targetField(): { to: string } {
    return { to: this.options.peerRoutingId };
  }

  private sendControl(message: unknown): void {
    const socket = this.socket;
    if (socket === undefined || this.phase === 'closed') return;
    try {
      socket.send(JSON.stringify(message));
    } catch (error) {
      this.finish({ kind: 'transport', message: `relay send failed: ${errorText(error)}` });
    }
  }

  /**
   * End the session exactly once.
   *
   * Every failure path routes through here, so keys are always wiped and the
   * caller always hears one reason — the first one, since later events are
   * consequences of it rather than new information.
   */
  private finish(reason: RelayCloseReason): void {
    if (this.closeReported) return;
    this.closeReported = true;
    this.phase = 'closed';

    this.channel?.close();
    this.channel = undefined;
    this.handshake = undefined;
    this.peerEphemeral = undefined;

    const socket = this.socket;
    this.socket = undefined;
    if (socket !== undefined) {
      try {
        socket.close(1000, 'closing');
      } catch {
        // Already closing, or a socket that does not like being closed twice.
        // Nothing useful to do about it.
      }
    }

    this.options.onClosed(reason);
  }

  private note(level: 'info' | 'warn' | 'error', message: string): void {
    this.options.onDiagnostic?.(level, message);
  }
}

/**
 * Relay origins are given as https; the control channel is a WebSocket.
 *
 * `http`/`ws` are accepted and mapped for local testing. Anything else is left
 * alone, so a caller that already has a `wss://` URL is not mangled.
 */
export function relayWebSocketUrl(relayUrl: string): string {
  const trimmed = relayUrl.trim().replace(/\/+$/, '');
  if (trimmed.startsWith('https://')) return `wss://${trimmed.slice('https://'.length)}`;
  if (trimmed.startsWith('http://')) return `ws://${trimmed.slice('http://'.length)}`;
  return trimmed;
}

const RELAY_ERROR_CODES: readonly RelayErrorCode[] = [
  'bad-message',
  'routing-id-taken',
  'not-registered',
  'peer-offline',
  'quota-exceeded',
  'rendezvous-busy',
  'internal',
];

/**
 * Fold an unknown code into the taxonomy.
 *
 * A relay could send anything. Mapping the unrecognized to `internal` means new
 * relay codes degrade to "relay problem, back off" rather than to a crash or a
 * silently ignored error.
 */
export function normalizeRelayErrorCode(value: unknown): RelayErrorCode {
  return typeof value === 'string' && (RELAY_ERROR_CODES as readonly string[]).includes(value)
    ? (value as RelayErrorCode)
    : 'internal';
}

/** Re-exported so callers validate ids without importing the seal module. */
export { isValidRoutingId };

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

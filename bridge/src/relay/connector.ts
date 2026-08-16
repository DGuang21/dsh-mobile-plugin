/**
 * [OUR DESIGN] Outbound relay connector.
 *
 * Runs on the workstation, beside the bridge. It dials *out* to the relay, which is
 * the whole reason the relay exists: no inbound port, no router configuration, no
 * dynamic DNS, and nothing listening on the public internet.
 *
 * Layering, outermost first:
 *   WSS to the relay → relay control protocol (protocol.ts) → sealed channel
 *   (seal.ts) → tunnel messages (tunnel.ts) → the bridge's own `/m1` routes
 *   (backend.ts).
 *
 * The relay is assumed hostile. Everything it could do — drop, reorder, replay,
 * forge, or substitute itself for the peer — is either detected by the sealed layer
 * or degrades to a disconnect. What it can still do is observe timing and volume,
 * and refuse service; neither is fixable at this layer.
 *
 * `[NOT INTEGRATION-TESTED]`: no real phone and no deployed relay have exercised
 * this. It is tested against the in-repo relay server over a real WebSocket.
 */

import type { KeyObject } from 'node:crypto';
import {
  RELAY_SUBPROTOCOL,
  type RelayErrorCode,
  type RelayServerMessage,
  isValidRoutingId,
} from './protocol.ts';
import {
  type SealHandshake,
  type SealedChannel,
  beginHandshake,
  completeHandshake,
  signHandshake,
} from './seal.ts';
import {
  TUNNEL_MAX_MESSAGE_BYTES,
  type TunnelServerMessage,
  parseTunnelClientMessage,
} from './tunnel.ts';
import type { TunnelBackend, TunnelStream } from './backend.ts';

export type ConnectorState =
  /** Not started, or stopped. */
  | 'idle'
  /** TCP/TLS dial in flight. */
  | 'dialing'
  /** Socket open, routing id claimed, waiting for the peer. */
  | 'registered'
  /** Peer present, seal handshake in flight. */
  | 'handshaking'
  /** Sealed channel established. Traffic can flow. */
  | 'tunneled'
  /** Backing off before the next dial. */
  | 'backoff';

export interface ConnectorOptions {
  /** Relay URL, e.g. `wss://relay.example/relay/v1`. */
  relayUrl: string;
  /** This bridge's routing id, agreed with the phone at pairing time. */
  routingId: string;
  /** The phone's routing id. */
  peerRoutingId: string;
  /** base64url raw Ed25519 public key of this bridge. */
  ownStaticPublicKey: string;
  /** Ed25519 private key of this bridge. Never leaves the process. */
  ownStaticPrivateKey: KeyObject;
  /** base64url raw Ed25519 public key of the paired phone, pinned at pairing. */
  peerStaticPublicKey: string;
  backend: TunnelBackend;
  /** Injected for tests; defaults to the global WebSocket. */
  webSocketFactory?: (url: string, protocols: string[]) => WebSocketLike;
  minBackoffMs?: number;
  maxBackoffMs?: number;
  now?: () => number;
  onStateChange?: (state: ConnectorState) => void;
  verbose?: boolean;
}

/**
 * The slice of the WebSocket API this uses.
 *
 * Node 22 supplies a global `WebSocket`, but naming a narrow interface keeps the
 * connector testable without a network and documents exactly what is relied upon.
 */
export interface WebSocketLike {
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'open', listener: () => void): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'close', listener: (event: { code: number; reason: string }) => void): void;
  addEventListener(type: 'error', listener: (event: unknown) => void): void;
}

export class RelayConnector {
  private readonly options: ConnectorOptions;
  private readonly now: () => number;
  private readonly minBackoffMs: number;
  private readonly maxBackoffMs: number;
  private socket: WebSocketLike | undefined;
  private state: ConnectorState = 'idle';
  private handshake: SealHandshake | undefined;
  private channel: SealedChannel | undefined;
  /** Set once we have sent our signed handshake message for this attempt. */
  private handshakeSigned = false;
  private stream: TunnelStream | undefined;
  private stopped = true;
  private attempt = 0;
  private backoffTimer: NodeJS.Timeout | undefined;
  private sessionSeq = 0;
  private lastError: string | undefined;
  /**
   * Bounded history of recent failures.
   *
   * A single `lastError` slot is not enough: a redial that races the relay's
   * cleanup of the previous socket reports `routing-id-taken`, which would
   * overwrite the reason the connection dropped in the first place — exactly the
   * detail an operator needs.
   */
  private readonly recentErrors: string[] = [];
  private framesIn = 0;
  private framesOut = 0;

  constructor(options: ConnectorOptions) {
    if (!isValidRoutingId(options.routingId) || !isValidRoutingId(options.peerRoutingId)) {
      throw new Error('routing ids must be 22-char base64url values');
    }
    if (options.routingId === options.peerRoutingId) {
      throw new Error('routingId and peerRoutingId must differ');
    }
    this.options = options;
    this.now = options.now ?? Date.now;
    this.minBackoffMs = options.minBackoffMs ?? 1_000;
    this.maxBackoffMs = options.maxBackoffMs ?? 60_000;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.attempt = 0;
    this.dial();
  }

  stop(): void {
    this.stopped = true;
    if (this.backoffTimer !== undefined) {
      clearTimeout(this.backoffTimer);
      this.backoffTimer = undefined;
    }
    this.teardown('stopped');
    this.setState('idle');
  }

  getState(): ConnectorState {
    return this.state;
  }

  stats(): {
    state: ConnectorState;
    attempt: number;
    framesIn: number;
    framesOut: number;
    tunneled: boolean;
    lastError: string | undefined;
    recentErrors: string[];
  } {
    return {
      state: this.state,
      attempt: this.attempt,
      framesIn: this.framesIn,
      framesOut: this.framesOut,
      tunneled: this.channel !== undefined,
      lastError: this.lastError,
      recentErrors: [...this.recentErrors],
    };
  }

  /** Record a failure reason, keeping the last few. */
  private noteError(reason: string): void {
    this.lastError = reason;
    this.recentErrors.push(reason);
    if (this.recentErrors.length > 10) this.recentErrors.shift();
  }

  // ── dial / redial ─────────────────────────────────────────────────────────

  private dial(): void {
    if (this.stopped) return;
    this.setState('dialing');
    this.sessionSeq += 1;
    const session = this.sessionSeq;

    let socket: WebSocketLike;
    try {
      const factory =
        this.options.webSocketFactory ??
        ((url: string, protocols: string[]) => new WebSocket(url, protocols) as unknown as WebSocketLike);
      socket = factory(this.options.relayUrl, [RELAY_SUBPROTOCOL]);
    } catch (error) {
      // A malformed URL fails synchronously and would otherwise never retry.
      this.fail(`dial failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    this.socket = socket;

    socket.addEventListener('open', () => {
      if (this.isStale(session)) return;
      this.log('relay socket open');
      this.sendControl({
        v: 1,
        type: 'relay/register',
        role: 'bridge',
        routingId: this.options.routingId,
        // Explicit rather than relying on the default: a steady-state tunnel must
        // get the mutual-naming rules, and a mode this connector never intends to
        // use should not be reachable by omission.
        mode: 'peer',
        peerRoutingId: this.options.peerRoutingId,
      });
    });

    socket.addEventListener('message', (event) => {
      if (this.isStale(session)) return;
      if (typeof event.data !== 'string') return;
      this.onControlText(event.data);
    });

    socket.addEventListener('error', () => {
      if (this.isStale(session)) return;
      // The DOM error event carries no useful detail; the close event follows.
      this.noteError('relay socket error');
    });

    socket.addEventListener('close', (event) => {
      if (this.isStale(session)) return;
      this.log(`relay socket closed ${event.code} ${event.reason}`);
      this.teardown(event.reason || `closed ${event.code}`);
      this.scheduleRedial();
    });
  }

  /** True if this event belongs to a superseded dial attempt. */
  private isStale(session: number): boolean {
    return this.stopped || session !== this.sessionSeq;
  }

  private scheduleRedial(): void {
    if (this.stopped) return;
    this.attempt += 1;
    // Exponential with full jitter. Jitter matters here: without it, every bridge
    // pointed at a relay that just restarted would redial in lockstep.
    const ceiling = Math.min(this.maxBackoffMs, this.minBackoffMs * 2 ** Math.min(this.attempt - 1, 10));
    const delay = this.minBackoffMs + Math.floor(Math.random() * Math.max(1, ceiling - this.minBackoffMs));
    this.setState('backoff');
    this.log(`redial in ${delay}ms (attempt ${this.attempt})`);
    this.backoffTimer = setTimeout(() => {
      this.backoffTimer = undefined;
      this.dial();
    }, delay);
    this.backoffTimer.unref?.();
  }

  private fail(reason: string): void {
    this.noteError(reason);
    this.teardown(reason);
    this.scheduleRedial();
  }

  private teardown(reason: string): void {
    this.handshake = undefined;
    this.handshakeSigned = false;
    if (this.channel !== undefined) {
      // Zeroes the record keys. A redial always renegotiates; there is no session
      // resumption, deliberately — resumption is where nonce reuse bugs live.
      this.channel.close();
      this.channel = undefined;
    }
    if (this.stream !== undefined) {
      this.stream.close();
      this.stream = undefined;
    }
    const socket = this.socket;
    this.socket = undefined;
    if (socket !== undefined) {
      try {
        socket.close(1000, reason.slice(0, 120));
      } catch {
        // Already gone.
      }
    }
  }

  private setState(state: ConnectorState): void {
    if (this.state === state) return;
    this.state = state;
    this.options.onStateChange?.(state);
  }

  // ── relay control layer ───────────────────────────────────────────────────

  private onControlText(text: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      this.fail('relay sent non-JSON');
      return;
    }
    const message = parsed as Partial<RelayServerMessage> | null;
    if (typeof message !== 'object' || message === null || message.v !== 1) {
      this.fail('relay sent an unsupported message');
      return;
    }

    switch (message.type) {
      case 'relay/registered': {
        this.setState('registered');
        this.log(`registered, peer ${message.peerPresent === true ? 'present' : 'absent'}`);
        return;
      }
      case 'relay/peer-online': {
        // The phone is here. Start the seal handshake; until it completes, nothing
        // the relay says is trusted.
        this.beginSeal();
        return;
      }
      case 'relay/peer-offline': {
        // Tear the sealed session down rather than keeping keys alive for a peer
        // that is gone: a returning phone must prove itself again.
        this.log('peer offline, dropping sealed session');
        if (this.channel !== undefined) {
          this.channel.close();
          this.channel = undefined;
        }
        this.handshake = undefined;
        this.handshakeSigned = false;
        this.closeStream('peer offline');
        this.setState('registered');
        return;
      }
      case 'relay/handshake': {
        this.onSealHandshake(message.hs);
        return;
      }
      case 'relay/data': {
        void this.onSealedRecord(message.record);
        return;
      }
      case 'relay/pong':
        return;
      case 'relay/error': {
        const code = message.code as RelayErrorCode | undefined;
        this.noteError(`relay error ${code ?? 'unknown'}: ${String(message.message ?? '')}`);
        this.log(this.lastError ?? '');
        // `routing-id-taken` is the one error that will not fix itself by retrying
        // quickly: something else holds our id. Back off like everything else, but
        // do not treat it as a transient blip.
        if (code === 'routing-id-taken') this.fail('routing id already in use');
        return;
      }
      default:
        this.fail('relay sent an unknown message type');
    }
  }

  private sendControl(message: unknown): void {
    const socket = this.socket;
    if (socket === undefined) return;
    try {
      socket.send(JSON.stringify(message));
    } catch (error) {
      this.noteError(`send failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // ── sealed handshake ──────────────────────────────────────────────────────

  /**
   * Send our ephemeral.
   *
   * The bridge is the responder: the phone initiates. Roles are fixed rather than
   * negotiated, because the transcript's canonical field order depends on them and a
   * negotiable role would be one more thing a hostile relay could try to confuse.
   */
  private beginSeal(): void {
    if (this.channel !== undefined) return;
    if (this.handshake !== undefined) return;
    this.setState('handshaking');
    this.handshake = beginHandshake({
      role: 'responder',
      // Session id binds both routing ids, so a record from one tunnel cannot be
      // opened in another even if keys were somehow shared.
      sessionId: `${this.options.peerRoutingId}:${this.options.routingId}`,
      ownStaticPublicKey: this.options.ownStaticPublicKey,
      peerStaticPublicKey: this.options.peerStaticPublicKey,
    });
    this.handshakeSigned = false;
    this.sendControl({ v: 1, type: 'relay/handshake', hs: { v: 1, eph: this.handshake.message.eph, sig: '' } });
  }

  private onSealHandshake(raw: unknown): void {
    if (this.channel !== undefined) {
      // A second handshake on an established tunnel is either a confused peer or a
      // relay trying to force a renegotiation it could observe. Drop the session.
      this.fail('handshake on an established tunnel');
      return;
    }
    // The phone may arrive before `peer-online` does; treat its handshake as the
    // trigger.
    if (this.handshake === undefined) this.beginSeal();
    const handshake = this.handshake;
    if (handshake === undefined) return;

    const message = raw as { eph?: unknown; sig?: unknown } | null;
    if (typeof message !== 'object' || message === null || typeof message.eph !== 'string') {
      this.fail('malformed peer handshake');
      return;
    }

    // Round one: the peer's ephemeral arrived unsigned. Now that we know it, we can
    // sign our own transcript and answer.
    if (!this.handshakeSigned) {
      this.handshakeSigned = true;
      const sig = signHandshake(handshake, message.eph, this.options.ownStaticPrivateKey);
      this.sendControl({
        v: 1,
        type: 'relay/handshake',
        hs: { v: 1, eph: handshake.message.eph, sig },
      });
    }

    // Round two: a signed message completes the handshake. An unsigned one was just
    // the peer's ephemeral and needs no further action.
    if (typeof message.sig !== 'string' || message.sig.length === 0) return;

    const completed = completeHandshake(handshake, { v: 1, eph: message.eph, sig: message.sig });
    if (!completed.ok) {
      // This is the branch that catches a hostile or misrouting relay: without the
      // phone's Ed25519 private key it cannot produce a valid transcript signature.
      this.fail(`seal handshake failed: ${completed.reason}`);
      return;
    }
    this.channel = completed.channel;
    this.handshake = undefined;
    this.setState('tunneled');
    this.log('sealed tunnel established');
  }

  // ── tunnel layer ──────────────────────────────────────────────────────────

  private async onSealedRecord(record: unknown): Promise<void> {
    const channel = this.channel;
    if (channel === undefined) {
      // Data before the handshake completed. Not an error worth dropping the
      // connection for — a phone may have sent early — but it cannot be read.
      this.noteError('sealed record before tunnel was established');
      return;
    }
    const opened = channel.openJson(record);
    if (!opened.ok) {
      // `replay` and `auth-failed` both mean the relay path is not behaving. There is
      // no safe way to continue on a channel whose integrity is in question.
      this.fail(`sealed record rejected: ${opened.reason}`);
      return;
    }

    const parsed = parseTunnelClientMessage(opened.value);
    if (!parsed.ok) {
      this.sendTunnel({ v: 1, type: 'tunnel/error', message: parsed.reason });
      return;
    }
    this.framesIn += 1;
    const message = parsed.message;

    switch (message.type) {
      case 'tunnel/ping':
        this.sendTunnel({ v: 1, type: 'tunnel/pong', at: message.at });
        return;
      case 'tunnel/unsubscribe':
        this.closeStream('unsubscribed');
        return;
      case 'tunnel/subscribe':
        await this.handleSubscribe(message.id, message.token, message.after ?? 0);
        return;
      case 'tunnel/request':
        await this.handleRequest(message.id, message.method, message.path, message.token, message.body);
        return;
    }
  }

  private async handleRequest(
    id: string,
    method: 'GET' | 'POST',
    path: string,
    token: string | undefined,
    body: unknown,
  ): Promise<void> {
    // The token rides inside the sealed tunnel. The relay never sees it, and the
    // local backend turns it into the normal Authorization header for /m1.
    const response = await this.options.backend.request({ method, path, ...(token === undefined ? {} : { token }), ...(body === undefined ? {} : { body }) });
    this.sendTunnel({ v: 1, type: 'tunnel/response', id, status: response.status, body: response.body });
  }

  private async handleSubscribe(id: string, token: string, after: number): Promise<void> {
    // One subscription per tunnel. A resubscribe is a reconnecting phone, and the
    // old stream's frames would only confuse it.
    this.closeStream('resubscribed');

    const opened = await this.options.backend.openStream({
      token,
      after,
      sinks: {
        onMessage: (value) => {
          // The first message is `/m1/stream`'s hello, which carries the rotated
          // token. It is forwarded as-is: it is already inside the sealed channel,
          // and re-shaping it would mean two places that know the frame format.
          this.sendTunnel({ v: 1, type: 'tunnel/event', envelope: value });
        },
        onClose: (reason) => {
          this.stream = undefined;
          this.sendTunnel({ v: 1, type: 'tunnel/unsubscribed', reason });
        },
      },
    });

    if (!opened.ok) {
      this.sendTunnel({ v: 1, type: 'tunnel/subscribe-failed', id, status: opened.status, reason: opened.reason });
      return;
    }
    this.stream = opened.stream;
    this.sendTunnel({ v: 1, type: 'tunnel/subscribed', id, hello: null });
  }

  private closeStream(reason: string): void {
    const stream = this.stream;
    if (stream === undefined) return;
    this.stream = undefined;
    void reason;
    stream.close();
  }

  private sendTunnel(message: TunnelServerMessage): void {
    const channel = this.channel;
    if (channel === undefined) return;
    let plaintext: Buffer;
    try {
      plaintext = Buffer.from(JSON.stringify(message), 'utf8');
    } catch {
      // A non-serializable body from the bridge would otherwise take the tunnel
      // down; answer with something the phone can act on instead.
      this.sendTunnel({ v: 1, type: 'tunnel/error', message: 'bridge produced an unserializable response' });
      return;
    }
    if (plaintext.byteLength > TUNNEL_MAX_MESSAGE_BYTES) {
      this.sendTunnel({ v: 1, type: 'tunnel/error', message: 'response exceeds tunnel message limit' });
      return;
    }
    try {
      this.sendControl({ v: 1, type: 'relay/data', record: channel.seal(plaintext) });
      this.framesOut += 1;
    } catch (error) {
      this.fail(`seal failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private log(line: string): void {
    if (this.options.verbose === true) console.error(`[relay-connector] ${line}`);
  }
}

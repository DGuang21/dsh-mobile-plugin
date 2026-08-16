/**
 * Mode B transport: an `M1Transport` over a sealed tunnel through an untrusted relay.
 *
 * Composes the two halves that already exist — `RelayClient` (one socket, one
 * sealed channel) and `TunnelClient` (request/response and events inside it) — and
 * presents them as the same `request()`/`subscribe()` pair Mode A offers.
 *
 * Scope, deliberately narrow: **one sealed session, no retry.** When the session
 * dies this transport is finished and reports why. Reconnect policy, backoff and
 * state transitions belong to the core, which is the only place that knows whether
 * a drop should become `reconnecting`, `relay-unavailable` or a terminal state. A
 * transport that reconnected itself would be a second, competing policy.
 *
 * The security-relevant translation happens in `classify()`: a handshake failure
 * caused by an unverifiable signature becomes `pin-mismatch`, which the core treats
 * as terminal. That is intentionally strict. A hostile relay can provoke it, so it
 * can be used to push a user into re-pairing — but the alternative, retrying past a
 * signature that did not verify against the pinned key, is exactly the behaviour a
 * man in the middle needs. Denial of service is the safe failure here.
 */

import {
  RelayClient,
  type RelayCloseReason,
  type WebSocketFactory,
  normalizeRelayErrorCode,
} from './relay';
import type { SealedChannel } from './seal';
import { TunnelClient, TunnelError } from './tunnel';
import {
  type M1Transport,
  type StreamHandlers,
  type StreamSubscription,
  TransportError,
  type TransportLostHandler,
  type TransportResponse,
} from './transport';

export interface RelayTransportOptions {
  relayUrl: string;
  /** Our durable device routing id. */
  routingId: string;
  /** The bridge's durable routing id, from the sealed claim response. */
  bridgeRoutingId: string;
  /** base64url raw Ed25519 static key of the bridge, pinned at pairing time. */
  bridgeStaticPublicKey: string;
  identity: { publicKey: string; privateKey: Uint8Array };
  createSocket: WebSocketFactory;
  /** The session died with nothing in flight. */
  onLost: TransportLostHandler;
  onDiagnostic?: (level: 'info' | 'warn' | 'error', message: string) => void;
  /** How long `start()` waits for the sealed handshake. */
  handshakeTimeoutMs?: number;
  requestTimeoutMs?: number;
}

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 15_000;

export class RelayTransport implements M1Transport {
  readonly mode = 'relay' as const;
  private readonly options: RelayTransportOptions;
  private readonly relay: RelayClient;
  private readonly tunnel: TunnelClient;
  private startPromise: Promise<void> | undefined;
  private settleStart: { resolve: () => void; reject: (error: TransportError) => void } | undefined;
  private handshakeTimer: ReturnType<typeof setTimeout> | undefined;
  private sealed = false;
  private closed = false;
  /** The failure that ended the session, so late callers get the real reason. */
  private lostTo: TransportError | undefined;
  private subscriptionHandlers: StreamHandlers | undefined;

  constructor(options: RelayTransportOptions) {
    this.options = options;
    this.relay = new RelayClient({
      relayUrl: options.relayUrl,
      routingId: options.routingId,
      peerRoutingId: options.bridgeRoutingId,
      bridgeStaticPublicKey: options.bridgeStaticPublicKey,
      identity: options.identity,
      createSocket: options.createSocket,
      onChannel: (channel) => this.onChannel(channel),
      onRecord: (value) => this.tunnel.handle(value),
      onClosed: (reason) => this.onRelayClosed(reason),
      ...(options.onDiagnostic === undefined ? {} : { onDiagnostic: options.onDiagnostic }),
    });
    this.tunnel = new TunnelClient({
      transport: {
        send: (value) => this.relay.send(value),
        isSealed: () => this.relay.isSealed(),
      },
      ...(options.requestTimeoutMs === undefined ? {} : { requestTimeoutMs: options.requestTimeoutMs }),
      ...(options.onDiagnostic === undefined ? {} : { onDiagnostic: options.onDiagnostic }),
    });
  }

  /** Open the socket, register, and run the handshake. Resolves once sealed. */
  start(): Promise<void> {
    if (this.startPromise !== undefined) return this.startPromise;
    if (this.closed) return Promise.reject(this.lostTo ?? new TransportError('offline', 'transport is closed'));

    this.startPromise = new Promise<void>((resolve, reject) => {
      this.settleStart = { resolve, reject };
      this.handshakeTimer = setTimeout(() => {
        // No seal in time. Failing here rather than waiting forever is what lets
        // the core count an attempt and back off.
        this.fail(new TransportError('timeout', 'sealed handshake did not complete in time'));
      }, this.options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS);
      this.relay.connect();
    });
    return this.startPromise;
  }

  async request(input: {
    method: 'GET' | 'POST';
    path: string;
    token?: string;
    body?: unknown;
  }): Promise<TransportResponse> {
    if (this.closed) throw this.lostTo ?? new TransportError('offline', 'tunnel is closed');
    if (!this.sealed) throw new TransportError('offline', 'sealed tunnel is not established');
    try {
      return await this.tunnel.request(input);
    } catch (error) {
      throw toTransportError(error);
    }
  }

  subscribe(input: { token: string; after: number; handlers: StreamHandlers }): StreamSubscription {
    if (this.closed || !this.sealed) {
      input.handlers.onClosed('sealed tunnel is not established');
      return { stop: () => undefined };
    }

    this.subscriptionHandlers = input.handlers;
    let stopped = false;
    const finish = (reason: string, status?: number): void => {
      if (stopped) return;
      stopped = true;
      if (this.subscriptionHandlers === input.handlers) this.subscriptionHandlers = undefined;
      input.handlers.onClosed(reason, status);
    };

    const accepted = this.tunnel.subscribe({
      token: input.token,
      after: input.after,
      handlers: {
        onHello: (hello) => input.handlers.onHello(hello),
        onEnvelope: (envelope) => input.handlers.onEnvelope(envelope),
        onUnsubscribed: (reason) => finish(reason),
        // The status is the one an `/m1/stream` upgrade would have used, so a 401
        // here means the same thing it means in Mode A: the token is done.
        onSubscribeFailed: (status, reason) => finish(reason, status),
      },
    });
    if (!accepted) {
      finish('could not send the subscribe over the tunnel');
      return { stop: () => undefined };
    }

    return {
      stop: () => {
        if (stopped) return;
        stopped = true;
        if (this.subscriptionHandlers === input.handlers) this.subscriptionHandlers = undefined;
        if (!this.closed) this.tunnel.unsubscribe();
      },
    };
  }

  /** Control-layer keepalive. The relay drops idle sockets; the radio sleeps. */
  ping(): void {
    if (this.closed) return;
    if (this.sealed) this.tunnel.ping();
    else this.relay.ping();
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.clearHandshakeTimer();
    this.sealed = false;
    // Order matters: settle pending requests first, so their rejections carry
    // "closed" rather than racing the relay's own close callback.
    this.tunnel.close('tunnel closed locally');
    this.relay.close('closed locally');
    this.settleStart?.reject(new TransportError('offline', 'transport closed before the handshake completed'));
    this.settleStart = undefined;
  }

  isSealed(): boolean {
    return this.sealed && !this.closed;
  }

  private onChannel(_channel: SealedChannel): void {
    this.clearHandshakeTimer();
    this.sealed = true;
    this.settleStart?.resolve();
    this.settleStart = undefined;
  }

  /**
   * The relay session ended.
   *
   * One rule: whoever is waiting hears about it. If `start()` is outstanding it
   * rejects; otherwise `onLost` fires. Never both, and never neither — a silent
   * drop is how a UI ends up showing `ready` over a dead tunnel.
   */
  private onRelayClosed(reason: RelayCloseReason): void {
    if (reason.kind === 'local' && this.closed) return;
    this.fail(classify(reason));
  }

  private fail(error: TransportError): void {
    if (this.closed) return;
    this.closed = true;
    this.lostTo = error;
    this.clearHandshakeTimer();
    this.sealed = false;

    this.tunnel.close(error.message);
    this.relay.close(error.message);

    const settle = this.settleStart;
    this.settleStart = undefined;
    if (settle !== undefined) {
      // `start()` is the caller's error channel here; reporting through `onLost`
      // as well would make the core count one failure twice.
      settle.reject(error);
      return;
    }
    this.options.onLost(error);
  }

  private clearHandshakeTimer(): void {
    if (this.handshakeTimer === undefined) return;
    clearTimeout(this.handshakeTimer);
    this.handshakeTimer = undefined;
  }
}

/**
 * Map a relay close reason onto the transport taxonomy.
 *
 * The only subtle case is `handshake`. `bad-signature` and `bad-static-key` mean
 * the peer could not prove ownership of the pinned key, which is a pin mismatch and
 * must be terminal. The rest (`bad-version`, `bad-ephemeral`,
 * `key-agreement-failed`, `handshake-consumed`, and any malformed-frame text) are
 * protocol faults that a fresh session can legitimately retry — a relay corrupting
 * frames is annoying, not proof of an impostor.
 */
export function classify(reason: RelayCloseReason): TransportError {
  switch (reason.kind) {
    case 'transport':
      return new TransportError('offline', reason.message);
    case 'relay-error':
      return new TransportError(
        'transport',
        `relay error: ${reason.code}${reason.message.length > 0 ? ` (${reason.message})` : ''}`,
        { relayCode: normalizeRelayErrorCode(reason.code) },
      );
    case 'handshake':
      return reason.reason === 'bad-signature' || reason.reason === 'bad-static-key'
        ? new TransportError('pin-mismatch', `sealed handshake rejected: ${reason.reason}`, {
            pinDetail: 'bridge-static-key',
          })
        : new TransportError('transport', `sealed handshake failed: ${reason.reason}`);
    case 'seal':
      // A record that would not open. Fail closed, and do not call it a pin
      // mismatch: the keys agreed once, so this is tampering or misrouting after
      // the fact, and a fresh handshake is the right response.
      return new TransportError('transport', `sealed tunnel fault: ${reason.reason}`);
    case 'local':
      return new TransportError('offline', reason.message);
  }
}

function toTransportError(error: unknown): TransportError {
  if (error instanceof TransportError) return error;
  if (error instanceof TunnelError) {
    switch (error.failure.kind) {
      case 'offline':
        return new TransportError('offline', error.failure.message);
      case 'timeout':
        return new TransportError('timeout', error.failure.message);
      case 'tunnel-error':
        return new TransportError('transport', error.failure.message);
    }
  }
  return new TransportError('transport', error instanceof Error ? error.message : String(error));
}

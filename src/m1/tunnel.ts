/**
 * [OUR DESIGN] Phone-side sealed tunnel client.
 *
 * Speaks the wire format in `bridge/src/relay/tunnel.ts` over whatever transport
 * a {@link TunnelTransport} provides — in practice a {@link RelayClient}'s sealed
 * channel. Its whole job is to make Mode B look like Mode A to the layer above:
 * `request()` returns a status and a body, exactly like `fetch` against `/m1`.
 *
 * That symmetry is the point. The bridge replays a tunnel request against its own
 * `/m1` router, so pairing, tokens, policy, rate limits and audit all apply
 * unchanged, and there is no second, weaker way in. The phone side mirrors it so
 * there is likewise no second client-side authorization path.
 *
 * Two properties worth stating because they are easy to get wrong:
 *
 *   - **Every pending request is settled exactly once.** A tunnel that drops
 *     rejects everything outstanding rather than leaving promises hanging, so a UI
 *     never shows a spinner that outlives its connection.
 *   - **`tunnel/subscribed` carries `hello: null`.** The real `/m1/stream` hello
 *     arrives as the FIRST `tunnel/event`, so the subscription is not "ready" until
 *     that envelope shows up. Treating the acknowledgement as the hello would drop
 *     the rotated token.
 */

import type { M1StreamEnvelope, M1StreamHello } from './types';

export const TUNNEL_MAX_MESSAGE_BYTES = 1024 * 1024;

/** How long a tunnel request waits before giving up. */
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/** What the tunnel needs from the layer below: sealed send, and a liveness check. */
export interface TunnelTransport {
  send(value: unknown): boolean;
  isSealed(): boolean;
}

/** A tunnel response, shaped like the HTTP one it stands in for. */
export interface TunnelResponse {
  status: number;
  body: unknown;
}

export type TunnelFailure =
  /** The tunnel is not up, or dropped before the response arrived. */
  | { kind: 'offline'; message: string }
  /** No response within the timeout. */
  | { kind: 'timeout'; message: string }
  /** The bridge reported a tunnel-level fault, distinct from an `/m1` error body. */
  | { kind: 'tunnel-error'; message: string };

export class TunnelError extends Error {
  readonly failure: TunnelFailure;

  constructor(failure: TunnelFailure) {
    super(failure.message);
    this.name = 'TunnelError';
    this.failure = failure;
  }
}

export interface SubscriptionHandlers {
  /** The `/m1/stream` hello, extracted from the first event. */
  onHello: (hello: M1StreamHello) => void;
  onEnvelope: (envelope: M1StreamEnvelope) => void;
  /** The bridge ended the subscription: revocation, dsh restart, shutdown. */
  onUnsubscribed: (reason: string) => void;
  /** The subscribe was refused, with the status an `/m1/stream` upgrade would use. */
  onSubscribeFailed: (status: number, reason: string) => void;
}

export interface TunnelClientOptions {
  transport: TunnelTransport;
  requestTimeoutMs?: number;
  onDiagnostic?: (level: 'info' | 'warn' | 'error', message: string) => void;
  /** Injectable for tests; defaults to the real timer. */
  setTimer?: (handler: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

interface Pending {
  resolve: (response: TunnelResponse) => void;
  reject: (error: TunnelError) => void;
  timer: unknown;
}

export class TunnelClient {
  private readonly options: TunnelClientOptions;
  private readonly pending = new Map<string, Pending>();
  private nextId = 1;
  private subscription: { id: string; handlers: SubscriptionHandlers; helloSeen: boolean } | undefined;
  private closed = false;

  constructor(options: TunnelClientOptions) {
    this.options = options;
  }

  /**
   * Send one `/m1` request and wait for its response.
   *
   * Rejects with a {@link TunnelError} rather than resolving to a failure, because
   * a transport fault is categorically different from an `/m1` error body: the
   * former means we do not know what happened, the latter is the bridge answering.
   */
  request(input: { method: 'GET' | 'POST'; path: string; token?: string; body?: unknown }): Promise<TunnelResponse> {
    if (this.closed) {
      return Promise.reject(new TunnelError({ kind: 'offline', message: 'tunnel is closed' }));
    }
    const id = `r${this.nextId}`;
    this.nextId += 1;

    return new Promise<TunnelResponse>((resolve, reject) => {
      const sent = this.options.transport.send({
        v: 1,
        type: 'tunnel/request',
        id,
        method: input.method,
        path: input.path,
        ...(input.token === undefined ? {} : { token: input.token }),
        ...(input.body === undefined ? {} : { body: input.body }),
      });
      if (!sent) {
        reject(new TunnelError({ kind: 'offline', message: 'tunnel is not established' }));
        return;
      }

      const timer = this.setTimer(() => {
        this.pending.delete(id);
        reject(new TunnelError({ kind: 'timeout', message: `tunnel request ${input.path} timed out` }));
      }, this.options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);

      this.pending.set(id, { resolve, reject, timer });
    });
  }

  /**
   * Open the event subscription.
   *
   * At most one per tunnel; a second subscribe replaces the first, which is what a
   * reconnecting phone wants. Returns immediately — readiness is signalled by
   * `handlers.onHello`, which fires when the first envelope arrives.
   */
  subscribe(input: { token: string; after?: number; handlers: SubscriptionHandlers }): boolean {
    if (this.closed) return false;
    const id = `s${this.nextId}`;
    this.nextId += 1;
    this.subscription = { id, handlers: input.handlers, helloSeen: false };
    return this.options.transport.send({
      v: 1,
      type: 'tunnel/subscribe',
      id,
      token: input.token,
      ...(input.after === undefined ? {} : { after: input.after }),
    });
  }

  /** Drop the subscription, keep the tunnel. */
  unsubscribe(): void {
    if (this.subscription === undefined) return;
    this.subscription = undefined;
    this.options.transport.send({ v: 1, type: 'tunnel/unsubscribe' });
  }

  ping(): void {
    this.options.transport.send({ v: 1, type: 'tunnel/ping', at: Date.now() });
  }

  /**
   * Handle one decrypted tunnel message.
   *
   * The caller has already authenticated it — it survived AES-GCM — but a paired
   * bridge could still send something malformed, so every field is checked before
   * use and an unknown message is noted rather than trusted.
   */
  handle(message: unknown): void {
    if (this.closed) return;
    const record = message as Record<string, unknown> | null;
    if (typeof record !== 'object' || record === null || record.v !== 1) {
      this.note('warn', 'tunnel message with an unsupported version');
      return;
    }

    switch (record.type) {
      case 'tunnel/response':
        this.onResponse(record);
        return;
      case 'tunnel/subscribed':
        this.onSubscribed(record);
        return;
      case 'tunnel/subscribe-failed':
        this.onSubscribeFailed(record);
        return;
      case 'tunnel/event':
        this.onEvent(record);
        return;
      case 'tunnel/unsubscribed':
        this.onUnsubscribed(record);
        return;
      case 'tunnel/pong':
        return;
      case 'tunnel/error':
        // A tunnel-level fault. It has no request id, so it cannot be attributed
        // to one caller; fail everything outstanding rather than let requests
        // hang on a tunnel the bridge has declared broken.
        this.failAll({
          kind: 'tunnel-error',
          message: typeof record.message === 'string' ? record.message : 'tunnel error',
        });
        return;
      default:
        this.note('warn', 'unknown tunnel message type');
    }
  }

  private onResponse(record: Record<string, unknown>): void {
    if (typeof record.id !== 'string') return;
    const pending = this.pending.get(record.id);
    // An id we never sent, or already settled. Dropping it is right: resolving a
    // stale correlation id would attribute a body to the wrong request.
    if (pending === undefined) return;
    this.pending.delete(record.id);
    this.clearTimer(pending.timer);

    const status = typeof record.status === 'number' && Number.isFinite(record.status) ? record.status : 0;
    if (status === 0) {
      pending.reject(new TunnelError({ kind: 'tunnel-error', message: 'tunnel response had no status' }));
      return;
    }
    pending.resolve({ status, body: record.body });
  }

  /**
   * The subscribe was accepted.
   *
   * `hello` on this frame is null by design — the bridge has only queued the
   * upgrade at this point. The real hello is the first `tunnel/event`.
   */
  private onSubscribed(record: Record<string, unknown>): void {
    if (typeof record.id !== 'string' || this.subscription?.id !== record.id) return;
    this.note('info', 'tunnel subscription accepted');
  }

  private onSubscribeFailed(record: Record<string, unknown>): void {
    if (typeof record.id !== 'string' || this.subscription?.id !== record.id) return;
    const subscription = this.subscription;
    this.subscription = undefined;
    const status = typeof record.status === 'number' ? record.status : 0;
    const reason = typeof record.reason === 'string' ? record.reason : 'subscribe failed';
    subscription.handlers.onSubscribeFailed(status, reason);
  }

  /**
   * One stream envelope, byte-identical to what `/m1/stream` would have sent.
   *
   * The first one is the hello, which carries the rotated token and the resume
   * cursor. It is recognized structurally rather than positionally so a reordered
   * or duplicated frame cannot make us miss it.
   */
  private onEvent(record: Record<string, unknown>): void {
    const subscription = this.subscription;
    if (subscription === undefined) {
      // Events after an unsubscribe, or from a replaced subscription. Not an
      // error; just nothing to do with them.
      return;
    }
    const envelope = record.envelope;
    if (typeof envelope !== 'object' || envelope === null) {
      this.note('warn', 'tunnel event without an envelope');
      return;
    }

    if (!subscription.helloSeen) {
      const hello = asStreamHello(envelope);
      if (hello !== undefined) {
        subscription.helloSeen = true;
        subscription.handlers.onHello(hello);
        return;
      }
      // A frame before the hello should not happen. Passing it through anyway
      // would mean rendering deltas against a baseline we never established.
      this.note('warn', 'tunnel event arrived before the stream hello');
      return;
    }

    const parsed = asStreamEnvelope(envelope);
    if (parsed === undefined) {
      this.note('warn', 'tunnel event with a malformed envelope');
      return;
    }
    subscription.handlers.onEnvelope(parsed);
  }

  private onUnsubscribed(record: Record<string, unknown>): void {
    const subscription = this.subscription;
    if (subscription === undefined) return;
    this.subscription = undefined;
    subscription.handlers.onUnsubscribed(typeof record.reason === 'string' ? record.reason : 'unsubscribed');
  }

  /**
   * Settle everything outstanding and stop accepting work.
   *
   * Called when the transport drops. Idempotent, and deliberately not recoverable:
   * a new tunnel gets a new client, so no counter or correlation id is ever reused
   * across sealed sessions.
   */
  close(message = 'tunnel closed'): void {
    if (this.closed) return;
    this.closed = true;
    this.failAll({ kind: 'offline', message });
    const subscription = this.subscription;
    this.subscription = undefined;
    subscription?.handlers.onUnsubscribed(message);
  }

  isClosed(): boolean {
    return this.closed;
  }

  /** Outstanding request count, for tests and diagnostics. */
  pendingCount(): number {
    return this.pending.size;
  }

  private failAll(failure: TunnelFailure): void {
    const entries = [...this.pending.values()];
    this.pending.clear();
    for (const entry of entries) {
      this.clearTimer(entry.timer);
      entry.reject(new TunnelError(failure));
    }
  }

  private setTimer(handler: () => void, ms: number): unknown {
    const set = this.options.setTimer ?? ((callback: () => void, delay: number) => setTimeout(callback, delay));
    return set(handler, ms);
  }

  private clearTimer(handle: unknown): void {
    const clear = this.options.clearTimer ?? ((value: unknown) => clearTimeout(value as ReturnType<typeof setTimeout>));
    clear(handle);
  }

  private note(level: 'info' | 'warn' | 'error', message: string): void {
    this.options.onDiagnostic?.(level, message);
  }
}

/**
 * Recognize the stream hello.
 *
 * Structural rather than positional: `kind: 'hello'` plus the fields we actually
 * depend on. A frame missing `token` or `lastBseq` is not usable as a baseline even
 * if it calls itself a hello.
 */
export function asStreamHello(value: unknown): M1StreamHello | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (record.kind !== 'hello' || record.v !== 1) return undefined;
  if (typeof record.bridgeId !== 'string') return undefined;
  if (typeof record.token !== 'string' || record.token.length === 0) return undefined;
  if (typeof record.tokenExpiresAt !== 'number') return undefined;
  if (typeof record.lastBseq !== 'number' || !Number.isFinite(record.lastBseq)) return undefined;
  return {
    v: 1,
    kind: 'hello',
    bridgeId: record.bridgeId,
    token: record.token,
    tokenExpiresAt: record.tokenExpiresAt,
    lastBseq: record.lastBseq,
    resync: record.resync === true,
    pendingCount: typeof record.pendingCount === 'number' ? record.pendingCount : 0,
  };
}

/**
 * Validate a stream envelope.
 *
 * `frame` stays `unknown` on purpose: the mux/host frame vocabulary is upstream's
 * and will grow, so an unknown `frame.type` must fold to a generic card rather
 * than be rejected here.
 */
export function asStreamEnvelope(value: unknown): M1StreamEnvelope | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (record.v !== 1) return undefined;
  if (typeof record.bseq !== 'number' || !Number.isFinite(record.bseq)) return undefined;
  if (record.kind !== 'mux' && record.kind !== 'host' && record.kind !== 'bridge') return undefined;
  return {
    v: 1,
    bseq: record.bseq,
    kind: record.kind,
    ...(typeof record.rpcId === 'string' ? { rpcId: record.rpcId } : {}),
    frame: record.frame,
  };
}

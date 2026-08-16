/**
 * `TunnelClient` tests: sealed request/response and stream subscription over Mode B.
 *
 * Requirement (4). The properties being pinned down:
 *
 *   - Every pending request settles exactly once, including when the tunnel drops.
 *     A promise left hanging is a spinner that outlives its connection.
 *   - **`tunnel/subscribed` is not the hello.** It carries `hello: null` by design;
 *     the real `/m1/stream` hello is the first `tunnel/event`. Treating the
 *     acknowledgement as the hello would drop the rotated token, which is the whole
 *     mechanism keeping the access token short-lived.
 *   - A stale or unknown correlation id is dropped, never resolved against the wrong
 *     caller.
 */

import { describe, expect, it, vi } from 'vitest';
import { TunnelClient, TunnelError, asStreamEnvelope, asStreamHello } from '../src/m1/tunnel';
import type { M1StreamEnvelope, M1StreamHello } from '../src/m1/types';

/** A transport that records what was sent and can be taken offline. */
function fakeTransport() {
  const sent: Record<string, unknown>[] = [];
  let sealed = true;
  return {
    sent,
    setSealed: (value: boolean) => { sealed = value; },
    transport: {
      send: (value: unknown) => {
        if (!sealed) return false;
        sent.push(value as Record<string, unknown>);
        return true;
      },
      isSealed: () => sealed,
    },
    last: () => sent[sent.length - 1],
    ofType: (type: string) => sent.filter((frame) => frame.type === type),
  };
}

function harness(options: { requestTimeoutMs?: number } = {}) {
  const wire = fakeTransport();
  const diagnostics: { level: string; message: string }[] = [];
  const timers: { handler: () => void; ms: number; cancelled: boolean }[] = [];
  const client = new TunnelClient({
    transport: wire.transport,
    ...(options.requestTimeoutMs === undefined ? {} : { requestTimeoutMs: options.requestTimeoutMs }),
    onDiagnostic: (level, message) => diagnostics.push({ level, message }),
    setTimer: (handler, ms) => {
      const entry = { handler, ms, cancelled: false };
      timers.push(entry);
      return entry;
    },
    clearTimer: (handle) => { (handle as { cancelled: boolean }).cancelled = true; },
  });
  return { client, wire, diagnostics, timers };
}

/** A minimal valid hello. */
/**
 * A valid hello, with an escape hatch for invalid ones.
 *
 * `Record<string, unknown>` rather than `Partial<M1StreamHello>`: half these tests
 * exist to prove the validator rejects a wrong `kind` or `v`, which the narrower type
 * would forbid them from expressing.
 */
function hello(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    kind: 'hello',
    bridgeId: 'bridge-1',
    token: 'rotated-token',
    tokenExpiresAt: 1_700_000_000_000,
    lastBseq: 12,
    resync: false,
    pendingCount: 0,
    ...overrides,
  };
}

/** As `hello`, and loosely typed for the same reason. */
function envelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, bseq: 13, kind: 'mux', frame: { type: 'session/event' }, ...overrides };
}

/** Collect subscription callbacks. */
function handlers() {
  const helloes: M1StreamHello[] = [];
  const envelopes: M1StreamEnvelope[] = [];
  const unsubscribed: string[] = [];
  const failed: { status: number; reason: string }[] = [];
  return {
    helloes,
    envelopes,
    unsubscribed,
    failed,
    handlers: {
      onHello: (value: M1StreamHello) => helloes.push(value),
      onEnvelope: (value: M1StreamEnvelope) => envelopes.push(value),
      onUnsubscribed: (reason: string) => unsubscribed.push(reason),
      onSubscribeFailed: (status: number, reason: string) => failed.push({ status, reason }),
    },
  };
}

describe('tunnel requests', () => {
  it('sends a request and resolves its response', async () => {
    const h = harness();
    const pending = h.client.request({ method: 'POST', path: '/m1/rpc', token: 'tok', body: { a: 1 } });
    const frame = h.wire.last();
    expect(frame).toMatchObject({ v: 1, type: 'tunnel/request', method: 'POST', path: '/m1/rpc', token: 'tok', body: { a: 1 } });
    h.client.handle({ v: 1, type: 'tunnel/response', id: frame?.id, status: 200, body: { ok: true } });
    await expect(pending).resolves.toEqual({ status: 200, body: { ok: true } });
  });

  it('omits token and body when absent rather than sending nulls', async () => {
    const h = harness();
    const pending = h.client.request({ method: 'GET', path: '/m1/health' });
    const frame = h.wire.last();
    expect(Object.keys(frame ?? {})).not.toContain('token');
    expect(Object.keys(frame ?? {})).not.toContain('body');
    h.client.handle({ v: 1, type: 'tunnel/response', id: frame?.id, status: 200, body: {} });
    await pending;
  });

  it('correlates concurrent requests independently', async () => {
    const h = harness();
    const first = h.client.request({ method: 'GET', path: '/a' });
    const second = h.client.request({ method: 'GET', path: '/b' });
    const [frameA, frameB] = h.wire.ofType('tunnel/request');
    // Answer out of order: correlation must be by id, not arrival order.
    h.client.handle({ v: 1, type: 'tunnel/response', id: frameB?.id, status: 201, body: 'b' });
    h.client.handle({ v: 1, type: 'tunnel/response', id: frameA?.id, status: 200, body: 'a' });
    await expect(first).resolves.toEqual({ status: 200, body: 'a' });
    await expect(second).resolves.toEqual({ status: 201, body: 'b' });
  });

  it('rejects when the tunnel is not established', async () => {
    const h = harness();
    h.wire.setSealed(false);
    await expect(h.client.request({ method: 'GET', path: '/a' })).rejects.toThrow(TunnelError);
    await expect(h.client.request({ method: 'GET', path: '/a' })).rejects.toMatchObject({ failure: { kind: 'offline' } });
  });

  it('rejects on timeout with the path named', async () => {
    const h = harness({ requestTimeoutMs: 5_000 });
    const pending = h.client.request({ method: 'GET', path: '/m1/slow' });
    expect(h.timers[0]?.ms).toBe(5_000);
    h.timers[0]?.handler();
    await expect(pending).rejects.toMatchObject({ failure: { kind: 'timeout' } });
    await expect(pending).rejects.toThrow(/\/m1\/slow/);
  });

  it('clears the timeout once a response arrives', async () => {
    const h = harness();
    const pending = h.client.request({ method: 'GET', path: '/a' });
    h.client.handle({ v: 1, type: 'tunnel/response', id: h.wire.last()?.id, status: 200, body: 1 });
    await pending;
    expect(h.timers[0]?.cancelled).toBe(true);
    expect(h.client.pendingCount()).toBe(0);
  });

  it('drops a response for an id it never sent', async () => {
    const h = harness();
    const pending = h.client.request({ method: 'GET', path: '/a' });
    h.client.handle({ v: 1, type: 'tunnel/response', id: 'r999', status: 500, body: 'wrong' });
    expect(h.client.pendingCount()).toBe(1);
    h.client.handle({ v: 1, type: 'tunnel/response', id: h.wire.last()?.id, status: 200, body: 'right' });
    await expect(pending).resolves.toMatchObject({ body: 'right' });
  });

  it('drops a duplicate response instead of settling twice', async () => {
    const h = harness();
    const pending = h.client.request({ method: 'GET', path: '/a' });
    const id = h.wire.last()?.id;
    h.client.handle({ v: 1, type: 'tunnel/response', id, status: 200, body: 'first' });
    h.client.handle({ v: 1, type: 'tunnel/response', id, status: 500, body: 'second' });
    await expect(pending).resolves.toMatchObject({ status: 200, body: 'first' });
  });

  it('rejects a response with no usable status', async () => {
    const h = harness();
    const pending = h.client.request({ method: 'GET', path: '/a' });
    h.client.handle({ v: 1, type: 'tunnel/response', id: h.wire.last()?.id, body: 'no status' });
    await expect(pending).rejects.toMatchObject({ failure: { kind: 'tunnel-error' } });
  });

  it('preserves an /m1 error body rather than turning it into a failure', async () => {
    // A 403 from `/m1` is the bridge answering. It must reach the caller as a
    // response, so the core can tell "revoked" from "the network is down".
    const h = harness();
    const pending = h.client.request({ method: 'POST', path: '/m1/rpc' });
    h.client.handle({
      v: 1,
      type: 'tunnel/response',
      id: h.wire.last()?.id,
      status: 403,
      body: { ok: false, error: { code: 'device-revoked', message: 'revoked' } },
    });
    await expect(pending).resolves.toMatchObject({ status: 403, body: { error: { code: 'device-revoked' } } });
  });

  it('fails everything outstanding on a tunnel error', async () => {
    const h = harness();
    const first = h.client.request({ method: 'GET', path: '/a' });
    const second = h.client.request({ method: 'GET', path: '/b' });
    h.client.handle({ v: 1, type: 'tunnel/error', message: 'carrier fault' });
    await expect(first).rejects.toMatchObject({ failure: { kind: 'tunnel-error', message: 'carrier fault' } });
    await expect(second).rejects.toMatchObject({ failure: { kind: 'tunnel-error' } });
    expect(h.client.pendingCount()).toBe(0);
  });

  it('fails everything outstanding on close, exactly once', async () => {
    const h = harness();
    const pending = h.client.request({ method: 'GET', path: '/a' });
    h.client.close('relay dropped');
    await expect(pending).rejects.toMatchObject({ failure: { kind: 'offline', message: 'relay dropped' } });
    expect(h.client.isClosed()).toBe(true);
    expect(h.timers[0]?.cancelled).toBe(true);
  });

  it('rejects new requests after close', async () => {
    const h = harness();
    h.client.close();
    await expect(h.client.request({ method: 'GET', path: '/a' })).rejects.toMatchObject({ failure: { kind: 'offline' } });
  });

  it('ignores messages after close', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.close();
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello() });
    expect(collected.helloes).toHaveLength(0);
  });
});

describe('tunnel subscription', () => {
  it('sends a subscribe with the token and cursor', () => {
    const h = harness();
    const collected = handlers();
    expect(h.client.subscribe({ token: 'tok', after: 40, handlers: collected.handlers })).toBe(true);
    expect(h.wire.last()).toMatchObject({ v: 1, type: 'tunnel/subscribe', token: 'tok', after: 40 });
  });

  it('omits the cursor on a first subscribe', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    expect(Object.keys(h.wire.last() ?? {})).not.toContain('after');
  });

  it('does not treat tunnel/subscribed as the hello', () => {
    // The acknowledgement carries `hello: null`. If this were taken as the hello,
    // the rotated token would be lost and the session would die at expiry.
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/subscribed', id: h.wire.last()?.id, hello: null });
    expect(collected.helloes).toHaveLength(0);
  });

  it('takes the first tunnel/event as the hello', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/subscribed', id: h.wire.last()?.id, hello: null });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello({ token: 'fresh', lastBseq: 7 }) });
    expect(collected.helloes).toHaveLength(1);
    expect(collected.helloes[0]).toMatchObject({ token: 'fresh', lastBseq: 7 });
    // The hello is not also delivered as an envelope.
    expect(collected.envelopes).toHaveLength(0);
  });

  it('delivers envelopes after the hello', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello() });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: envelope({ bseq: 13 }) });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: envelope({ bseq: 14, kind: 'bridge' }) });
    expect(collected.envelopes.map((item) => item.bseq)).toEqual([13, 14]);
  });

  it('drops frames that arrive before the hello', () => {
    // Rendering deltas against a baseline that was never established is worse than
    // dropping them: the user would see a partial conversation presented as whole.
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: envelope({ bseq: 5 }) });
    expect(collected.envelopes).toHaveLength(0);
    expect(h.diagnostics.some((entry) => entry.message.includes('before the stream hello'))).toBe(true);
  });

  it('recognizes the hello even if it is not the literally first frame', () => {
    // Structural recognition, not positional: a duplicated or reordered frame must
    // not make the hello unrecoverable.
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: envelope({ bseq: 5 }) });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello() });
    expect(collected.helloes).toHaveLength(1);
  });

  it('surfaces a subscribe failure with its status', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/subscribe-failed', id: h.wire.last()?.id, status: 401, reason: 'token expired' });
    expect(collected.failed).toEqual([{ status: 401, reason: 'token expired' }]);
  });

  it('ignores a subscribe failure for a stale subscription id', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/subscribe-failed', id: 's999', status: 401, reason: 'stale' });
    expect(collected.failed).toHaveLength(0);
  });

  it('surfaces an unsubscribe from the bridge', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello() });
    h.client.handle({ v: 1, type: 'tunnel/unsubscribed', reason: 'dsh restarted' });
    expect(collected.unsubscribed).toEqual(['dsh restarted']);
  });

  it('stops delivering events after an unsubscribe', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello() });
    h.client.handle({ v: 1, type: 'tunnel/unsubscribed', reason: 'gone' });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: envelope({ bseq: 99 }) });
    expect(collected.envelopes).toHaveLength(0);
  });

  it('notifies the subscriber when the tunnel closes underneath it', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.close('carrier lost');
    expect(collected.unsubscribed).toEqual(['carrier lost']);
  });

  it('replaces a subscription rather than running two', () => {
    const h = harness();
    const first = handlers();
    const second = handlers();
    h.client.subscribe({ token: 'tok', handlers: first.handlers });
    h.client.subscribe({ token: 'tok2', handlers: second.handlers });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello() });
    expect(first.helloes).toHaveLength(0);
    expect(second.helloes).toHaveLength(1);
  });

  it('sends an unsubscribe that keeps the tunnel open', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.unsubscribe();
    expect(h.wire.last()).toMatchObject({ type: 'tunnel/unsubscribe' });
    expect(h.client.isClosed()).toBe(false);
  });

  it('drops a malformed envelope after the hello without ending the tunnel', () => {
    const h = harness();
    const collected = handlers();
    h.client.subscribe({ token: 'tok', handlers: collected.handlers });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: hello() });
    h.client.handle({ v: 1, type: 'tunnel/event', envelope: { v: 1, kind: 'mux' } });
    expect(collected.envelopes).toHaveLength(0);
    expect(h.client.isClosed()).toBe(false);
  });

  it('refuses to subscribe on a closed tunnel', () => {
    const h = harness();
    h.client.close();
    expect(h.client.subscribe({ token: 'tok', handlers: handlers().handlers })).toBe(false);
  });
});

describe('unknown and malformed tunnel messages', () => {
  it('ignores an unsupported version', () => {
    const h = harness();
    h.client.handle({ v: 2, type: 'tunnel/response', id: 'r1', status: 200 });
    expect(h.diagnostics.some((entry) => entry.message.includes('unsupported version'))).toBe(true);
  });

  it('ignores a non-object', () => {
    const h = harness();
    for (const value of [null, undefined, 'text', 42]) h.client.handle(value);
    expect(h.client.isClosed()).toBe(false);
  });

  it('notes an unknown type instead of failing', () => {
    // The bridge's frame vocabulary will grow. An unknown type must not kill a
    // working tunnel.
    const h = harness();
    h.client.handle({ v: 1, type: 'tunnel/something-new' });
    expect(h.diagnostics.some((entry) => entry.message.includes('unknown tunnel message type'))).toBe(true);
    expect(h.client.isClosed()).toBe(false);
  });

  it('ignores a pong', () => {
    const h = harness();
    h.client.ping();
    expect(h.wire.last()).toMatchObject({ type: 'tunnel/ping' });
    h.client.handle({ v: 1, type: 'tunnel/pong' });
    expect(h.client.isClosed()).toBe(false);
  });
});

describe('asStreamHello', () => {
  it('accepts a complete hello', () => {
    expect(asStreamHello(hello())).toMatchObject({ kind: 'hello', token: 'rotated-token', lastBseq: 12 });
  });

  it('defaults resync and pendingCount', () => {
    const parsed = asStreamHello({ v: 1, kind: 'hello', bridgeId: 'b', token: 't', tokenExpiresAt: 1, lastBseq: 0 });
    expect(parsed).toMatchObject({ resync: false, pendingCount: 0 });
  });

  it('reads resync when set', () => {
    expect(asStreamHello(hello({ resync: true }))?.resync).toBe(true);
  });

  it('rejects a hello with no usable token or cursor', () => {
    // Without these it cannot serve as a baseline, whatever it calls itself.
    expect(asStreamHello(hello({ token: '' }))).toBeUndefined();
    expect(asStreamHello(hello({ token: undefined }))).toBeUndefined();
    expect(asStreamHello(hello({ lastBseq: undefined }))).toBeUndefined();
    expect(asStreamHello(hello({ lastBseq: Number.NaN }))).toBeUndefined();
    expect(asStreamHello(hello({ tokenExpiresAt: undefined }))).toBeUndefined();
    expect(asStreamHello(hello({ bridgeId: undefined }))).toBeUndefined();
  });

  it('rejects anything that is not a hello', () => {
    expect(asStreamHello(envelope())).toBeUndefined();
    expect(asStreamHello(hello({ kind: 'mux' }))).toBeUndefined();
    expect(asStreamHello(hello({ v: 2 }))).toBeUndefined();
    expect(asStreamHello(null)).toBeUndefined();
    expect(asStreamHello('hello')).toBeUndefined();
  });
});

describe('asStreamEnvelope', () => {
  it('accepts each envelope kind', () => {
    for (const kind of ['mux', 'host', 'bridge']) {
      expect(asStreamEnvelope(envelope({ kind: kind as 'mux' }))?.kind).toBe(kind);
    }
  });

  it('keeps rpcId when present and omits it otherwise', () => {
    expect(asStreamEnvelope(envelope({ rpcId: 'rpc-1' }))?.rpcId).toBe('rpc-1');
    expect(Object.keys(asStreamEnvelope(envelope()) ?? {})).not.toContain('rpcId');
  });

  it('passes an unknown frame through untouched', () => {
    // The frame vocabulary is upstream's and will grow. An unknown `frame.type`
    // must fold to a generic card, not be rejected here.
    const parsed = asStreamEnvelope(envelope({ frame: { type: 'brand/new', extra: [1, 2] } }));
    expect(parsed?.frame).toEqual({ type: 'brand/new', extra: [1, 2] });
  });

  it('tolerates an absent frame', () => {
    expect(asStreamEnvelope({ v: 1, bseq: 1, kind: 'mux' })).toMatchObject({ bseq: 1 });
  });

  it('rejects a bad version, kind, or cursor', () => {
    expect(asStreamEnvelope(envelope({ v: 2 }))).toBeUndefined();
    expect(asStreamEnvelope(envelope({ kind: 'other' }))).toBeUndefined();
    expect(asStreamEnvelope(envelope({ bseq: undefined }))).toBeUndefined();
    expect(asStreamEnvelope(envelope({ bseq: Number.POSITIVE_INFINITY }))).toBeUndefined();
    expect(asStreamEnvelope(null)).toBeUndefined();
  });
});

describe('the default request timeout', () => {
  it('arms a real timer when none is injected', async () => {
    vi.useFakeTimers();
    try {
      const wire = fakeTransport();
      const client = new TunnelClient({ transport: wire.transport, requestTimeoutMs: 10 });
      const pending = client.request({ method: 'GET', path: '/a' });
      const assertion = expect(pending).rejects.toMatchObject({ failure: { kind: 'timeout' } });
      await vi.advanceTimersByTimeAsync(11);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });
});

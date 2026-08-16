/**
 * `M1Core` — the state machine.
 *
 * Everything with a policy in it lives in `core.ts`, so this is where the eight
 * behaviours the brief names get pinned down: reconnect and backoff, token rotation,
 * resync, revocation, pin mismatch, routing collision, the 15-state model, and the
 * memory-only token.
 *
 * All timers are injected and all clocks are fake, so no test waits out a backoff.
 * `random: () => 0.5` makes jitter zero (`base * 0.25 * (2*0.5 - 1) === 0`), which
 * turns the schedule into exact numbers we can assert on rather than a range.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { M1Core, M1Error } from '../src/m1/core';
import { M1_PATHS } from '../src/m1/paths';
import type { WebSocketFactory } from '../src/m1/relay';
import { isTerminalState } from '../src/m1/state';
import { TransportError } from '../src/m1/transport';
import type { M1ClientState, M1CoreEvent } from '../src/m1/types';
import type { StoredBridge } from '../src/storage';
import {
  BRIDGE_ID,
  FakeBridge,
  type FakeStreamSocket,
  dshBusinessError,
  envelopeFrame,
  helloFrame,
  jsonError,
  jsonOk,
} from './helpers/fake-bridge';
import { FakeSocket } from './helpers/fake-relay';
import { fixedIdentity } from './helpers/identity';

const IDENTITY = fixedIdentity(7);

/** The documented schedule, repeated here so a silent change to it fails a test. */
const BACKOFF_MS = [500, 1_000, 2_000, 5_000, 10_000, 20_000, 30_000];

function lanBridge(overrides: Partial<StoredBridge> = {}): StoredBridge {
  return {
    mode: 'lan',
    bridgeId: BRIDGE_ID,
    bridgeName: 'Workstation',
    bridgeKey: 'YmstcGxhY2Vob2xkZXI',
    deviceId: IDENTITY.deviceId,
    scopeTier: 'default',
    pairedAt: 1_000,
    baseUrl: 'https://bridge.local:8443',
    ...overrides,
  } as StoredBridge;
}

function relayBridge(overrides: Partial<StoredBridge> = {}): StoredBridge {
  return {
    mode: 'relay',
    bridgeId: BRIDGE_ID,
    bridgeName: 'Workstation',
    bridgeKey: 'YmstcGxhY2Vob2xkZXI',
    deviceId: IDENTITY.deviceId,
    scopeTier: 'default',
    pairedAt: 1_000,
    relayUrl: 'https://relay.example',
    bridgeRoutingId: 'YnJpZGdlLXJvdXRlLWlkMQ',
    deviceRoutingId: 'ZGV2aWNlLXJvdXRlLWlkMQ',
    ...overrides,
  } as StoredBridge;
}

/**
 * A controllable clock and timer queue.
 *
 * Vitest's fake timers would also work, but the core takes `setTimer`/`clearTimer`
 * as options precisely so a test can *see* what was scheduled. Asserting on
 * `timers.pending[0].ms` is a direct check of the backoff schedule; asserting that
 * `vi.advanceTimersByTime(500)` reconnected is only an indirect one.
 */
class TestClock {
  now = 1_000_000;
  private seq = 0;
  readonly pending: { id: number; ms: number; at: number; run: () => void }[] = [];

  readonly setTimer = (handler: () => void, ms: number): unknown => {
    const id = ++this.seq;
    this.pending.push({ id, ms, at: this.now + ms, run: handler });
    return id;
  };

  readonly clearTimer = (handle: unknown): void => {
    const index = this.pending.findIndex((entry) => entry.id === handle);
    if (index >= 0) this.pending.splice(index, 1);
  };

  /** Run every timer due at or before `now + ms`, advancing the clock. */
  async advance(ms: number): Promise<void> {
    const target = this.now + ms;
    for (;;) {
      const next = this.pending
        .filter((entry) => entry.at <= target)
        .sort((a, b) => a.at - b.at)[0];
      if (next === undefined) break;
      this.now = next.at;
      this.clearTimer(next.id);
      next.run();
      await flush();
    }
    this.now = target;
  }

  /** Fire the single pending timer regardless of its delay. */
  async fireNext(): Promise<void> {
    const next = this.pending[0];
    if (next === undefined) throw new Error('no pending timer to fire');
    this.now = next.at;
    this.clearTimer(next.id);
    next.run();
    await flush();
  }
}

/** Let queued microtasks (the core's async continuations) settle. */
async function flush(times = 8): Promise<void> {
  for (let index = 0; index < times; index += 1) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
  for (let index = 0; index < times; index += 1) await Promise.resolve();
}

interface Harness {
  core: M1Core;
  bridge: FakeBridge;
  clock: TestClock;
  states: M1ClientState[];
  events: M1CoreEvent[];
  /** Every value written to the durable store, in order. */
  writes: (StoredBridge | undefined)[];
  stored: () => StoredBridge | undefined;
  /** The most recent `/m1/stream` socket, asserted to exist. */
  socket: () => FakeStreamSocket;
  resyncCalls: string[];
  /** Replaceable resync handler, so one test can make it throw. */
  setResync: (fn: (reason: string) => Promise<void>) => void;
}

function harness(initial: StoredBridge | undefined, options: { createSocket?: WebSocketFactory } = {}): Harness {
  const bridge = new FakeBridge(IDENTITY.publicKey);
  const clock = new TestClock();
  const states: M1ClientState[] = [];
  const events: M1CoreEvent[] = [];
  const writes: (StoredBridge | undefined)[] = [];
  let current = initial;
  const resyncCalls: string[] = [];
  let resyncImpl: (reason: string) => Promise<void> = async (reason) => {
    resyncCalls.push(reason);
  };

  const core = new M1Core({
    identity: IDENTITY,
    store: {
      read: async () => current,
      write: async (value) => {
        writes.push(value);
        current = value;
      },
    },
    fetchImpl: bridge.fetchImpl,
    webSocketImpl: bridge.webSocketImpl,
    ...(options.createSocket === undefined ? {} : { createSocket: options.createSocket }),
    onResync: async (reason) => {
      await resyncImpl(reason);
    },
    now: () => clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    random: () => 0.5,
  });

  core.subscribe((event) => {
    events.push(event);
    if (event.type === 'state') states.push(event.state);
  });

  return {
    core,
    bridge,
    clock,
    states,
    events,
    writes,
    stored: () => current,
    socket: () => {
      const socket = bridge.lastSocket;
      if (socket === undefined) throw new Error('no stream socket was opened');
      return socket;
    },
    resyncCalls,
    setResync: (fn) => {
      resyncImpl = fn;
    },
  };
}

/** Start, authenticate, open the stream, deliver the hello: a `ready` core. */
async function ready(h: Harness, hello = helloFrame()): Promise<void> {
  await h.core.start();
  await flush();
  h.socket().deliver(hello);
  await flush();
}

const stateNames = (h: Harness): string[] => h.states.map((state) => state.name);
const phases = (h: Harness): (string | undefined)[] =>
  h.states.filter((state) => state.name === 'connecting').map((state) => (state as { phase: string }).phase);

describe('M1Core: startup', () => {
  it('rests in unpaired with no stored route and dials nothing', async () => {
    const h = harness(undefined);
    await h.core.start();
    await flush();

    expect(h.core.getState()).toEqual({ name: 'unpaired', reason: 'fresh' });
    expect(h.bridge.requests).toHaveLength(0);
  });

  it('walks paired → connecting → ready from a stored route', async () => {
    const h = harness(lanBridge());
    await ready(h);

    expect(stateNames(h)).toEqual(['paired', 'connecting', 'connecting', 'ready']);
    expect(h.core.getState()).toEqual({ name: 'ready', lastBseq: 0, dsh: 'up' });
    expect(h.core.mode).toBe('lan');
  });

  it('reports the LAN connect phases without a sealing step', async () => {
    const h = harness(lanBridge());
    await ready(h);

    // `sealing` is Mode B only: there is nothing to verify on the LAN path. And
    // `authenticating` appears once, not twice — `setState` drops the repeat that
    // Mode A's no-op `transport.start()` would otherwise produce.
    expect(phases(h)).toEqual(['authenticating', 'streaming']);
  });

  it('is idempotent: a second start does not open a second session', async () => {
    const h = harness(lanBridge());
    await ready(h);
    await h.core.start();
    await flush();

    expect(h.bridge.sockets).toHaveLength(1);
    expect(h.bridge.issuedTokens).toBe(1);
  });

  it('authenticates with a real device proof before opening the stream', async () => {
    const h = harness(lanBridge());
    await ready(h);

    // Two calls to the one endpoint: challenge, then proof. The double verifies the
    // signature itself, so reaching `ready` means the proof was valid.
    const auth = h.bridge.requestsTo(M1_PATHS.authSession);
    expect(auth).toHaveLength(2);
    expect(auth[0]?.body?.signature).toBeUndefined();
    expect(typeof auth[1]?.body?.signature).toBe('string');
    expect(h.bridge.issuedTokens).toBe(1);
  });

  it('opens the stream with the issued token and the stored cursor', async () => {
    const h = harness(lanBridge());
    await h.core.start();
    await flush();

    expect(h.socket().tokenProtocol).toBe('access-token-1');
    expect(h.socket().after).toBe(0);
  });

  it('prefers a user-supplied address over the stored one', async () => {
    const bridge = new FakeBridge(IDENTITY.publicKey);
    const core = new M1Core({
      identity: IDENTITY,
      store: { read: async () => lanBridge({ baseUrl: 'https://stale.local' }), write: async () => undefined },
      baseUrl: 'https://override.local',
      fetchImpl: bridge.fetchImpl,
      webSocketImpl: bridge.webSocketImpl,
      now: () => 1_000_000,
    });
    await core.start();
    await flush();

    expect(bridge.requests[0]?.path).toBe(M1_PATHS.authSession);
    expect(bridge.sockets[0]?.url.startsWith('wss://override.local')).toBe(true);
    core.dispose();
  });
});

describe('M1Core: the access token stays in memory', () => {
  it('never writes a token to the durable store', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, jsonOk({ sessions: [] }));
    await h.core.rpc('session.list', {});

    // Any write at all is suspicious here; the tier did not change and nothing else
    // should have touched storage.
    const serialized = JSON.stringify(h.writes);
    expect(serialized).not.toContain('access-token');
    expect(serialized).not.toContain('rotated-token');
  });

  it('holds a token while connected and drops it on teardown', async () => {
    const h = harness(lanBridge());
    await ready(h);
    expect(h.core.hasToken()).toBe(true);

    await h.core.clear();
    expect(h.core.hasToken()).toBe(false);
  });

  it('exposes the session without exposing it as storable state', async () => {
    const h = harness(lanBridge());
    await ready(h);

    // The session object does carry the token — it is the auth response — but it is
    // reachable only through `getSession()`, never through `getBridge()`.
    expect(h.core.getSession()?.token).toBe('rotated-token-1');
    expect(JSON.stringify(h.core.getBridge())).not.toContain('token');
  });
});

describe('M1Core: token rotation', () => {
  it('adopts the rotated token from the hello', async () => {
    const h = harness(lanBridge());
    await ready(h, helloFrame({ token: 'rotated-token-9', tokenExpiresAt: 9_999_999 }));

    h.bridge.queue(M1_PATHS.rpc, jsonOk({ sessions: [] }));
    await h.core.rpc('session.list', {});
    const rpc = h.bridge.requestsTo(M1_PATHS.rpc);
    expect(rpc[0]?.token).toBe('rotated-token-9');
  });

  it('re-authenticates when the held token is inside the refresh margin', async () => {
    const h = harness(lanBridge());
    // Expiry 30 s out, margin is 60 s: the next request must refresh first.
    await ready(h, helloFrame({ token: 'nearly-dead', tokenExpiresAt: 1_030_000 }));

    h.bridge.setTokenExpiry(2_000_000);
    h.bridge.queue(M1_PATHS.rpc, jsonOk({ sessions: [] }));
    await h.core.rpc('session.list', {});

    expect(h.bridge.issuedTokens).toBe(2);
    expect(h.bridge.requestsTo(M1_PATHS.rpc)[0]?.token).toBe('access-token-2');
  });

  it('does not re-authenticate when the token is comfortably alive', async () => {
    const h = harness(lanBridge());
    await ready(h, helloFrame({ tokenExpiresAt: h.clock.now + 600_000 }));

    h.bridge.queue(M1_PATHS.rpc, jsonOk({ sessions: [] }));
    await h.core.rpc('session.list', {});

    expect(h.bridge.issuedTokens).toBe(1);
  });

  it('re-authenticates pre-emptively on a token-expiring frame', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().deliver(envelopeFrame(1, 'bridge', { type: 'token-expiring', expiresAt: h.clock.now + 30_000 }));
    await flush();

    expect(h.bridge.issuedTokens).toBe(2);
    // The frame still reaches the UI: a client may want to show it.
    expect(h.events.some((event) => event.type === 'envelope' && event.envelope.bseq === 1)).toBe(true);
  });

  it('retries a request exactly once on a 401, then gives up', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.bridge.queue(M1_PATHS.rpc, jsonError(401, 'unauthenticated'), jsonError(401, 'unauthenticated'));
    await expect(h.core.rpc('session.list', {})).rejects.toThrow(M1Error);

    // Two attempts, not a loop.
    expect(h.bridge.requestsTo(M1_PATHS.rpc)).toHaveLength(2);
  });

  it('succeeds transparently when the re-auth retry works', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.bridge.queue(M1_PATHS.rpc, jsonError(401, 'unauthenticated'), jsonOk({ sessions: ['s1'] }));
    await expect(h.core.rpc<{ sessions: string[] }>('session.list', {})).resolves.toEqual({ sessions: ['s1'] });
    expect(h.bridge.issuedTokens).toBe(2);
  });

  it('shares one auth exchange between concurrent callers', async () => {
    const h = harness(lanBridge());
    await h.core.start();
    await flush();
    h.socket().deliver(helloFrame({ tokenExpiresAt: 1_000 }));
    await flush();

    h.bridge.setTokenExpiry(2_000_000);
    h.bridge.queue(M1_PATHS.rpc, jsonOk({ a: 1 }), jsonOk({ b: 2 }));
    await Promise.all([h.core.rpc('a', {}), h.core.rpc('b', {})]);

    // A second challenge would invalidate the first: the bridge's nonces are
    // single-use per device, so overlapping callers must share one exchange.
    expect(h.bridge.issuedTokens).toBe(2);
    expect(h.bridge.requestsTo(M1_PATHS.authSession)).toHaveLength(4);
  });
});

describe('M1Core: reconnect and backoff', () => {
  it('follows the documented schedule, capped and repeating', async () => {
    const h = harness(lanBridge());
    await ready(h);

    // No hello between closes: a hello resets the counter, which is the *next*
    // test. Here each close must climb one rung.
    for (let index = 0; index < BACKOFF_MS.length + 2; index += 1) {
      h.socket().fireClose(1006, 'network went away');
      await flush();

      const expected = BACKOFF_MS[Math.min(index, BACKOFF_MS.length - 1)] ?? 30_000;
      const state = h.core.getState();
      expect(state.name).toBe('reconnecting');
      expect((state as { attempt: number }).attempt).toBe(index + 1);
      // Zero jitter with `random: () => 0.5`, so this is the base delay exactly.
      expect(h.clock.pending[0]?.ms).toBe(expected);

      await h.clock.fireNext();
    }

    // The last two rungs are both the cap, not 60 s and 120 s.
    h.socket().deliver(helloFrame());
    await flush();
    expect(h.core.getState().name).toBe('ready');
  });

  it('applies jitter within ±25% of the base delay', async () => {
    for (const [roll, expected] of [
      [0, 375],
      [1, 625],
    ] as const) {
      const bridge = new FakeBridge(IDENTITY.publicKey);
      const clock = new TestClock();
      const core = new M1Core({
        identity: IDENTITY,
        store: { read: async () => lanBridge(), write: async () => undefined },
        fetchImpl: bridge.fetchImpl,
        webSocketImpl: bridge.webSocketImpl,
        now: () => clock.now,
        setTimer: clock.setTimer,
        clearTimer: clock.clearTimer,
        random: () => roll,
      });
      await core.start();
      await flush();
      bridge.lastSocket?.deliver(helloFrame());
      await flush();
      bridge.lastSocket?.fireClose(1006, 'dropped');
      await flush();

      expect(clock.pending[0]?.ms).toBe(expected);
      core.dispose();
    }
  });

  it('resets the attempt counter once a hello arrives', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().fireClose(1006, 'first drop');
    await flush();
    await h.clock.fireNext();
    h.socket().deliver(helloFrame());
    await flush();

    h.socket().fireClose(1006, 'second drop');
    await flush();
    // Back to the start of the schedule, not the second rung.
    expect((h.core.getState() as { attempt: number }).attempt).toBe(1);
    expect(h.clock.pending[0]?.ms).toBe(500);
  });

  it('carries the close reason into the reconnecting state', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().fireClose(1011, 'bridge restarting');
    await flush();
    expect(h.core.getState()).toMatchObject({ name: 'reconnecting', reason: 'bridge restarting' });
  });

  it('re-authenticates immediately on a 401 close, with no backoff', async () => {
    const h = harness(lanBridge());
    await ready(h);
    const before = h.clock.pending.length;

    // Mode B can report a status on close; this is that path.
    (h.core as unknown as { onStreamClosed: (r: string, s?: number) => void }).onStreamClosed('unauthorized', 401);
    await flush();

    expect(h.clock.pending.length).toBe(before);
    expect(h.bridge.issuedTokens).toBe(2);
    expect(h.core.getState().name).toBe('connecting');
  });

  it('reconnectNow drops the session and restarts from attempt zero', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().fireClose(1006, 'drop');
    await flush();
    expect((h.core.getState() as { attempt: number }).attempt).toBe(1);
    const sockets = h.bridge.sockets.length;

    await h.core.reconnectNow('app foregrounded');
    await flush();

    // Attempt zero, not two: an explicit reconnect is not a retry.
    expect(h.states.some((state) => state.name === 'connecting' && state.attempt === 0)).toBe(true);
    expect(h.bridge.sockets.length).toBe(sockets + 1);
    // And the pending backoff timer is gone, so it cannot fire a second connect.
    expect(h.clock.pending).toHaveLength(0);
  });

  it('reconnectNow is a no-op in a terminal state', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, jsonError(403, 'device-revoked'));
    await expect(h.core.rpc('session.list', {})).rejects.toThrow();
    await flush();
    expect(h.core.getState().name).toBe('revoked');

    const sockets = h.bridge.sockets.length;
    await h.core.reconnectNow('app foregrounded');
    expect(h.bridge.sockets).toHaveLength(sockets);
    expect(h.core.getState().name).toBe('revoked');
  });

  it('does not open a second transport when connect overlaps itself', async () => {
    const h = harness(lanBridge());
    const first = h.core.start();
    const second = h.core.connect();
    await Promise.all([first, second]);
    await flush();

    expect(h.bridge.sockets).toHaveLength(1);
  });

  it('resumes the stream from the highest bseq seen', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().deliver(envelopeFrame(7, 'mux', { type: 'text' }));
    await flush();

    h.socket().fireClose(1006, 'drop');
    await flush();
    await h.clock.fireNext();

    expect(h.socket().after).toBe(7);
  });

  it('treats a stream error as a close and backs off', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().fireError();
    await flush();
    expect(h.core.getState()).toMatchObject({ name: 'reconnecting', reason: 'stream connection failed' });
  });

  it('backs off when the socket constructor throws', async () => {
    const h = harness(lanBridge());
    h.bridge.failSocketFactory('invalid url');
    await h.core.start();
    await flush();

    expect(h.core.getState().name).toBe('reconnecting');
    expect(h.clock.pending[0]?.ms).toBe(500);
  });

  it('backs off when the bridge is unreachable, without losing the pairing', async () => {
    const h = harness(lanBridge());
    h.bridge.queueAuth({ kind: 'network', message: 'no route to host' });
    await h.core.start();
    await flush();

    expect(h.core.getState().name).toBe('reconnecting');
    expect(h.core.getBridge()).toBeDefined();
    expect(h.writes).toHaveLength(0);
  });
});

describe('M1Core: the harness, as distinct from the bridge', () => {
  it('goes harness-offline on a dsh-disconnected frame and back on dsh-ready', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().deliver(envelopeFrame(1, 'bridge', { type: 'dsh-disconnected' }));
    await flush();
    expect(h.core.getState().name).toBe('harness-offline');
    // Not terminal, and no retry: the stream is still up.
    expect(isTerminalState(h.core.getState())).toBe(false);
    expect(h.clock.pending).toHaveLength(0);

    h.socket().deliver(envelopeFrame(2, 'bridge', { type: 'dsh-ready' }));
    await flush();
    expect(h.core.getState()).toEqual({ name: 'ready', lastBseq: 2, dsh: 'up' });
  });

  it('goes harness-offline on a dsh-unavailable request, without dropping the stream', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.bridge.queue(M1_PATHS.rpc, jsonError(503, 'dsh-unavailable', 'harness is down'));
    await expect(h.core.rpc('session.list', {})).rejects.toThrow(M1Error);
    await flush();

    // The bridge answered, so the path is fine and there is nothing to reconnect.
    // The stream is still open and `dsh-ready` is what takes us back to `ready`.
    expect(h.core.getState()).toEqual({ name: 'harness-offline' });
    expect(h.clock.pending).toHaveLength(0);
    expect(h.socket().closed).toBe(false);

    h.socket().deliver(envelopeFrame(1, 'bridge', { type: 'dsh-ready' }));
    await flush();
    expect(h.core.getState().name).toBe('ready');
  });

  it('goes harness-offline and retries when the connect itself hits dsh-unavailable', async () => {
    const h = harness(lanBridge());
    h.bridge.queueAuth(jsonError(503, 'dsh-unavailable', 'harness is down'));
    await h.core.start();
    await flush();

    // Nothing is established yet, so this one *is* retried.
    expect(stateNames(h)).toContain('harness-offline');
    expect(h.core.getState().name).toBe('reconnecting');
    expect(h.clock.pending[0]?.ms).toBe(500);
  });

  it('leaves a mid-reconnect state alone when a stale request reports the harness down', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, jsonError(503, 'dsh-unavailable', 'harness is down'));
    // Attached now, not after the close: the rejection can land in between.
    const pending = h.core.rpc('session.list', {}).catch(() => undefined);

    h.socket().fireClose(1006, 'drop');
    await flush();
    await pending;
    await flush();

    // `reconnecting` is the more urgent truth: saying `harness-offline` here would
    // tell the user the workstation is reachable when we no longer know that.
    expect(h.core.getState().name).toBe('reconnecting');
  });

  it('ignores a stale harness-down report that lands after a reconnect succeeded', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, jsonError(503, 'dsh-unavailable', 'harness is down'));
    const pending = h.core.rpc('session.list', {}).catch(() => undefined);

    // Drop and fully re-establish while the request is in flight, so its rejection
    // describes a connection that no longer exists.
    h.socket().fireClose(1006, 'drop');
    await flush();
    await h.clock.fireNext();
    await flush();
    h.socket().deliver(helloFrame({ lastBseq: 5 }));
    await flush();
    expect(h.core.getState().name).toBe('ready');

    await pending;
    await flush();
    // The old generation's failure must not mark the new session offline.
    expect(h.core.getState()).toEqual({ name: 'ready', lastBseq: 5, dsh: 'up' });
  });

  it('keeps a dsh business error away from the state machine', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.bridge.queue(M1_PATHS.rpc, dshBusinessError('tool-denied', 'the operator denied that tool'));
    await expect(h.core.rpc('session.send', {})).rejects.toMatchObject({
      code: 'tool-denied',
      isDshError: true,
    });

    // "The harness said no" is not a connection problem. Telling a user to check
    // their Wi-Fi here is exactly the failure this taxonomy exists to prevent.
    expect(h.core.getState().name).toBe('ready');
    expect(h.clock.pending).toHaveLength(0);
  });

  it('ignores pong frames entirely', async () => {
    const h = harness(lanBridge());
    await ready(h);
    const before = h.events.length;

    h.socket().deliver(envelopeFrame(1, 'bridge', { type: 'pong' }));
    await flush();
    expect(h.events).toHaveLength(before);
  });
});

describe('M1Core: resync', () => {
  it('re-baselines when the hello says resync', async () => {
    const h = harness(lanBridge());
    await ready(h, helloFrame({ resync: true, lastBseq: 42 }));

    expect(h.resyncCalls).toEqual(['window-overflow']);
    expect(stateNames(h)).toContain('resyncing');
    expect(h.core.getState()).toEqual({ name: 'ready', lastBseq: 42, dsh: 'up' });
  });

  it('re-baselines on a resync-required frame and reports the reason', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().deliver(envelopeFrame(5, 'bridge', { type: 'resync-required', reason: 'dsh-restarted' }));
    await flush();

    expect(h.resyncCalls).toEqual(['dsh-restarted']);
    expect(h.events.some((event) => event.type === 'resync' && event.reason === 'dsh-restarted')).toBe(true);
    expect(h.core.getState().name).toBe('ready');
  });

  it('folds an unrecognized resync reason to window-overflow', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().deliver(envelopeFrame(5, 'bridge', { type: 'resync-required', reason: 'something-new' }));
    await flush();
    expect(h.resyncCalls).toEqual(['window-overflow']);
  });

  it('returns to ready even when the resync handler throws', async () => {
    const h = harness(lanBridge());
    h.setResync(async () => {
      throw new Error('history fetch failed');
    });
    await ready(h, helloFrame({ resync: true }));

    // A failing handler must not strand the session in `resyncing` forever.
    expect(h.core.getState().name).toBe('ready');
    expect(
      h.events.some((event) => event.type === 'diagnostic' && event.message.includes('resync handler failed')),
    ).toBe(true);
  });

  it('does not run two resyncs at once', async () => {
    const h = harness(lanBridge());
    let release = (): void => undefined;
    h.setResync(async (reason) => {
      h.resyncCalls.push(reason);
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    });
    await h.core.start();
    await flush();
    h.socket().deliver(helloFrame({ resync: true }));
    await flush();

    h.socket().deliver(envelopeFrame(2, 'bridge', { type: 'resync-required', reason: 'dsh-restarted' }));
    await flush();
    expect(h.resyncCalls).toEqual(['window-overflow']);

    release();
    await flush();
    expect(h.core.getState().name).toBe('ready');
  });

  it('does not resurrect a session cleared during a resync', async () => {
    const h = harness(lanBridge());
    let release = (): void => undefined;
    h.setResync(async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
    });
    await h.core.start();
    await flush();
    h.socket().deliver(helloFrame({ resync: true }));
    await flush();

    await h.core.clear();
    release();
    await flush();

    expect(h.core.getState()).toEqual({ name: 'unpaired', reason: 'cleared' });
  });
});

describe('M1Core: revocation', () => {
  it('is terminal, wipes the durable route, and keeps the device key', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().deliver(envelopeFrame(3, 'bridge', { type: 'device-revoked' }));
    await flush();

    expect(h.core.getState()).toEqual({ name: 'revoked' });
    expect(isTerminalState(h.core.getState())).toBe(true);
    expect(h.writes).toEqual([undefined]);
    expect(h.stored()).toBeUndefined();
    // The identity is this phone's, not this pairing's.
    expect(h.core.deviceId).toBe(IDENTITY.deviceId);
  });

  it('schedules no retry and ignores a later connect', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().deliver(envelopeFrame(3, 'bridge', { type: 'device-revoked' }));
    await flush();

    expect(h.clock.pending).toHaveLength(0);
    const sockets = h.bridge.sockets.length;
    await h.core.connect();
    await flush();
    expect(h.bridge.sockets).toHaveLength(sockets);
    expect(h.core.getState().name).toBe('revoked');
  });

  it('revokes on a device-revoked request error even if the caller swallows it', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.bridge.queue(M1_PATHS.rpc, jsonError(403, 'device-revoked', 'this device was removed'));
    await h.core.rpc('session.list', {}).catch(() => undefined);
    await flush();

    expect(h.core.getState().name).toBe('revoked');
  });

  it('revokes on a 403 stream close', async () => {
    const h = harness(lanBridge());
    await ready(h);

    (h.core as unknown as { onStreamClosed: (r: string, s?: number) => void }).onStreamClosed('forbidden', 403);
    await flush();
    expect(h.core.getState().name).toBe('revoked');
  });

  it('treats unauthenticated as unusable, because the bridge will not say which', async () => {
    const h = harness(lanBridge());
    h.bridge.queueAuth(jsonError(401, 'unauthenticated', 'unknown device'));
    await h.core.start();
    await flush();

    // The bridge answers `unauthenticated` for both an unknown and a revoked
    // device on purpose; either way the pairing cannot be used.
    expect(h.core.getState().name).toBe('revoked');
    expect(h.stored()).toBeUndefined();
  });

  it('surfaces a storage failure while wiping instead of hiding it', async () => {
    const bridge = new FakeBridge(IDENTITY.publicKey);
    const events: M1CoreEvent[] = [];
    const core = new M1Core({
      identity: IDENTITY,
      store: {
        read: async () => lanBridge(),
        write: async () => {
          throw new Error('keychain unavailable');
        },
      },
      fetchImpl: bridge.fetchImpl,
      webSocketImpl: bridge.webSocketImpl,
      now: () => 1_000_000,
    });
    core.subscribe((event) => events.push(event));
    await core.start();
    await flush();
    bridge.lastSocket?.deliver(helloFrame());
    await flush();
    bridge.lastSocket?.deliver(envelopeFrame(1, 'bridge', { type: 'device-revoked' }));
    await flush();

    expect(core.getState().name).toBe('revoked');
    expect(
      events.some(
        (event) =>
          event.type === 'diagnostic' &&
          event.level === 'error' &&
          event.message.includes('could not clear the stored pairing'),
      ),
    ).toBe(true);
    core.dispose();
  });

  it('does not re-emit revoked when a second signal arrives', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().deliver(envelopeFrame(3, 'bridge', { type: 'device-revoked' }));
    await flush();
    const writes = h.writes.length;
    const states = h.states.length;

    h.socket().deliver(envelopeFrame(4, 'bridge', { type: 'device-revoked' }));
    await flush();
    expect(h.writes).toHaveLength(writes);
    expect(h.states).toHaveLength(states);
  });
});

describe('M1Core: pin mismatch', () => {
  it('is terminal when a different bridge answers the auth challenge', async () => {
    const h = harness(lanBridge());
    h.bridge.queueAuth(jsonOk({ nonce: 'n', bridgeId: 'some-other-bridge', expiresAt: 9_000_000 }));
    await h.core.start();
    await flush();

    expect(h.core.getState()).toEqual({ name: 'pin-mismatch', detail: 'bridge-identity' });
    expect(isTerminalState(h.core.getState())).toBe(true);
    expect(h.clock.pending).toHaveLength(0);
  });

  it('never signs anything for the wrong bridge', async () => {
    const h = harness(lanBridge());
    h.bridge.queueAuth(jsonOk({ nonce: 'n', bridgeId: 'some-other-bridge', expiresAt: 9_000_000 }));
    await h.core.start();
    await flush();

    // Only the challenge went out. A signature over an attacker's nonce is a
    // credential we must never hand over, even a useless-looking one.
    const auth = h.bridge.requestsTo(M1_PATHS.authSession);
    expect(auth).toHaveLength(1);
    expect(auth[0]?.body?.signature).toBeUndefined();
  });

  it('keeps the pairing on disk so the user can inspect it, and emits an error', async () => {
    const h = harness(lanBridge());
    h.bridge.queueAuth(jsonOk({ nonce: 'n', bridgeId: 'imposter', expiresAt: 9_000_000 }));
    await h.core.start();
    await flush();

    // Deliberately not wiped: unlike revocation, the pairing itself may be fine and
    // the *network* is what lied. Destroying it would help an attacker.
    expect(h.stored()).toBeDefined();
    expect(h.events.some((event) => event.type === 'diagnostic' && event.level === 'error')).toBe(true);
  });

  it('stays terminal across a connect attempt', async () => {
    const h = harness(lanBridge());
    h.bridge.queueAuth(jsonOk({ nonce: 'n', bridgeId: 'imposter', expiresAt: 9_000_000 }));
    await h.core.start();
    await flush();

    await h.core.connect();
    await flush();
    expect(h.core.getState().name).toBe('pin-mismatch');
  });
});

describe('M1Core: relay-specific failures', () => {
  it('reports routing-collision, terminally, with the colliding id', async () => {
    const stored = relayBridge();
    const h = harness(stored);
    (h.core as unknown as { bridge: StoredBridge }).bridge = stored;
    (h.core as unknown as { handleFailure: (error: unknown) => void }).handleFailure(
      new TransportError('transport', 'routing id taken', { relayCode: 'routing-id-taken' }),
    );
    await flush();

    expect(h.core.getState()).toEqual({ name: 'routing-collision', routingId: stored.deviceRoutingId });
    expect(isTerminalState(h.core.getState())).toBe(true);
    expect(h.clock.pending).toHaveLength(0);
  });

  it('reports rendezvous-busy terminally', async () => {
    const h = harness(relayBridge());
    (h.core as unknown as { bridge: StoredBridge }).bridge = relayBridge();
    (h.core as unknown as { handleFailure: (error: unknown) => void }).handleFailure(
      new TransportError('transport', 'rendezvous busy', { relayCode: 'rendezvous-busy' }),
    );
    await flush();

    expect(h.core.getState()).toEqual({ name: 'rendezvous-busy' });
    expect(h.clock.pending).toHaveLength(0);
  });

  it('reports relay-unavailable, with the code, and keeps retrying', async () => {
    const h = harness(relayBridge());
    (h.core as unknown as { bridge: StoredBridge }).bridge = relayBridge();
    (h.core as unknown as { handleFailure: (error: unknown) => void }).handleFailure(
      new TransportError('transport', 'relay is over quota', { relayCode: 'quota-exceeded' }),
    );
    await flush();

    // "relay" rather than "offline": the workstation may be perfectly healthy, and
    // that is the difference between a user waiting and a user rebooting.
    expect(h.core.getState()).toMatchObject({ name: 'relay-unavailable', attempt: 1, code: 'quota-exceeded' });
    expect(h.clock.pending[0]?.ms).toBe(500);
  });

  it('fails cleanly when relay mode has no socket factory on this platform', async () => {
    const h = harness(relayBridge());
    await h.core.start();
    await flush();

    // `validateStoredBridge` guarantees the record is complete, so the only way to
    // get here is a missing `createSocket` — a wiring bug, not bad data.
    expect(h.core.getState().name).toBe('reconnecting');
    expect(
      h.events.some(
        (event) => event.type === 'diagnostic' && event.message.includes('relay transport is not configured'),
      ),
    ).toBe(false);
    expect((h.core.getState() as { reason: string }).reason).toContain('relay transport is not configured');
  });

  it('reports the relay connect phases in order', async () => {
    const h = harness(relayBridge(), {
      // A socket that opens and then says nothing: enough to get past
      // `buildTransport` and observe the phases, without a relay to talk to.
      createSocket: (url, subprotocols) => new FakeSocket(url, subprotocols),
    });
    await h.core.start();
    await flush();

    // `relay` then `sealing` — the phone must not claim to be authenticating while
    // it is still verifying the pinned key.
    expect(phases(h).slice(0, 2)).toEqual(['relay', 'sealing']);
  });
});

describe('M1Core: LAN address changes', () => {
  it('persists a new address and reconnects', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.core.setBaseUrl('https://moved.local:8443/');
    await flush();

    // Persisted, or the next launch dials the old address again.
    expect(h.writes.at(-1)).toMatchObject({ baseUrl: 'https://moved.local:8443' });
    expect(h.bridge.sockets.at(-1)?.url.startsWith('wss://moved.local:8443')).toBe(true);
  });

  it('ignores a no-op address change', async () => {
    const h = harness(lanBridge());
    await ready(h);
    const sockets = h.bridge.sockets.length;

    h.core.setBaseUrl('https://bridge.local:8443');
    await flush();
    expect(h.bridge.sockets).toHaveLength(sockets);
    expect(h.writes).toHaveLength(0);
  });

  it('does not reconnect a relay pairing on an address change', async () => {
    const h = harness(relayBridge());
    await h.core.start();
    await flush();
    const before = h.states.length;

    h.core.setBaseUrl('https://irrelevant.local');
    await flush();
    // Mode B does not use `baseUrl`; changing it must not disturb the session.
    expect(h.states).toHaveLength(before);
    expect(h.writes).toHaveLength(0);
  });

  it('backs off when a LAN pairing has no address at all', async () => {
    const h = harness(lanBridge({ baseUrl: undefined }));
    await h.core.start();
    await flush();

    expect(h.core.getState()).toMatchObject({
      name: 'reconnecting',
      reason: 'no bridge address is configured',
    });
  });
});

describe('M1Core: health probe', () => {
  it('returns the unauthenticated health body', async () => {
    const h = harness(lanBridge());
    h.bridge.queue(M1_PATHS.health, { kind: 'json', status: 200, body: { ok: true, dsh: 'up' } });

    await expect(h.core.health('https://bridge.local:8443')).resolves.toEqual({ ok: true, dsh: 'up' });
    expect(h.bridge.requestsTo(M1_PATHS.health)[0]?.token).toBeUndefined();
  });

  it('rejects without an address rather than guessing one', async () => {
    const h = harness(undefined);
    await expect(h.core.health()).rejects.toThrow('no bridge address to check');
  });

  it('rejects on a non-200', async () => {
    const h = harness(lanBridge());
    h.bridge.queue(M1_PATHS.health, { kind: 'json', status: 503, body: { ok: false } });
    await expect(h.core.health('https://bridge.local:8443')).rejects.toThrow('health check failed (503)');
  });

  it('rejects when something that is not the bridge answers', async () => {
    const h = harness(lanBridge());
    h.bridge.queue(M1_PATHS.health, { kind: 'text', status: 200, text: '<html>captive portal</html>' });
    await expect(h.core.health('https://bridge.local:8443')).rejects.toThrow('returned no body');
  });
});

describe('M1Core: requests', () => {
  it('refuses to send anything while offline', async () => {
    const h = harness(lanBridge());
    await expect(h.core.rpc('session.list', {})).rejects.toMatchObject({ kind: 'offline' });
    expect(h.bridge.requests).toHaveLength(0);
  });

  it('sends the documented rpc envelope', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, jsonOk({ sessions: [] }));

    await h.core.rpc('session.list', { limit: 5 }, 'req-1');
    expect(h.bridge.requestsTo(M1_PATHS.rpc)[0]?.body).toEqual({
      v: 1,
      method: 'session.list',
      payload: { limit: 5 },
      requestId: 'req-1',
    });
  });

  it('omits requestId when the caller did not supply one', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, jsonOk({}));

    await h.core.rpc('session.list', {});
    expect(h.bridge.requestsTo(M1_PATHS.rpc)[0]?.body).not.toHaveProperty('requestId');
  });

  it('posts approvals and question answers to /m1/respond', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.respond, jsonOk({}), jsonOk({}));

    await h.core.respondApproval('rpc-1', 'allowed-once');
    await h.core.respondQuestion('rpc-2', [{ id: 'q1', value: 'yes' }]);

    expect(h.bridge.requestsTo(M1_PATHS.respond).map((entry) => entry.body)).toEqual([
      { v: 1, rpcId: 'rpc-1', kind: 'approval', outcome: 'allowed-once' },
      { v: 1, rpcId: 'rpc-2', kind: 'question', answers: [{ id: 'q1', value: 'yes' }] },
    ]);
  });

  it('preserves a bridge error code and retryAfterMs for the caller', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, jsonError(429, 'rate-limited', 'slow down', { retryAfterMs: 2_500 }));

    await expect(h.core.rpc('session.send', {})).rejects.toMatchObject({
      code: 'rate-limited',
      retryAfterMs: 2_500,
      isDshError: false,
    });
  });

  it('reports a transport failure as a transport failure and backs off', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, { kind: 'network', message: 'connection reset' });

    await expect(h.core.rpc('session.list', {})).rejects.toMatchObject({ kind: 'offline' });
    await flush();
    expect(h.core.getState().name).toBe('reconnecting');
  });

  it('treats an unenveloped error status as an error', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.bridge.queue(M1_PATHS.rpc, { kind: 'text', status: 502, text: 'bad gateway' });

    await expect(h.core.rpc('session.list', {})).rejects.toMatchObject({ code: 'internal', status: 502 });
  });
});

describe('M1Core: stream frame handling', () => {
  it('advances lastBseq and forwards envelopes to the UI', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().deliver(envelopeFrame(1, 'mux', { type: 'text', text: 'hi' }, 'rpc-1'));
    h.socket().deliver(envelopeFrame(2, 'host', { type: 'approval' }));
    await flush();

    expect(h.core.getLastBseq()).toBe(2);
    const envelopes = h.events.filter((event) => event.type === 'envelope');
    expect(envelopes).toHaveLength(2);
    expect(h.core.getState()).toEqual({ name: 'ready', lastBseq: 2, dsh: 'up' });
  });

  it('never moves lastBseq backwards', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().deliver(envelopeFrame(9, 'mux', {}));
    await flush();
    h.socket().deliver(envelopeFrame(4, 'mux', {}));
    await flush();

    expect(h.core.getLastBseq()).toBe(9);
  });

  it('takes the higher of the stored cursor and the hello lastBseq', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().deliver(envelopeFrame(20, 'mux', {}));
    await flush();
    h.socket().fireClose(1006, 'drop');
    await flush();
    await h.clock.fireNext();

    // A bridge that reports a *lower* cursor must not rewind us into replaying
    // frames the UI has already rendered.
    h.socket().deliver(helloFrame({ lastBseq: 5 }));
    await flush();
    expect(h.core.getLastBseq()).toBe(20);
  });

  it('drops a frame that arrives before the hello', async () => {
    const h = harness(lanBridge());
    await h.core.start();
    await flush();

    h.socket().deliver(envelopeFrame(1, 'mux', {}));
    await flush();
    // No baseline and no rotated token yet, so rendering it would be worse than
    // dropping it.
    expect(h.events.some((event) => event.type === 'envelope')).toBe(false);
    expect(h.core.getState().name).toBe('connecting');
  });

  it('drops malformed frames without killing the stream', async () => {
    const h = harness(lanBridge());
    await ready(h);

    h.socket().deliverRaw('not json at all');
    h.socket().deliver({ v: 1, bseq: 'nope', kind: 'mux', frame: {} });
    h.socket().deliver({ v: 2, bseq: 1, kind: 'mux', frame: {} });
    await flush();

    expect(h.events.some((event) => event.type === 'envelope')).toBe(false);
    expect(h.core.getState().name).toBe('ready');
  });

  it('emits the hello as an event so a consumer can see rotation happen', async () => {
    const h = harness(lanBridge());
    await ready(h, helloFrame({ pendingCount: 3 }));

    const hello = h.events.find((event) => event.type === 'hello');
    expect(hello).toMatchObject({ type: 'hello', hello: { pendingCount: 3 } });
  });
});

describe('M1Core: clear and dispose', () => {
  it('clear wipes the route, stops everything, and rests in unpaired/cleared', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().deliver(envelopeFrame(4, 'mux', {}));
    await flush();

    await h.core.clear();

    expect(h.core.getState()).toEqual({ name: 'unpaired', reason: 'cleared' });
    expect(h.writes).toEqual([undefined]);
    expect(h.core.getBridge()).toBeUndefined();
    expect(h.core.getLastBseq()).toBe(0);
    expect(h.core.hasToken()).toBe(false);
    expect(h.clock.pending).toHaveLength(0);
  });

  it('clear strands an in-flight reconnect', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().fireClose(1006, 'drop');
    await flush();
    expect(h.clock.pending).toHaveLength(1);

    await h.core.clear();
    expect(h.clock.pending).toHaveLength(0);

    const sockets = h.bridge.sockets.length;
    await h.core.connect();
    await flush();
    expect(h.bridge.sockets).toHaveLength(sockets);
  });

  it('a stale stream cannot deliver into a cleared core', async () => {
    const h = harness(lanBridge());
    await ready(h);
    const stale = h.socket();
    await h.core.clear();

    stale.deliver(envelopeFrame(5, 'mux', { type: 'text' }));
    stale.deliver(helloFrame({ token: 'ghost-token' }));
    await flush();

    expect(h.core.getState()).toEqual({ name: 'unpaired', reason: 'cleared' });
    expect(h.core.getLastBseq()).toBe(0);
    expect(h.core.hasToken()).toBe(false);
  });

  it('dispose stops listeners and timers', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().fireClose(1006, 'drop');
    await flush();

    h.core.dispose();
    const events = h.events.length;
    expect(h.clock.pending).toHaveLength(0);

    h.socket().deliver(envelopeFrame(1, 'mux', {}));
    await flush();
    expect(h.events).toHaveLength(events);
  });
});

describe('M1Core: state model coverage', () => {
  it('emits no duplicate consecutive states', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.socket().deliver(envelopeFrame(1, 'mux', {}));
    await flush();

    // The hook mirrors these into React state; a duplicate is a wasted render.
    for (let index = 1; index < h.states.length; index += 1) {
      expect(JSON.stringify(h.states[index])).not.toBe(JSON.stringify(h.states[index - 1]));
    }
  });

  it('reaches every non-pairing state the contract names', async () => {
    const seen = new Set<string>();
    // The current state counts too: `unpaired/fresh` is the initial state, so
    // `start()` on a fresh install correctly emits nothing.
    const record = (h: Harness): void => {
      for (const state of h.states) seen.add(state.name);
      seen.add(h.core.getState().name);
    };

    // unpaired/fresh
    const fresh = harness(undefined);
    await fresh.core.start();
    record(fresh);

    // scanning
    fresh.core.beginScanning();
    record(fresh);

    // paired → connecting → ready → harness-offline → resyncing
    const live = harness(lanBridge());
    await ready(live);
    live.socket().deliver(envelopeFrame(1, 'bridge', { type: 'dsh-disconnected' }));
    await flush();
    live.socket().deliver(envelopeFrame(2, 'bridge', { type: 'resync-required' }));
    await flush();
    record(live);

    // reconnecting
    live.socket().fireClose(1006, 'drop');
    await flush();
    record(live);

    // revoked
    const revoked = harness(lanBridge());
    await ready(revoked);
    revoked.socket().deliver(envelopeFrame(1, 'bridge', { type: 'device-revoked' }));
    await flush();
    record(revoked);

    // pin-mismatch
    const mismatch = harness(lanBridge());
    mismatch.bridge.queueAuth(jsonOk({ nonce: 'n', bridgeId: 'imposter', expiresAt: 1 }));
    await mismatch.core.start();
    await flush();
    record(mismatch);

    for (const [code, name] of [
      ['routing-id-taken', 'routing-collision'],
      ['rendezvous-busy', 'rendezvous-busy'],
      ['quota-exceeded', 'relay-unavailable'],
    ] as const) {
      const relay = harness(relayBridge());
      (relay.core as unknown as { bridge: StoredBridge }).bridge = relayBridge();
      (relay.core as unknown as { handleFailure: (e: unknown) => void }).handleFailure(
        new TransportError('transport', code, { relayCode: code }),
      );
      await flush();
      expect(relay.core.getState().name).toBe(name);
      record(relay);
    }

    for (const name of [
      'unpaired',
      'scanning',
      'paired',
      'connecting',
      'ready',
      'reconnecting',
      'harness-offline',
      'relay-unavailable',
      'rendezvous-busy',
      'routing-collision',
      'resyncing',
      'revoked',
      'pin-mismatch',
    ]) {
      expect(seen).toContain(name);
    }
  });

  it('beginScanning is refused once paired', async () => {
    const h = harness(lanBridge());
    await ready(h);
    h.core.beginScanning();
    expect(h.core.getState().name).toBe('ready');
  });
});

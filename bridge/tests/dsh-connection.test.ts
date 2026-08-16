import { describe, expect, it, vi } from 'vitest';
import { DshApiClient } from '../src/dsh/client.ts';
import { DshConnection } from '../src/dsh/connection.ts';
import { DshDownlink } from '../src/dsh/downlink.ts';
import { rebaseline } from '../src/dsh/rebaseline.ts';
import { FakeDsh } from './fake-dsh.ts';
import { socketRecorder } from './fake-socket.ts';

const BASE = 'http://127.0.0.1:3080';

function harness(options: { describeFails?: boolean } = {}) {
  const fake = new FakeDsh(
    options.describeFails
      ? { errors: { 'host.describe': { code: 'internal', message: 'host is unwell', details: {} } } }
      : { methods: { 'host.describe': () => ({ canOpenPath: true }) } },
  );
  const recorder = socketRecorder();
  const client = new DshApiClient({ baseUrl: BASE, fetchImpl: fake.fetch });
  const downlink = new DshDownlink({
    baseUrl: BASE,
    webSocketFactory: recorder.factory,
    onMalformedFrame: () => {},
  });
  return { fake, recorder, client, downlink };
}

describe('DshConnection readiness', () => {
  it('requires both sockets open AND host.describe before reporting connected', async () => {
    const { client, downlink, recorder } = harness();
    const states: string[] = [];
    let description: unknown;

    const connection = new DshConnection({
      client,
      downlink,
      sleepImpl: () => new Promise(() => {}), // never let backoff or the open-timeout fire
      sinks: {
        onStateChange: (state) => states.push(state),
        onConnected: (value) => {
          description = value;
        },
      },
    });
    connection.start();

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(2));
    expect(states).toEqual(['connecting']);

    // Only the mux socket is open: the handshake must not complete.
    recorder.byPath('events.mux')!.open();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(connection.isConnected()).toBe(false);
    expect(description).toBeUndefined();

    recorder.byPath('events.host')!.open();
    await vi.waitFor(() => expect(connection.isConnected()).toBe(true));
    expect(description).toEqual({ canOpenPath: true });
    expect(connection.getDescription()).toEqual({ canOpenPath: true });

    await connection.stop();
  });

  it('never reports connected when host.describe fails', async () => {
    const { client, downlink, recorder } = harness({ describeFails: true });
    const connection = new DshConnection({
      client,
      downlink,
      backoffBaseMs: 1,
      sleepImpl: (ms, signal) =>
        new Promise((resolve) => {
          const timer = setTimeout(resolve, Math.min(ms, 1));
          signal.addEventListener('abort', () => {
            clearTimeout(timer);
            resolve();
          });
        }),
    });
    connection.start();

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(2));
    recorder.byPath('events.mux')!.open();
    recorder.byPath('events.host')!.open();

    // Both sockets are open, so only the failed describe keeps us disconnected.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(connection.isConnected()).toBe(false);
    expect(connection.getDescription()).toBeUndefined();

    await connection.stop();
  });

  it('fails the whole generation and rebuilds BOTH streams when one socket dies', async () => {
    const { client, downlink, recorder } = harness();
    const disconnects: string[] = [];
    const connection = new DshConnection({
      client,
      downlink,
      backoffBaseMs: 1,
      sleepImpl: (ms) => new Promise((resolve) => setTimeout(resolve, Math.min(ms, 1))),
      sinks: { onDisconnected: (reason) => disconnects.push(reason) },
    });
    connection.start();

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(2));
    recorder.byPath('events.mux')!.open();
    recorder.byPath('events.host')!.open();
    await vi.waitFor(() => expect(connection.isConnected()).toBe(true));

    // Kill only the host socket.
    recorder.sockets[1]!.close();

    // Both are rebuilt: a second pair of sockets appears.
    await vi.waitFor(() => expect(recorder.sockets.length).toBeGreaterThanOrEqual(4));
    expect(disconnects).toHaveLength(1);
    // The surviving mux socket from the dead generation was closed too.
    expect(recorder.sockets[0]!.closed).toBe(true);

    await connection.stop();
  });

  it('clears the host description on generation loss so stale capabilities are never served', async () => {
    const { client, downlink, recorder } = harness();
    // Observed inside the disconnect sink: the invariant is that a capability
    // answer is never available WHILE disconnected. Polling after the fact would
    // race the next generation, which legitimately republishes a description.
    let descriptionAtDisconnect: unknown = 'not-yet-called';
    const connection = new DshConnection({
      client,
      downlink,
      backoffBaseMs: 1,
      sleepImpl: (ms) => new Promise((resolve) => setTimeout(resolve, Math.min(ms, 1))),
      sinks: {
        onDisconnected: () => {
          descriptionAtDisconnect = connection.getDescription();
        },
      },
    });
    connection.start();

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(2));
    recorder.byPath('events.mux')!.open();
    recorder.byPath('events.host')!.open();
    await vi.waitFor(() => expect(connection.getDescription()).toEqual({ canOpenPath: true }));

    recorder.sockets[0]!.close();
    await vi.waitFor(() => expect(descriptionAtDisconnect).not.toBe('not-yet-called'));
    expect(descriptionAtDisconnect).toBeUndefined();

    await connection.stop();
    // And it is cleared again after an explicit stop.
    expect(connection.getDescription()).toBeUndefined();
  });
});

describe('official rebaseline procedure', () => {
  it('re-baselines session.list and workspace.list and never sends a `since` field', async () => {
    const fake = new FakeDsh({
      methods: {
        'session.list': () => ({ items: [{ sessionId: 's1', blank: false }] }),
        'workspace.list': () => ({ items: [{ workspaceId: 'w1' }] }),
        'session.history': (payload) => ({
          events: [],
          hasMore: false,
          projections: { title: { value: 'Fix the parser', seq: 12 } },
          echo: payload,
        }),
      },
    });
    const client = new DshApiClient({ baseUrl: BASE, fetchImpl: fake.fetch });

    const result = await rebaseline(client, {
      sessionIds: ['s1'],
      watermarks: new Map([['s1', 42]]),
    });

    expect(result.sessions).toEqual({ items: [{ sessionId: 's1', blank: false }] });
    expect(result.workspaces).toEqual({ items: [{ workspaceId: 'w1' }] });
    expect(result.histories.has('s1')).toBe(true);
    expect(result.watermarks.get('s1')).toBe(42);
    expect(result.failures).toHaveLength(0);

    // `since` is an unimplemented seat upstream; it must never appear on the wire.
    const serialized = JSON.stringify(fake.requests);
    expect(serialized).not.toContain('since');
    // `cursor` is likewise a reserved seat: session.list is sent an empty payload.
    const listRequest = fake.requests.find((r) => r.method === 'session.list')!;
    expect((listRequest.body as { payload: unknown }).payload).toEqual({});
  });

  it('collects a partial failure rather than discarding what did succeed', async () => {
    const fake = new FakeDsh({
      methods: { 'session.list': () => ({ items: [] }) },
      errors: { 'workspace.list': { code: 'internal', message: 'workspace store down', details: {} } },
    });
    const client = new DshApiClient({ baseUrl: BASE, fetchImpl: fake.fetch });

    const result = await rebaseline(client);

    expect(result.sessions).toEqual({ items: [] });
    expect(result.workspaces).toBeUndefined();
    expect(result.failures).toEqual([
      { method: 'workspace.list', code: 'internal', message: expect.stringContaining('workspace store down') },
    ]);
  });
});

import { describe, expect, it, vi } from 'vitest';
import { DshDownlink } from '../src/dsh/downlink.ts';
import type { MuxFrame } from '../src/dsh/types.ts';
import { socketRecorder } from './fake-socket.ts';

const BASE = 'http://127.0.0.1:3080';

/** Collect frames until `count` arrive, then abort the stream. */
async function collect<T>(iterator: AsyncGenerator<T>, count: number): Promise<T[]> {
  const out: T[] = [];
  if (count === 0) return out;
  for await (const item of iterator) {
    out.push(item);
    if (out.length >= count) break;
  }
  return out;
}

describe('DshDownlink', () => {
  it('upgrades to ws:// on the verified event paths', async () => {
    const recorder = socketRecorder();
    const downlink = new DshDownlink({ baseUrl: BASE, webSocketFactory: recorder.factory });
    const ac = new AbortController();

    void downlink.openMux(ac.signal).next();
    void downlink.openHost(ac.signal).next();
    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(2));

    expect(recorder.sockets[0]!.url).toBe('ws://127.0.0.1:3080/api/events.mux');
    expect(recorder.sockets[1]!.url).toBe('ws://127.0.0.1:3080/api/events.host');
    ac.abort();
  });

  it('yields validated mux frames with the rpcId that answerable frames echo', async () => {
    const recorder = socketRecorder();
    const downlink = new DshDownlink({ baseUrl: BASE, webSocketFactory: recorder.factory });
    const ac = new AbortController();
    const stream = downlink.openMux(ac.signal);
    const collected = collect(stream, 2);

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(1));
    const socket = recorder.sockets[0]!;
    socket.open();
    socket.deliverFrame('rpc-sub', { type: 'session/subscribed', sessionId: 's1', lastSeq: 42 });
    socket.deliverFrame('rpc-approval', {
      type: 'approval/requested',
      sessionId: 's1',
      approvalId: 'a1',
      toolName: 'bash',
      reason: 'run tests',
    });

    const frames = await collected;
    expect(frames[0]!.rpcId).toBe('rpc-sub');
    expect(frames[0]!.frame).toEqual({ type: 'session/subscribed', sessionId: 's1', lastSeq: 42 });
    expect(frames[1]!.rpcId).toBe('rpc-approval');
    expect((frames[1]!.frame as MuxFrame & { type: 'approval/requested' }).toolName).toBe('bash');
    ac.abort();
  });

  it('reports and skips a corrupt frame without killing the stream', async () => {
    const malformed: string[] = [];
    const recorder = socketRecorder();
    const downlink = new DshDownlink({
      baseUrl: BASE,
      webSocketFactory: recorder.factory,
      onMalformedFrame: (_path, reason) => malformed.push(reason),
    });
    const ac = new AbortController();
    const collected = collect(downlink.openMux(ac.signal), 1);

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(1));
    const socket = recorder.sockets[0]!;
    socket.open();

    socket.deliver('this is not json');
    socket.deliver(JSON.stringify({ type: 'not-a-server-request' }));
    socket.deliverFrame('rpc-x', { type: 'session/subscribed', sessionId: 's1' }); // lastSeq missing
    socket.deliverFrame('rpc-x', { type: 'future/frame-from-a-newer-harness', sessionId: 's1' });
    // The stream survives all four and still delivers the next good frame.
    socket.deliverFrame('rpc-good', { type: 'session/subscribed', sessionId: 's1', lastSeq: 7 });

    const frames = await collected;
    expect(frames).toHaveLength(1);
    expect(frames[0]!.rpcId).toBe('rpc-good');
    expect(malformed).toHaveLength(4);
    expect(malformed[3]).toContain('unknown mux frame type');
    ac.abort();
  });

  it('rejects an empty question/requested batch as host breakage', async () => {
    const malformed: string[] = [];
    const recorder = socketRecorder();
    const downlink = new DshDownlink({
      baseUrl: BASE,
      webSocketFactory: recorder.factory,
      onMalformedFrame: (_p, reason) => malformed.push(reason),
    });
    const ac = new AbortController();
    void collect(downlink.openMux(ac.signal), 1);

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(1));
    const socket = recorder.sockets[0]!;
    socket.open();
    socket.deliverFrame('rpc-q', { type: 'question/requested', sessionId: 's1', questions: [] });

    await vi.waitFor(() => expect(malformed).toHaveLength(1));
    expect(malformed[0]).toContain('non-empty array');
    ac.abort();
  });

  it('ends the stream when the socket closes', async () => {
    const recorder = socketRecorder();
    const downlink = new DshDownlink({ baseUrl: BASE, webSocketFactory: recorder.factory });
    const ac = new AbortController();

    const drained = (async () => {
      const out: unknown[] = [];
      for await (const frame of downlink.openMux(ac.signal)) out.push(frame);
      return out;
    })();

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(1));
    const socket = recorder.sockets[0]!;
    socket.open();
    socket.deliverFrame('rpc-1', { type: 'session/subscribed', sessionId: 's1', lastSeq: 1 });
    socket.close();

    await expect(drained).resolves.toHaveLength(1);
  });

  it('closes the socket when the generation signal aborts', async () => {
    const recorder = socketRecorder();
    const downlink = new DshDownlink({ baseUrl: BASE, webSocketFactory: recorder.factory });
    const ac = new AbortController();

    const drained = (async () => {
      for await (const _frame of downlink.openMux(ac.signal)) void _frame;
    })();

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(1));
    recorder.sockets[0]!.open();
    ac.abort();

    await drained;
    expect(recorder.sockets[0]!.closed).toBe(true);
  });

  it('accepts the three host frames the research doc omitted', async () => {
    const recorder = socketRecorder();
    const malformed: string[] = [];
    const downlink = new DshDownlink({
      baseUrl: BASE,
      webSocketFactory: recorder.factory,
      onMalformedFrame: (_p, reason) => malformed.push(reason),
    });
    const ac = new AbortController();
    const collected = collect(downlink.openHost(ac.signal), 3);

    await vi.waitFor(() => expect(recorder.sockets).toHaveLength(1));
    const socket = recorder.sockets[0]!;
    socket.open();
    socket.deliverFrame('r1', { type: 'host/workspace-order-changed', workspaceIds: ['w1', 'w2'] });
    socket.deliverFrame('r2', { type: 'host/archived-sessions-changed', archivedSessionIds: ['s9'] });
    socket.deliverFrame('r3', { type: 'host/remote-event', event: 'some/hook', args: [1, 'two'] });

    const frames = await collected;
    expect(frames.map((f) => (f.frame as { type: string }).type)).toEqual([
      'host/workspace-order-changed',
      'host/archived-sessions-changed',
      'host/remote-event',
    ]);
    expect(malformed).toHaveLength(0);
    ac.abort();
  });
});

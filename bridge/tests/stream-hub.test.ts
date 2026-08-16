/**
 * StreamHub: fanout, resume, and pending-obligation replay.
 *
 * The hub is where the phone's reconnect story becomes observable. FrameRing has
 * its own tests for window arithmetic; these concentrate on the behaviours that
 * only exist once ingest, snapshots, pending obligations, and subscribers are
 * combined:
 *
 * - mux and host frames share one ordered log, because the phone folds against
 *   arrival order;
 * - a resync hands over snapshots instead of history;
 * - pending obligations are replayed on *every* attach, with the original rpcId;
 * - a dsh restart invalidates the previous generation's state without ever
 *   reusing a bseq.
 *
 * The hub is deliberately credential-free — anything reaching it is already
 * authorized — so there is nothing auth-shaped to assert here. That separation is
 * the point: a fanout bug cannot become an auth bypass.
 */

import { describe, expect, it, vi } from 'vitest';
import { StreamHub, type Subscriber } from '../src/stream/hub.ts';
import type { BridgeEnvelope } from '../src/stream/ring.ts';
import type { HostFrame, MuxFrame } from '../src/dsh/types.ts';

/** A subscriber that records what it was handed, in order. */
function recorder(deviceId = 'device-1'): Subscriber & { received: BridgeEnvelope[] } {
  const received: BridgeEnvelope[] = [];
  return { deviceId, deliver: (envelope) => void received.push(envelope), received };
}

/**
 * Read `rpcId` off an envelope.
 *
 * Needed because `bridge` envelopes have no `rpcId` field at all, by design — our
 * own control frames are never answerable. The type system enforces that, so a
 * test reaching for the property has to say which kind it expects.
 */
function rpcIdOf(envelope: BridgeEnvelope | undefined): string | undefined {
  if (envelope === undefined || envelope.kind === 'bridge') return undefined;
  return envelope.rpcId;
}

function mux(frame: MuxFrame, rpcId = 'rpc-mux'): { rpcId: string; frame: MuxFrame } {
  return { rpcId, frame };
}

function host(frame: HostFrame, rpcId = 'rpc-host'): { rpcId: string; frame: HostFrame } {
  return { rpcId, frame };
}

const subscribed = (sessionId: string, lastSeq = 0): MuxFrame => ({ type: 'session/subscribed', sessionId, lastSeq });
const approval = (approvalId: string, sessionId = 's-1'): MuxFrame => ({
  type: 'approval/requested',
  sessionId,
  approvalId,
  toolName: 'shell',
});

/** A hub already past its first `dsh-ready`, which is the normal serving state. */
function readyHub(...args: ConstructorParameters<typeof StreamHub>): StreamHub {
  const hub = new StreamHub(...args);
  hub.onDshReady();
  return hub;
}

describe('StreamHub', () => {
  describe('readiness gate', () => {
    it('refuses to attach before dsh is ready', () => {
      // Attaching to a hub with no upstream would look like a healthy stream that
      // simply has no traffic, which is indistinguishable from an idle workstation.
      // The phone needs to be able to tell those apart.
      const hub = new StreamHub();
      expect(hub.isReady()).toBe(false);
      expect(hub.attach(recorder(), 0)).toEqual({ ok: false, reason: 'not-ready' });
    });

    it('publishes dsh-ready with a generation number on first readiness', () => {
      const hub = new StreamHub();
      hub.onDshReady();
      expect(hub.isReady()).toBe(true);
      const attached = hub.attach(recorder(), 0);
      expect(attached.ok).toBe(true);
      if (!attached.ok) return;
      // Generation 1, and no resync: there was no previous generation to invalidate.
      expect(attached.backlog.map((envelope) => envelope.frame)).toEqual([{ type: 'dsh-ready', generation: 1 }]);
      expect(attached.resynced).toBe(false);
    });

    it('reports a disconnect as a frame in the log, then stops serving attaches', () => {
      const hub = readyHub();
      const device = recorder();
      hub.attach(device, 0);
      hub.onDshDisconnected('socket closed');

      // Already-attached devices are told inline rather than dropped: the socket to
      // the phone is still fine, and reconnecting it would lose the explanation.
      expect(device.received.at(-1)?.frame).toEqual({ type: 'dsh-disconnected', error: 'socket closed' });
      expect(hub.isReady()).toBe(false);
      expect(hub.attach(recorder('device-2'), 0).ok).toBe(false);
    });
  });

  describe('ordered log', () => {
    it('interleaves mux and host frames in arrival order under one counter', () => {
      // The two downlinks are separate sockets upstream, so their relative order is
      // only defined by when the bridge saw them. Merging into one counter is what
      // lets the phone treat "host says the session is gone" and "mux says it
      // emitted an event" as comparable in time.
      const hub = readyHub();
      const device = recorder();
      hub.attach(device, hub.stats().lastBseq);

      hub.ingestMux(mux(subscribed('s-1')));
      hub.ingestHost(host({ type: 'host/session-status', sessionId: 's-1', running: true }));
      hub.ingestMux(mux(subscribed('s-2')));

      expect(device.received.map((envelope) => [envelope.bseq, envelope.kind])).toEqual([
        [2, 'mux'],
        [3, 'host'],
        [4, 'mux'],
      ]);
    });

    it('tags answerable mux frames with the dsh rpcId and leaves others untagged', () => {
      const hub = readyHub();
      const answerable = hub.ingestMux(mux(approval('a-1'), 'rpc-approval'));
      const ordinary = hub.ingestMux(mux(subscribed('s-1'), 'rpc-plain'));

      // A phone that holds an rpcId can answer. Handing one out for a frame that
      // takes no answer would invite a `not-pending` round trip at best, and at
      // worst teach the phone that any frame is answerable.
      expect(rpcIdOf(answerable)).toBe('rpc-approval');
      expect(rpcIdOf(ordinary)).toBeUndefined();
    });

    it('fans out to every attached device and stops after detach', () => {
      const hub = readyHub();
      const first = recorder('device-1');
      const second = recorder('device-2');
      const cursor = hub.stats().lastBseq;
      hub.attach(first, cursor);
      hub.attach(second, cursor);

      hub.ingestMux(mux(subscribed('s-1')));
      hub.detach(second);
      hub.ingestMux(mux(subscribed('s-2')));

      expect(first.received).toHaveLength(2);
      expect(second.received).toHaveLength(1);
      // Same envelope object identity is fine and intended: envelopes are frozen
      // history, and copying per subscriber would only cost memory.
      expect(first.received[0]).toBe(second.received[0]);
    });

    it('keeps fanning out when one subscriber throws', () => {
      // A phone whose socket has been torn down under us will throw on write. If
      // that aborted the loop, one dead device could silence every other one.
      const hub = readyHub();
      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      try {
        const healthy = recorder('device-healthy');
        const broken: Subscriber = {
          deviceId: 'device-broken',
          deliver: () => {
            throw new Error('socket gone');
          },
        };
        hub.attach(broken, hub.stats().lastBseq);
        hub.attach(healthy, hub.stats().lastBseq);

        expect(() => hub.ingestMux(mux(subscribed('s-1')))).not.toThrow();
        expect(healthy.received).toHaveLength(1);
        expect(spy).toHaveBeenCalled();
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('resume', () => {
    it('serves a delta from the cursor without a resync', () => {
      const hub = readyHub();
      hub.ingestMux(mux(subscribed('s-1')));
      const cursor = hub.stats().lastBseq;
      hub.ingestMux(mux(subscribed('s-2')));
      hub.ingestMux(mux(subscribed('s-3')));

      const attached = hub.attach(recorder(), cursor);
      expect(attached.ok).toBe(true);
      if (!attached.ok) return;
      expect(attached.resynced).toBe(false);
      expect(attached.snapshots).toEqual([]);
      expect(attached.backlog.map((envelope) => envelope.bseq)).toEqual([cursor + 1, cursor + 2]);
      expect(attached.lastBseq).toBe(cursor + 2);
    });

    it('hands over snapshots instead of history when the cursor fell out of the window', () => {
      // The trade the resync makes: the phone loses the individual events it missed,
      // but snapshot frames are replace-never-merge upstream, so the newest of each
      // is enough to be current. Replaying an unbounded log would be the alternative.
      const hub = readyHub({ ringLimits: { maxFrames: 3 } });
      hub.ingestMux(mux({ type: 'session/queue', sessionId: 's-1', items: [] }));
      const staleCursor = hub.stats().lastBseq;
      for (let index = 0; index < 5; index += 1) hub.ingestMux(mux(subscribed(`s-${index}`)));

      const attached = hub.attach(recorder(), staleCursor);
      expect(attached.ok).toBe(true);
      if (!attached.ok) return;
      expect(attached.resynced).toBe(true);
      expect(attached.backlog).toEqual([]);
      expect(attached.snapshots.map((envelope) => envelope.frame)).toEqual([
        { type: 'session/queue', sessionId: 's-1', items: [] },
      ]);
      // Even though the queue frame itself was evicted from the ring, the snapshot
      // survived it — which is the whole reason the resync is acceptable.
      expect(attached.lastBseq).toBe(hub.stats().lastBseq);
    });

    it('stamps snapshot and pending envelopes with the current cursor, not a new one', () => {
      // These are re-deliveries, not events. Advancing the counter for them would
      // make the phone's cursor unreachable by anyone else's, and would leave gaps
      // in the log that never contained anything.
      const hub = readyHub({ ringLimits: { maxFrames: 2 } });
      hub.ingestMux(mux({ type: 'session/jobs', sessionId: 's-1', jobs: [] }));
      hub.ingestMux(mux(approval('a-1'), 'rpc-approval'));
      const before = hub.stats().lastBseq;
      for (let index = 0; index < 3; index += 1) hub.ingestMux(mux(subscribed(`filler-${index}`)));

      const attached = hub.attach(recorder(), before - 1);
      expect(attached.ok).toBe(true);
      if (!attached.ok) return;
      const last = hub.stats().lastBseq;
      expect(attached.snapshots.map((envelope) => envelope.bseq)).toEqual([last]);
      expect(attached.pending.map((envelope) => envelope.bseq)).toEqual([last]);
      // And the counter did not move because of the attach.
      expect(hub.stats().lastBseq).toBe(last);
    });
  });

  describe('pending obligations', () => {
    it('replays open approvals on a plain resume, with the original rpcId', () => {
      // The failure this prevents: phone backgrounds mid-approval, reconnects with a
      // perfectly valid cursor, gets an empty delta, and the session sits blocked
      // forever on an answer nobody knows is owed.
      const hub = readyHub();
      hub.ingestMux(mux(approval('a-1'), 'rpc-approval'));
      const cursor = hub.stats().lastBseq;

      const attached = hub.attach(recorder(), cursor);
      expect(attached.ok).toBe(true);
      if (!attached.ok) return;
      expect(attached.resynced).toBe(false);
      expect(attached.backlog).toEqual([]);
      expect(attached.pending).toHaveLength(1);
      expect(rpcIdOf(attached.pending[0])).toBe('rpc-approval');
      expect(attached.pending[0]?.frame).toEqual(approval('a-1'));
    });

    it('replays to a second device too, since either may answer', () => {
      const hub = readyHub();
      hub.ingestMux(mux(approval('a-1'), 'rpc-approval'));
      const first = hub.attach(recorder('device-1'), hub.stats().lastBseq);
      const second = hub.attach(recorder('device-2'), hub.stats().lastBseq);
      expect(first.ok && first.pending).toHaveLength(1);
      expect(second.ok && second.pending).toHaveLength(1);
    });

    it('replays oldest first', () => {
      // Approvals block a session, so the one that has been waiting longest is the
      // one most likely to be holding something up.
      let clock = 1_000;
      const hub = readyHub({ now: () => clock });
      hub.ingestMux(mux(approval('a-old'), 'rpc-old'));
      clock += 5_000;
      hub.ingestMux(mux(approval('a-new'), 'rpc-new'));

      const attached = hub.attach(recorder(), hub.stats().lastBseq);
      expect(attached.ok && attached.pending.map(rpcIdOf)).toEqual(['rpc-old', 'rpc-new']);
    });

    it('stops replaying once we answered it ourselves', () => {
      const hub = readyHub();
      hub.ingestMux(mux(approval('a-1'), 'rpc-approval'));
      expect(hub.isPending('rpc-approval')).toBe(true);
      expect(hub.consumePending('rpc-approval')).toBe(true);
      // Idempotent: a retried respond must not report success twice, because the
      // HTTP layer turns a false here into `already-resolved`.
      expect(hub.consumePending('rpc-approval')).toBe(false);
      expect(hub.isPending('rpc-approval')).toBe(false);

      const attached = hub.attach(recorder(), hub.stats().lastBseq);
      expect(attached.ok && attached.pending).toEqual([]);
    });

    it('stops replaying once dsh says someone else resolved it', () => {
      // Another client answered, or the tool call was cancelled. Continuing to
      // replay would offer the phone a button that can only fail.
      const hub = readyHub();
      hub.ingestMux(mux(approval('a-1'), 'rpc-approval'));
      hub.ingestMux(mux({ type: 'approval/resolved', sessionId: 's-1', approvalId: 'a-1', outcome: 'allowed-once' }));
      expect(hub.isPending('rpc-approval')).toBe(false);
      expect(hub.pendingCount()).toBe(0);
    });

    it('drops obligations for a session the host says is gone', () => {
      const hub = readyHub();
      hub.ingestMux(mux(approval('a-1', 's-doomed'), 'rpc-approval'));
      hub.ingestHost(host({ type: 'host/session-removed', sessionId: 's-doomed' }));
      expect(hub.isPending('rpc-approval')).toBe(false);
      // The snapshot store is cleaned on the same frame, so a resync cannot
      // resurrect the dead session either.
      expect(hub.stats().snapshots).toBe(0);
    });

    it('never treats an rpcId it did not deliver as pending', () => {
      // This is the authorization check behind POST /m1/respond: a phone must not be
      // able to answer on behalf of a frame it never saw.
      const hub = readyHub();
      expect(hub.isPending('rpc-invented')).toBe(false);
      expect(hub.consumePending('rpc-invented')).toBe(false);
    });
  });

  describe('dsh restart', () => {
    it('invalidates the previous generation and keeps counting bseq', () => {
      const hub = readyHub();
      hub.ingestMux(mux({ type: 'session/queue', sessionId: 's-1', items: [] }));
      hub.ingestMux(mux(approval('a-1'), 'rpc-approval'));
      const beforeRestart = hub.stats().lastBseq;

      const device = recorder();
      hub.attach(device, beforeRestart);
      hub.onDshReady();

      // Told to re-baseline, then told the new generation is up — in that order, so
      // the phone cannot act on the new generation before it knows to discard state.
      expect(device.received.map((envelope) => envelope.frame)).toEqual([
        { type: 'resync-required', reason: 'dsh-restarted' },
        { type: 'dsh-ready', generation: 2 },
      ]);
      // Numbering continued. Reuse would let a resuming device accept a new frame as
      // one it already had.
      expect(device.received.map((envelope) => envelope.bseq)).toEqual([beforeRestart + 1, beforeRestart + 2]);
      // The dead generation's obligations and snapshots are gone: that rpcId would
      // now answer `not-pending` upstream.
      expect(hub.isPending('rpc-approval')).toBe(false);
      expect(hub.stats().snapshots).toBe(0);
      expect(hub.stats().pending).toBe(0);
    });

    it('forces a resync for a device that reconnects across the restart', () => {
      const hub = readyHub();
      hub.ingestMux(mux(subscribed('s-1')));
      const staleCursor = hub.stats().lastBseq - 1;
      hub.onDshReady();

      const attached = hub.attach(recorder(), staleCursor);
      expect(attached.ok && attached.resynced).toBe(true);
    });

    it('does not resync on the very first ready', () => {
      // Generation 1 has no predecessor to invalidate, and emitting a
      // `resync-required` there would make every cold start look like a fault.
      const hub = new StreamHub();
      const device = recorder();
      hub.onDshReady();
      hub.attach(device, 0);
      expect(device.received).toEqual([]);
      expect(hub.stats().lastBseq).toBe(1);
    });
  });

  describe('per-device delivery', () => {
    it('tells a revoked device why, then drops only its subscriptions', () => {
      const hub = readyHub();
      const revoked = recorder('device-revoked');
      const other = recorder('device-other');
      hub.attach(revoked, hub.stats().lastBseq);
      hub.attach(other, hub.stats().lastBseq);

      expect(hub.disconnectDevice('device-revoked')).toBe(1);
      expect(revoked.received.map((envelope) => envelope.frame)).toEqual([{ type: 'device-revoked' }]);

      hub.ingestMux(mux(subscribed('s-1')));
      // Ordering matters: the reason is delivered *before* the drop, or the phone
      // only ever sees a socket close and retries forever.
      expect(revoked.received).toHaveLength(1);
      expect(other.received).toHaveLength(1);
    });

    it('drops every stream a device holds, not just the first', () => {
      const hub = readyHub();
      const first = recorder('device-multi');
      const second = recorder('device-multi');
      hub.attach(first, hub.stats().lastBseq);
      hub.attach(second, hub.stats().lastBseq);
      expect(hub.disconnectDevice('device-multi')).toBe(2);
      expect(hub.stats().subscribers).toBe(0);
    });

    it('notifies one device without dropping it', () => {
      const hub = readyHub();
      const target = recorder('device-1');
      const other = recorder('device-2');
      hub.attach(target, hub.stats().lastBseq);
      hub.attach(other, hub.stats().lastBseq);

      expect(hub.notifyDevice('device-1', { type: 'token-expiring', expiresAt: 1_700_000_000_000 })).toBe(1);
      expect(target.received.map((envelope) => envelope.frame)).toEqual([{ type: 'token-expiring', expiresAt: 1_700_000_000_000 }]);
      expect(other.received).toEqual([]);
      // Still attached, unlike disconnectDevice.
      expect(hub.stats().subscribers).toBe(2);
    });

    it('reports zero for an unknown device rather than throwing', () => {
      const hub = readyHub();
      expect(hub.disconnectDevice('device-absent')).toBe(0);
      expect(hub.notifyDevice('device-absent', { type: 'device-revoked' })).toBe(0);
    });
  });
});

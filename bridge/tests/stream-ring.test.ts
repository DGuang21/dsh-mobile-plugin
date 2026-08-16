/**
 * FrameRing: the resume window.
 *
 * dsh has no resume of its own, so this is the primitive the phone's whole
 * reconnect story rests on. The tests below concentrate on the boundaries where a
 * wrong answer is silently corrupting rather than loudly broken — a truncated
 * delta that looks like a complete one is far worse than a resync, because the
 * phone folds it into state and never learns it missed anything.
 */

import { describe, expect, it } from 'vitest';
import { FrameRing, type BridgeEnvelope } from '../src/stream/ring.ts';

/** A mux envelope minus its bseq, which the ring assigns. */
function mux(sessionId: string, lastSeq = 0): Omit<BridgeEnvelope, 'bseq'> {
  return { v: 1, kind: 'mux', frame: { type: 'session/subscribed', sessionId, lastSeq } } as Omit<BridgeEnvelope, 'bseq'>;
}

describe('FrameRing', () => {
  describe('sequence assignment', () => {
    it('starts at 1 and increases by one', () => {
      const ring = new FrameRing();
      expect(ring.append(mux('a')).bseq).toBe(1);
      expect(ring.append(mux('b')).bseq).toBe(2);
      expect(ring.lastBseq()).toBe(2);
    });

    it('reports lastBseq 0 before anything is appended', () => {
      // Not 1. A phone that has seen nothing sends `after=0`, and the two values
      // must not be confusable.
      expect(new FrameRing().lastBseq()).toBe(0);
    });

    it('never reuses a bseq after eviction', () => {
      const ring = new FrameRing({ maxFrames: 2 });
      for (let index = 0; index < 5; index += 1) ring.append(mux(`s-${index}`));
      // The window slid, but numbering continued: reuse would let a resuming
      // device accept a new frame as one it already had.
      expect(ring.lastBseq()).toBe(5);
      expect(ring.earliestBseq()).toBe(4);
      expect(ring.size()).toBe(2);
    });

    it('rejects limits below one rather than silently clamping', () => {
      expect(() => new FrameRing({ maxFrames: 0 })).toThrow(/maxFrames/);
      expect(() => new FrameRing({ maxBytes: 0 })).toThrow(/maxBytes/);
    });
  });

  describe('reading a live window', () => {
    it('returns everything after the requested point', () => {
      const ring = new FrameRing();
      ring.append(mux('a'));
      ring.append(mux('b'));
      ring.append(mux('c'));
      const read = ring.readAfter(1);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.frames.map((frame) => frame.bseq)).toEqual([2, 3]);
      expect(read.lastBseq).toBe(3);
    });

    it('treats after=0 as the whole retained window', () => {
      const ring = new FrameRing();
      ring.append(mux('a'));
      ring.append(mux('b'));
      const read = ring.readAfter(0);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.frames.map((frame) => frame.bseq)).toEqual([1, 2]);
    });

    it('returns an empty delta, not a resync, when the caller is current', () => {
      const ring = new FrameRing();
      ring.append(mux('a'));
      const read = ring.readAfter(1);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.frames).toEqual([]);
    });

    it('reads an empty ring at after=0 without demanding a resync', () => {
      // A phone attaching to a bridge that has published nothing yet is a normal
      // cold start, not a gap.
      const read = new FrameRing().readAfter(0);
      expect(read.ok).toBe(true);
    });
  });

  describe('resync boundaries', () => {
    it('demands a resync when the requested point was evicted', () => {
      const ring = new FrameRing({ maxFrames: 2 });
      for (let index = 0; index < 5; index += 1) ring.append(mux(`s-${index}`));
      const read = ring.readAfter(1);
      expect(read.ok).toBe(false);
      if (read.ok) return;
      expect(read.reason).toBe('resync-required');
      // Both bounds are reported so the phone can tell how far behind it fell.
      expect(read.earliestBseq).toBe(4);
      expect(read.lastBseq).toBe(5);
    });

    it('demands a resync for after=0 once anything has been evicted', () => {
      // The subtle one. `after=0` looks like "send me everything", but on a ring
      // that has evicted, honouring it would start the device mid-history with no
      // indication that earlier frames existed.
      const ring = new FrameRing({ maxFrames: 2 });
      ring.append(mux('a'));
      ring.append(mux('b'));
      ring.append(mux('c'));
      expect(ring.readAfter(0).ok).toBe(false);
    });

    it('demands a resync when asked for a point in the future', () => {
      // Happens after a bridge restart resets the counter while the phone still
      // holds a high cursor. The log cannot prove what the client already has.
      const ring = new FrameRing();
      ring.append(mux('a'));
      expect(ring.readAfter(99).ok).toBe(false);
    });

    it('demands a resync for a non-integer or negative cursor', () => {
      const ring = new FrameRing();
      ring.append(mux('a'));
      expect(ring.readAfter(-1).ok).toBe(false);
      expect(ring.readAfter(1.5).ok).toBe(false);
      expect(ring.readAfter(Number.NaN).ok).toBe(false);
    });

    it('serves the exact oldest retained frame without a resync', () => {
      // The off-by-one that matters: a device holding exactly the oldest retained
      // bseq has a complete history and must NOT be forced to re-baseline.
      const ring = new FrameRing({ maxFrames: 3 });
      for (let index = 0; index < 5; index += 1) ring.append(mux(`s-${index}`));
      expect(ring.earliestBseq()).toBe(3);
      const read = ring.readAfter(3);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.frames.map((frame) => frame.bseq)).toEqual([4, 5]);
    });
  });

  describe('byte budget', () => {
    it('evicts on bytes even when the frame count is fine', () => {
      const ring = new FrameRing({ maxFrames: 1000, maxBytes: 500 });
      const big = { v: 1, kind: 'mux', frame: { type: 'session/subscribed', sessionId: 'x'.repeat(300), lastSeq: 0 } };
      ring.append(big as Omit<BridgeEnvelope, 'bseq'>);
      ring.append(big as Omit<BridgeEnvelope, 'bseq'>);
      ring.append(big as Omit<BridgeEnvelope, 'bseq'>);
      // One huge frame must not be able to pin the whole budget's worth of history.
      expect(ring.size()).toBeLessThan(3);
      expect(ring.byteSize()).toBeLessThanOrEqual(500 + 400);
    });

    it('keeps one frame even when it alone exceeds the byte budget', () => {
      // Evicting to empty would make the ring useless for the very next reader,
      // and a device that just received the frame could never resume from it.
      const ring = new FrameRing({ maxBytes: 10 });
      ring.append(mux('a'.repeat(200)));
      expect(ring.size()).toBe(1);
    });

    it('tracks byteSize down as well as up', () => {
      const ring = new FrameRing({ maxFrames: 2 });
      ring.append(mux('a'));
      ring.append(mux('b'));
      const peak = ring.byteSize();
      ring.append(mux('c'));
      // Eviction must decrement the running total, or the budget leaks and the
      // ring slowly starves itself down to one frame.
      expect(ring.byteSize()).toBeLessThanOrEqual(peak);
      expect(ring.byteSize()).toBeGreaterThan(0);
    });
  });

  describe('clearRetained', () => {
    it('drops frames but keeps the counter', () => {
      const ring = new FrameRing();
      ring.append(mux('a'));
      ring.append(mux('b'));
      ring.clearRetained();

      expect(ring.size()).toBe(0);
      expect(ring.byteSize()).toBe(0);
      // The counter survives: a dsh restart produces new frames that must not
      // reuse numbers the phone already holds.
      expect(ring.lastBseq()).toBe(2);
      expect(ring.append(mux('c')).bseq).toBe(3);
    });

    it('forces a resync for any device that was behind', () => {
      const ring = new FrameRing();
      ring.append(mux('a'));
      ring.append(mux('b'));
      ring.clearRetained();
      expect(ring.readAfter(1).ok).toBe(false);
      expect(ring.readAfter(0).ok).toBe(false);
    });

    it('gives a device at the exact clear point an empty delta, not a resync', () => {
      // Deliberate, and the same boundary rule as eviction: `evictedThrough` is
      // the last bseq that is *gone*, and a device holding it has already received
      // it. It has missed nothing, so demanding a re-baseline would be busywork.
      //
      // This is safe in practice because `clearRetained` is never the last thing
      // that happens — see the next test.
      const ring = new FrameRing();
      ring.append(mux('a'));
      ring.append(mux('b'));
      ring.clearRetained();
      const read = ring.readAfter(2);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.frames).toEqual([]);
    });

    it('still tells a current device to resync, via the frames the hub publishes next', () => {
      // The restart path in StreamHub.onDshReady is clearRetained() followed by
      // publishing `resync-required` and `dsh-ready`. So the device sitting at the
      // clear point learns about the restart as ordinary frames, in order, rather
      // than through the attach result. Verified here as a sequence because the
      // safety of the previous test depends on it.
      const ring = new FrameRing();
      ring.append(mux('a'));
      ring.append(mux('b'));
      ring.clearRetained();
      ring.append({ v: 1, kind: 'bridge', frame: { type: 'resync-required', reason: 'dsh-restarted' } } as Omit<BridgeEnvelope, 'bseq'>);
      ring.append({ v: 1, kind: 'bridge', frame: { type: 'dsh-ready', generation: 2 } } as Omit<BridgeEnvelope, 'bseq'>);

      const read = ring.readAfter(2);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.frames.map((frame) => (frame.kind === 'bridge' ? frame.frame.type : frame.kind))).toEqual([
        'resync-required',
        'dsh-ready',
      ]);
    });
  });
});

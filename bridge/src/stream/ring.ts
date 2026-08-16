/**
 * [OUR DESIGN] Bounded resume log.
 *
 * dsh has no resume: `since` is an unimplemented seat on the subscribe payload
 * (DSH_CORE_RESEARCH.md §6). Mobile clients background, lose radio and reconnect
 * constantly, so the bridge owns resume. This file is the retention primitive.
 *
 * Invariants:
 * - `bseq` is bridge-assigned, monotonic, and starts at 1. It is NOT dsh's
 *   per-session `seq`, and the two must never be compared.
 * - Retention is bounded by BOTH a frame count and a byte budget, whichever
 *   trips first, so one huge frame cannot pin megabytes of history.
 * - A reader asking for a `bseq` that has already been evicted gets
 *   `resync-required`, never a partial delta. A silent gap would corrupt the
 *   phone's fold; an explicit resync is recoverable.
 */

import type { HostFrame, MuxFrame } from '../dsh/types.ts';

/** Our control frames. Deliberately distinguishable from dsh frames. */
export type BridgeFrame =
  | { type: 'resync-required'; reason: 'window-overflow' | 'dsh-restarted' }
  | { type: 'dsh-disconnected'; error?: string }
  | { type: 'dsh-ready'; generation: number }
  | { type: 'token-expiring'; expiresAt: number }
  | { type: 'device-revoked' }
  | { type: 'pong'; at: number };

/**
 * The envelope pushed to the phone. `kind` tells the client which vocabulary
 * `frame` belongs to, so an upstream addition can never be mistaken for one of
 * our control frames.
 */
export type BridgeEnvelope =
  | { v: 1; bseq: number; kind: 'mux'; rpcId?: string; frame: MuxFrame }
  | { v: 1; bseq: number; kind: 'host'; rpcId?: string; frame: HostFrame }
  | { v: 1; bseq: number; kind: 'bridge'; frame: BridgeFrame };

export interface RingLimits {
  /** Maximum retained frames. Default 2000 (CORE_ARCHITECTURE.md §3.2). */
  readonly maxFrames: number;
  /** Maximum retained bytes of serialized frame payload. Default 8 MiB. */
  readonly maxBytes: number;
}

export const DEFAULT_RING_LIMITS: RingLimits = {
  maxFrames: 2000,
  maxBytes: 8 * 1024 * 1024,
};

export type ReadResult =
  | { ok: true; frames: readonly BridgeEnvelope[]; lastBseq: number }
  | { ok: false; reason: 'resync-required'; earliestBseq: number; lastBseq: number };

interface Entry {
  readonly envelope: BridgeEnvelope;
  readonly bytes: number;
}

/**
 * Append-only log with a bounded tail. Not a fixed-size array: entries are
 * shifted off the front as either budget is exceeded, which keeps eviction
 * order identical to arrival order and makes `earliestBseq` trivially correct.
 */
export class FrameRing {
  private readonly limits: RingLimits;
  private entries: Entry[] = [];
  private bytes = 0;
  private nextBseq = 1;
  /** Highest bseq ever assigned, retained after eviction empties the ring. */
  private lastAssigned = 0;
  /** Highest bseq that has been evicted; readers at or below this must resync. */
  private evictedThrough = 0;

  constructor(limits: Partial<RingLimits> = {}) {
    const merged = { ...DEFAULT_RING_LIMITS, ...limits };
    if (merged.maxFrames < 1) throw new Error('maxFrames must be >= 1');
    if (merged.maxBytes < 1) throw new Error('maxBytes must be >= 1');
    this.limits = merged;
  }

  /**
   * Assign the next `bseq` and retain the envelope.
   *
   * Takes the envelope without its `bseq` because the ring is the single
   * authority for sequence assignment; letting a caller pass one in would
   * eventually produce two frames with the same number.
   */
  append(input: Omit<BridgeEnvelope, 'bseq'>): BridgeEnvelope {
    const bseq = this.nextBseq++;
    const envelope = { ...input, bseq } as BridgeEnvelope;
    // Approximate cost by serialized size. Exact heap cost is unknowable and
    // irrelevant; what matters is that a big frame counts as big.
    const bytes = Buffer.byteLength(JSON.stringify(envelope), 'utf8');
    this.entries.push({ envelope, bytes });
    this.bytes += bytes;
    this.lastAssigned = bseq;
    this.evict();
    return envelope;
  }

  /**
   * Frames strictly after `after`.
   *
   * `after: 0` means "everything retained", which is what a fresh device sends.
   * A caller that asks for a point already evicted gets `resync-required` —
   * never a truncated delta.
   */
  readAfter(after: number): ReadResult {
    if (!Number.isInteger(after) || after < 0) {
      return { ok: false, reason: 'resync-required', earliestBseq: this.earliestBseq(), lastBseq: this.lastAssigned };
    }
    // Asking for the future (e.g. after a bridge restart reset the counter)
    // is not resumable: our log cannot prove what the client already has.
    if (after > this.lastAssigned) {
      return { ok: false, reason: 'resync-required', earliestBseq: this.earliestBseq(), lastBseq: this.lastAssigned };
    }
    if (after > 0 && after < this.evictedThrough) {
      return { ok: false, reason: 'resync-required', earliestBseq: this.earliestBseq(), lastBseq: this.lastAssigned };
    }
    // `after === 0` on a ring that has already evicted is also a resync: the
    // device would silently start mid-history and never learn what it missed.
    if (after === 0 && this.evictedThrough > 0) {
      return { ok: false, reason: 'resync-required', earliestBseq: this.earliestBseq(), lastBseq: this.lastAssigned };
    }
    const frames = this.entries.filter((entry) => entry.envelope.bseq > after).map((entry) => entry.envelope);
    return { ok: true, frames, lastBseq: this.lastAssigned };
  }

  /** Lowest retained bseq, or the next one to be assigned when empty. */
  earliestBseq(): number {
    return this.entries[0]?.envelope.bseq ?? this.nextBseq;
  }

  lastBseq(): number {
    return this.lastAssigned;
  }

  size(): number {
    return this.entries.length;
  }

  byteSize(): number {
    return this.bytes;
  }

  /**
   * Drop all retained frames but keep the sequence counter.
   *
   * Used when dsh restarts: the retained tail describes a dead generation, but
   * reusing numbers would make a resuming client accept new frames as old ones.
   */
  clearRetained(): void {
    this.evictedThrough = this.lastAssigned;
    this.entries = [];
    this.bytes = 0;
  }

  private evict(): void {
    while (this.entries.length > this.limits.maxFrames || (this.bytes > this.limits.maxBytes && this.entries.length > 1)) {
      const dropped = this.entries.shift();
      if (!dropped) break;
      this.bytes -= dropped.bytes;
      this.evictedThrough = dropped.envelope.bseq;
    }
  }
}

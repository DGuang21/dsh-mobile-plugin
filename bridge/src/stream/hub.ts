/**
 * [OUR DESIGN] Fanout hub: one dsh generation, many phones.
 *
 * Responsibilities, in the order they matter:
 * 1. Merge the two dsh downlinks into a single ordered log with a bridge-assigned
 *    `bseq`. Mux and host frames interleave in arrival order; that order is the
 *    contract the phone folds against.
 * 2. Serve resume from the ring, and refuse to serve a partial delta.
 * 3. Track pending answerable frames and replay them on every attach with the
 *    original `rpcId`.
 * 4. Translate dsh generation changes into our `bridge` control frames.
 *
 * Deliberately NOT here: authentication and policy. A subscriber reaching this
 * class has already been authorized. Keeping the hub credential-free means a
 * fanout bug cannot become an auth bypass.
 */

import type { DownlinkEnvelope } from '../dsh/downlink.ts';
import { ANSWERABLE_FRAME_TYPES, type HostFrame, type MuxFrame, type RpcId } from '../dsh/types.ts';
import { FrameRing, type BridgeEnvelope, type BridgeFrame, type RingLimits } from './ring.ts';
import { PendingAnswerables, SnapshotStore, type PendingAnswerable } from './snapshots.ts';

/** What a device gets when it attaches. */
export type AttachResult =
  | {
      ok: true;
      /** Retained delta, or [] for a fresh attach on an empty ring. */
      backlog: readonly BridgeEnvelope[];
      /** Current snapshots, sent before the delta on a resync. */
      snapshots: readonly BridgeEnvelope[];
      /** Replayed pending obligations, same `rpcId` as first delivery. */
      pending: readonly BridgeEnvelope[];
      lastBseq: number;
      resynced: boolean;
    }
  | { ok: false; reason: 'not-ready' };

export interface Subscriber {
  readonly deviceId: string;
  /** Called for every envelope after attach. Must not throw. */
  readonly deliver: (envelope: BridgeEnvelope) => void;
}

export interface StreamHubOptions {
  ringLimits?: Partial<RingLimits>;
  now?: () => number;
}

export class StreamHub {
  private readonly ring: FrameRing;
  private readonly snapshots = new SnapshotStore();
  private readonly pending: PendingAnswerables;
  private readonly subscribers = new Set<Subscriber>();
  private readonly now: () => number;
  private dshReady = false;
  private generation = 0;

  constructor(options: StreamHubOptions = {}) {
    this.ring = new FrameRing(options.ringLimits ?? {});
    this.now = options.now ?? Date.now;
    this.pending = new PendingAnswerables(this.now);
  }

  // ── ingest ────────────────────────────────────────────────────────────────

  ingestMux(envelope: DownlinkEnvelope<MuxFrame>): BridgeEnvelope {
    const frame = envelope.frame;
    // Record the obligation before publishing, so a subscriber that immediately
    // answers cannot race ahead of the pending set.
    if (ANSWERABLE_FRAME_TYPES.has(frame.type)) this.pending.record(envelope.rpcId, frame);
    this.pending.resolveFromFrame(frame);
    this.snapshots.record('mux', frame);
    const published = this.ring.append({
      v: 1,
      kind: 'mux',
      ...(ANSWERABLE_FRAME_TYPES.has(frame.type) ? { rpcId: envelope.rpcId } : {}),
      frame,
    });
    this.fanout(published);
    return published;
  }

  ingestHost(envelope: DownlinkEnvelope<HostFrame>): BridgeEnvelope {
    const frame = envelope.frame;
    this.snapshots.record('host', frame);
    if (frame.type === 'host/session-removed') {
      this.snapshots.forgetSession(frame.sessionId);
      this.pending.forgetSession(frame.sessionId);
    }
    const published = this.ring.append({ v: 1, kind: 'host', frame });
    this.fanout(published);
    return published;
  }

  /** Emit one of our own control frames into the same ordered log. */
  publishBridgeFrame(frame: BridgeFrame): BridgeEnvelope {
    const published = this.ring.append({ v: 1, kind: 'bridge', frame });
    this.fanout(published);
    return published;
  }

  // ── dsh lifecycle ─────────────────────────────────────────────────────────

  /**
   * A new dsh generation is ready.
   *
   * Retained state describes the previous generation, so it is dropped and every
   * attached device is told to resync. Reusing `bseq` numbers across a restart
   * would let a resuming device accept new frames as ones it already had, which
   * is why the ring keeps counting.
   */
  onDshReady(): void {
    this.generation += 1;
    const restarted = this.generation > 1;
    this.dshReady = true;
    if (restarted) {
      this.snapshots.clear();
      // Pending obligations belong to the dead generation: those rpcIds would
      // now return `not-pending`.
      this.pending.clear();
      this.ring.clearRetained();
      this.publishBridgeFrame({ type: 'resync-required', reason: 'dsh-restarted' });
    }
    this.publishBridgeFrame({ type: 'dsh-ready', generation: this.generation });
  }

  onDshDisconnected(reason: string): void {
    this.dshReady = false;
    this.publishBridgeFrame({ type: 'dsh-disconnected', error: reason });
  }

  isReady(): boolean {
    return this.dshReady;
  }

  // ── subscriptions ─────────────────────────────────────────────────────────

  /**
   * Attach a device at `after`.
   *
   * `after: 0` on a ring that has already evicted is a resync, not "send me
   * everything you have" — see FrameRing.readAfter. On resync the device gets
   * snapshots plus pending obligations so it has current state immediately, and
   * re-baselines the rest through the official dsh procedure.
   */
  attach(subscriber: Subscriber, after: number): AttachResult {
    if (!this.dshReady) return { ok: false, reason: 'not-ready' };

    const read = this.ring.readAfter(after);
    this.subscribers.add(subscriber);

    // Pending obligations are always replayed, resync or not: a phone that
    // backgrounded mid-approval must be able to answer.
    const pending = this.pending.all().map<BridgeEnvelope>((entry) => ({
      v: 1,
      // Replay reuses the bseq slot the frame was first published under. It is
      // a re-delivery, not a new event, so it must not advance the cursor.
      bseq: this.ring.lastBseq(),
      kind: 'mux',
      rpcId: entry.rpcId,
      frame: entry.frame,
    }));

    if (read.ok) {
      return { ok: true, backlog: read.frames, snapshots: [], pending, lastBseq: read.lastBseq, resynced: false };
    }

    const snapshots = this.snapshots.all().map<BridgeEnvelope>((snapshot) =>
      snapshot.kind === 'mux'
        ? { v: 1, bseq: this.ring.lastBseq(), kind: 'mux', frame: snapshot.frame }
        : { v: 1, bseq: this.ring.lastBseq(), kind: 'host', frame: snapshot.frame },
    );
    // The resync frame is delivered inline in the attach result rather than
    // published to the log: it is addressed to this device only.
    return { ok: true, backlog: [], snapshots, pending, lastBseq: read.lastBseq, resynced: true };
  }

  detach(subscriber: Subscriber): void {
    this.subscribers.delete(subscriber);
  }

  /** Drop a revoked device's streams immediately, telling it why first. */
  disconnectDevice(deviceId: string, frame: BridgeFrame = { type: 'device-revoked' }): number {
    let dropped = 0;
    for (const subscriber of [...this.subscribers]) {
      if (subscriber.deviceId !== deviceId) continue;
      this.safeDeliver(subscriber, { v: 1, bseq: this.ring.lastBseq(), kind: 'bridge', frame });
      this.subscribers.delete(subscriber);
      dropped += 1;
    }
    return dropped;
  }

  /** Deliver to one device only (token expiry warnings, per-device notices). */
  notifyDevice(deviceId: string, frame: BridgeFrame): number {
    let sent = 0;
    for (const subscriber of this.subscribers) {
      if (subscriber.deviceId !== deviceId) continue;
      this.safeDeliver(subscriber, { v: 1, bseq: this.ring.lastBseq(), kind: 'bridge', frame });
      sent += 1;
    }
    return sent;
  }

  // ── answerable frames ─────────────────────────────────────────────────────

  /** True when `rpcId` is a live obligation this bridge delivered. */
  isPending(rpcId: RpcId): boolean {
    return this.pending.has(rpcId);
  }

  /**
   * The open obligation for `rpcId`, including the frame that raised it.
   *
   * `POST /m1/respond` needs the frame, not just its existence: the upstream answer
   * payload carries correlation ids (`sessionId`, and `approvalId` for approvals)
   * that dsh re-checks against its own pending entry. Taking them from here rather
   * than from the request body means a phone supplies only the decision, so it
   * cannot answer one approval while naming another's ids.
   */
  getPending(rpcId: RpcId): PendingAnswerable | undefined {
    return this.pending.get(rpcId);
  }

  /** Clear an obligation after our own successful `respond`. */
  consumePending(rpcId: RpcId): boolean {
    return this.pending.consume(rpcId);
  }

  pendingCount(): number {
    return this.pending.size();
  }

  stats(): { subscribers: number; retainedFrames: number; retainedBytes: number; lastBseq: number; earliestBseq: number; snapshots: number; pending: number } {
    return {
      subscribers: this.subscribers.size,
      retainedFrames: this.ring.size(),
      retainedBytes: this.ring.byteSize(),
      lastBseq: this.ring.lastBseq(),
      earliestBseq: this.ring.earliestBseq(),
      snapshots: this.snapshots.size(),
      pending: this.pending.size(),
    };
  }

  private fanout(envelope: BridgeEnvelope): void {
    for (const subscriber of this.subscribers) this.safeDeliver(subscriber, envelope);
  }

  private safeDeliver(subscriber: Subscriber, envelope: BridgeEnvelope): void {
    try {
      subscriber.deliver(envelope);
    } catch (error) {
      // One wedged socket must not stop fanout to the others.
      console.error(`[bridge:hub] delivery to ${subscriber.deviceId} threw:`, error);
    }
  }
}

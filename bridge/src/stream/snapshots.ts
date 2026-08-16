/**
 * [OUR DESIGN] Snapshot retention and pending answerable-frame tracking.
 *
 * Two problems the ring alone cannot solve:
 *
 * 1. A device that must resync (or attaches fresh) needs current state without
 *    replaying the whole log. Snapshot frames are idempotent and
 *    replace-never-merge by upstream design, so keeping only the newest of each
 *    is lossless for those types.
 * 2. An answerable frame is a *pending obligation*, not history. dsh replays
 *    pending approvals on subscribe with the same `rpcId`; a phone that
 *    backgrounded mid-approval must see it again on attach or the session
 *    silently stalls waiting for an answer nobody will give.
 */

import { SNAPSHOT_FRAME_TYPES, type HostFrame, type MuxFrame, type RpcId } from '../dsh/types.ts';

/** A retained snapshot, tagged so it can be re-emitted with the right `kind`. */
export type Snapshot =
  | { kind: 'mux'; frame: MuxFrame }
  | { kind: 'host'; frame: HostFrame };

/** An answerable frame awaiting an answer, keyed by the `rpcId` dsh minted. */
export interface PendingAnswerable {
  readonly rpcId: RpcId;
  readonly sessionId: string;
  readonly frame: Extract<MuxFrame, { type: 'approval/requested' | 'question/requested' }>;
  readonly receivedAt: number;
}

/**
 * Separator for composite snapshot keys.
 *
 * NUL, because it is the one byte that cannot appear in any id upstream sends, so
 * `(a, bc)` and `(ab, c)` can never collide into the same key. Written as an escape
 * rather than as a literal NUL in the template: a raw NUL byte makes the whole file
 * read as binary, which means `grep` silently skips it and every editor renders the
 * separator as a space. The emitted key bytes are identical either way.
 */
const SEP = '\u0000';

/**
 * Composite key for a snapshot.
 *
 * `session/projection` is per `(sessionId, key)` — one session has many
 * projections and they must not evict each other. `host/workspace-changed` is
 * per workspace. Everything else is per `(type, sessionId)`.
 */
function snapshotKey(frame: MuxFrame | HostFrame): string | undefined {
  if (!SNAPSHOT_FRAME_TYPES.has(frame.type)) return undefined;
  switch (frame.type) {
    case 'session/projection':
      return `session/projection${SEP}${frame.sessionId}${SEP}${frame.key}`;
    case 'session/queue':
    case 'session/jobs':
      return `${frame.type}${SEP}${frame.sessionId}`;
    case 'host/workspace-changed': {
      // `workspace` is wide by contract. Fall back to a single slot rather than
      // guessing at an id we cannot validate.
      const workspace = frame.workspace;
      const id =
        typeof workspace === 'object' && workspace !== null && 'id' in workspace
          ? String((workspace as { id: unknown }).id)
          : '';
      return `host/workspace-changed${SEP}${id}`;
    }
    default:
      return undefined;
  }
}

export class SnapshotStore {
  /** key → newest snapshot for that key. */
  private readonly snapshots = new Map<string, Snapshot>();
  /**
   * Per-projection high-water seq. `session/projection` is higher-seq-wins, so
   * an out-of-order redelivery must not clobber newer state.
   */
  private readonly projectionSeq = new Map<string, number>();

  /** Returns true when the frame was retained as a snapshot. */
  record(kind: 'mux' | 'host', frame: MuxFrame | HostFrame): boolean {
    const key = snapshotKey(frame);
    if (key === undefined) return false;

    if (frame.type === 'session/projection') {
      const known = this.projectionSeq.get(key);
      if (known !== undefined && frame.seq <= known) return false;
      this.projectionSeq.set(key, frame.seq);
    }

    this.snapshots.set(key, { kind, frame } as Snapshot);
    return true;
  }

  /** All retained snapshots, in insertion order. */
  all(): readonly Snapshot[] {
    return [...this.snapshots.values()];
  }

  /** Drop everything for a session that upstream says is gone. */
  forgetSession(sessionId: string): void {
    for (const [key, snapshot] of this.snapshots) {
      const frame = snapshot.frame;
      if ('sessionId' in frame && frame.sessionId === sessionId) {
        this.snapshots.delete(key);
        this.projectionSeq.delete(key);
      }
    }
  }

  /**
   * Drop everything. Called when dsh restarts: retained snapshots describe a
   * dead generation and re-baselining supersedes them.
   */
  clear(): void {
    this.snapshots.clear();
    this.projectionSeq.clear();
  }

  size(): number {
    return this.snapshots.size;
  }
}

/**
 * Tracks which answerable frames are still open.
 *
 * The bridge uses this for two independent checks:
 * - replay on device attach, so a backgrounded phone can still answer;
 * - authorization on `POST /m1/respond`, so a phone cannot answer an `rpcId`
 *   it never received (CORE_ARCHITECTURE.md §7).
 */
export class PendingAnswerables {
  private readonly pending = new Map<RpcId, PendingAnswerable>();
  /** approvalId → rpcId, so `approval/resolved` can clear the obligation. */
  private readonly byApprovalId = new Map<string, RpcId>();

  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  record(rpcId: RpcId, frame: MuxFrame): boolean {
    if (frame.type !== 'approval/requested' && frame.type !== 'question/requested') return false;
    this.pending.set(rpcId, {
      rpcId,
      sessionId: frame.sessionId,
      frame,
      receivedAt: this.now(),
    });
    if (frame.type === 'approval/requested') this.byApprovalId.set(frame.approvalId, rpcId);
    return true;
  }

  /**
   * Clear an obligation that upstream resolved without us — another client
   * answered, the tool call was cancelled, or the session died.
   */
  resolveFromFrame(frame: MuxFrame): void {
    if (frame.type === 'approval/resolved') {
      const rpcId = this.byApprovalId.get(frame.approvalId);
      if (rpcId !== undefined) {
        this.pending.delete(rpcId);
        this.byApprovalId.delete(frame.approvalId);
      }
      return;
    }
    if (frame.type === 'question/resolved') {
      this.pending.delete(frame.questionRpcId);
    }
  }

  /** True when this `rpcId` is a live obligation. */
  has(rpcId: RpcId): boolean {
    return this.pending.has(rpcId);
  }

  get(rpcId: RpcId): PendingAnswerable | undefined {
    return this.pending.get(rpcId);
  }

  /**
   * Mark answered locally. We clear on our own successful `respond` rather than
   * waiting for the resolved frame, so a second phone cannot be told the frame
   * is still open during the round trip.
   */
  consume(rpcId: RpcId): boolean {
    const entry = this.pending.get(rpcId);
    if (!entry) return false;
    this.pending.delete(rpcId);
    if (entry.frame.type === 'approval/requested') this.byApprovalId.delete(entry.frame.approvalId);
    return true;
  }

  /** Everything still open, oldest first, for replay on attach. */
  all(): readonly PendingAnswerable[] {
    return [...this.pending.values()].sort((a, b) => a.receivedAt - b.receivedAt);
  }

  forgetSession(sessionId: string): void {
    for (const [rpcId, entry] of this.pending) {
      if (entry.sessionId !== sessionId) continue;
      this.pending.delete(rpcId);
      if (entry.frame.type === 'approval/requested') this.byApprovalId.delete(entry.frame.approvalId);
    }
  }

  /**
   * Drop everything. A pending approval belongs to a dsh generation: after a
   * restart the `rpcId` is dead and answering it would return `not-pending`.
   */
  clear(): void {
    this.pending.clear();
    this.byApprovalId.clear();
  }

  size(): number {
    return this.pending.size;
  }
}

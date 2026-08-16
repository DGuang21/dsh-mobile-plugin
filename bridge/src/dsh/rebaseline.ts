/**
 * The official dsh recovery procedure, section 5.5 of DSH_CORE_RESEARCH.md.
 *
 * There is no official resume. `since` on the mux stream is a reserved seat that
 * v1 ignores, so we never send it. Recovery is:
 *   1. Reopen the stream (owned by DshConnection).
 *   2. Take `session/subscribed { lastSeq }` per session as the watermark.
 *   3. Refetch history via `session.history`.
 *   4. Re-render pending answerable frames from the replay (same `rpcId`).
 *   5. Re-baseline snapshots: `session.list`, `workspace.list`, and the history
 *      tail `projections` block.
 *
 * Step 4 is not done here: the replay arrives on the reopened mux stream itself,
 * and the bridge's fanout re-sends those pending frames to devices on attach.
 *
 * Note `session.history` on a cold session may create the host-side agent and add
 * latency to the first open; there is no persistence-only read path. We therefore
 * refetch history only for sessions a device is actually watching.
 */

import type { DshApiClient } from './client.ts';
import { DshRpcError } from './errors.ts';

export interface RebaselineResult {
  /** `session.list` value, the authoritative summary set (including `blank`). */
  sessions: unknown;
  /** `workspace.list` value. */
  workspaces: unknown;
  /** Per-session history pages that were refetched. */
  histories: Map<string, unknown>;
  /** Watermarks taken from `session/subscribed`, echoed back for the caller. */
  watermarks: Map<string, number>;
  /** Methods that failed, so the caller can degrade rather than assume success. */
  failures: { method: string; code: string; message: string }[];
}

export interface RebaselineOptions {
  /** Sessions worth a history refetch — normally those devices are watching. */
  sessionIds?: Iterable<string>;
  /** Watermarks from the current generation's `session/subscribed` frames. */
  watermarks?: Map<string, number>;
  /** Cap on history messages per session. */
  maxMessages?: number;
  signal?: AbortSignal;
}

/**
 * Run the rebaseline. Individual failures are collected rather than thrown: a
 * workspace list failing should not deny the caller a session list it did get.
 */
export async function rebaseline(
  client: DshApiClient,
  options: RebaselineOptions = {},
): Promise<RebaselineResult> {
  const failures: RebaselineResult['failures'] = [];
  const record = async (method: string, payload: unknown): Promise<unknown> => {
    try {
      return await client.callOrThrow(method, payload, options.signal);
    } catch (error) {
      if (error instanceof DshRpcError) {
        failures.push({ method, code: error.code, message: error.message });
        return undefined;
      }
      // Carrier failures mean the generation is already gone; let the caller see it.
      throw error;
    }
  };

  // `cursor` on session.list is an unimplemented seat: v1 returns everything,
  // ordered updatedAt descending. We send `{}` rather than inventing paging.
  const sessions = await record('session.list', {});
  const workspaces = await record('workspace.list', {});

  const histories = new Map<string, unknown>();
  for (const sessionId of options.sessionIds ?? []) {
    const payload: Record<string, unknown> = { sessionId };
    if (options.maxMessages !== undefined) payload.maxMessages = options.maxMessages;
    const history = await record('session.history', payload);
    if (history !== undefined) histories.set(sessionId, history);
  }

  return {
    sessions,
    workspaces,
    histories,
    watermarks: options.watermarks ?? new Map(),
    failures,
  };
}

/**
 * Extract the `projections` block from a `session.history` value. Session titles
 * ride this generic key→value pair under higher-seq-wins; there is no title
 * frame. Returns an empty map when the page carries no block.
 */
export function projectionsFromHistory(history: unknown): Map<string, { value: unknown; seq: number }> {
  const out = new Map<string, { value: unknown; seq: number }>();
  if (typeof history !== 'object' || history === null) return out;
  const block = (history as { projections?: unknown }).projections;
  if (typeof block !== 'object' || block === null) return out;

  for (const [key, entry] of Object.entries(block as Record<string, unknown>)) {
    if (typeof entry !== 'object' || entry === null) continue;
    const seq = (entry as { seq?: unknown }).seq;
    out.set(key, {
      value: (entry as { value?: unknown }).value,
      seq: typeof seq === 'number' && Number.isInteger(seq) ? seq : 0,
    });
  }
  return out;
}

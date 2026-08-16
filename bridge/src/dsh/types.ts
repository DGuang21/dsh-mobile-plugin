/**
 * Verified `dsh` `/api` wire contract.
 *
 * Every type here was read out of an official DeepSeek Harness checkout on
 * 2026-08-15 (see docs/DSH_CORE_RESEARCH.md for file-level citations):
 *   - packages/host/apiproxy/src/api/rpc.ts          (envelopes, RpcError codes)
 *   - packages/host/apiproxy/src/api/rpc.schema.ts   (RpcReceipt)
 *   - packages/host/apiproxy/src/api/events.ts       (MuxFrame / HostFrame)
 *   - packages/host/apiproxy/src/api/events.schema.ts
 *   - packages/host/apiproxy/src/api/rpc-map.ts      (method registry)
 *   - packages/host/apiproxy/src/fetch/handler.ts    (route dispatch, status codes)
 *
 * NOTHING in this file is our design. Do not add bridge concepts here; our
 * own protocol lives in src/m1/types.ts.
 *
 * dsh is a developer preview with promised breaking changes. These types are
 * pinned to that checkout and must be re-verified per docs/CORE_ARCHITECTURE.md
 * section 11.
 */

/** Correlation id. The initiator mints it; a response echoes it verbatim. */
export type RpcId = string;

/** `POST /api/<method>` request body (full form). */
export interface ClientRequest {
  type: 'client-request';
  rpcId: RpcId;
  method: string;
  payload: unknown;
}

/** `POST /api/<method>` response body (full form). Always HTTP 200. */
export interface ServerResponse {
  type: 'server-response';
  rpcId: RpcId;
  result: RpcResult<unknown>;
}

/** Downlink frame envelope. `method` mirrors `payload.type`. */
export interface ServerRequest {
  type: 'server-request';
  rpcId: RpcId;
  method: string;
  payload: unknown;
}

/** `POST /api/respond` request body. `rpcId` is echoed from the server frame. */
export interface ClientResponse {
  type: 'client-response';
  rpcId: RpcId;
  result: RpcResult<unknown>;
}

/** Business success/failure. Methods never throw business errors. */
export type RpcResult<T> = { ok: true; value: T } | { ok: false; error: RpcError };

/**
 * `POST /api/respond` response body. A carrier receipt, NOT an RPC message.
 * A late or duplicate answer yields `not-pending`; a malformed body
 * `bad-response`. Both still arrive as HTTP 200.
 */
export type RpcReceipt =
  | { accepted: true }
  | { accepted: false; reason: 'not-pending' | 'bad-response' };

/**
 * Closed error-code union, verified from `RpcErrorDetailsMap`. `internal` is
 * the catch-all. `details` is always present (`internal` uses `{}`).
 */
export type RpcErrorCode =
  | 'bad-request'
  | 'cancelled'
  | 'session-not-found'
  | 'model-unavailable'
  | 'session-conflict'
  | 'invalid-time-zone'
  | 'workspace-attach-failed'
  | 'workspace-not-found'
  | 'workspace-invalid-path'
  | 'workspace-name-conflict'
  | 'workspace-move-invalid'
  | 'directory-unreadable'
  | 'directory-exists'
  | 'directory-create-failed'
  | 'directory-picker-unavailable'
  | 'agent-preset-read-only'
  | 'agent-preset-locked'
  | 'agent-preset-conflict'
  | 'agent-preset-not-found'
  | 'agent-preset-invalid'
  | 'agent-busy'
  | 'attachment-error'
  | 'queue-item-not-found'
  | 'steer-unavailable'
  | 'command-error'
  | 'unknown-command'
  | 'settings-rejected'
  | 'settings-not-exposed'
  | 'settings-conflict'
  | 'credential-rejected'
  | 'model-discovery-failed'
  | 'title-invalid'
  | 'fork-unavailable'
  | 'subagent-parent-unavailable'
  | 'subagent-not-found'
  | 'subagent-catalog-diagnostic'
  | 'subagent-not-resumable'
  | 'subagent-unauthorized'
  | 'subagent-delivery-unavailable'
  | 'internal';

export interface RpcError {
  code: RpcErrorCode;
  message: string;
  details: Record<string, unknown>;
}

/**
 * Strict envelope with a deliberately wide `data`. `data` is NOT deep-validated
 * at the carrier, so a client must tolerate unknown `type` and unknown shapes.
 */
export interface SessionEvent {
  type: string;
  seq: number;
  time: number;
  data: unknown;
  sourceEventSeqs?: number[];
  surfaceOp?: unknown;
  /** Marker letting older readers skip an unknown type. */
  ignorable?: true;
}

/** Host-computed, never-persisted render intent for `tool/call` / `tool/result`. */
export interface ToolEventView {
  for: 'call' | 'result';
  view: unknown;
}

/** A client may only ever *send* `allowed-once` or `rejected`. */
export type ApprovalOutcome = 'allowed-once' | 'rejected' | 'cancelled' | 'unavailable';

/** Sendable subset of {@link ApprovalOutcome}. */
export type SendableApprovalOutcome = 'allowed-once' | 'rejected';

export interface AskUserQuestionItem {
  id: string;
  question: string;
  header?: string;
  detail?: string;
  options?: { label: string; description?: string }[];
  multiSelect?: boolean;
  /** Tagged union upstream; unknown tags are rejected at the frame schema. */
  intent?: { kind: 'plan-review'; approve: string };
}

export interface QueuedInboxItem {
  id: string;
  placement: 'queued' | 'steering' | 'context';
  message: unknown;
}

/**
 * `MuxFrame` union. Only `approval/requested` and `question/requested` are
 * answerable, and that is decided statically by frame type.
 */
export type MuxFrame =
  | { type: 'session/event'; sessionId: string; event: SessionEvent; view?: ToolEventView }
  | { type: 'session/subscribed'; sessionId: string; lastSeq: number }
  | {
      type: 'approval/requested';
      sessionId: string;
      approvalId: string;
      toolName: string;
      callId?: string;
      reason?: string;
    }
  | { type: 'approval/resolved'; sessionId: string; approvalId: string; outcome: ApprovalOutcome }
  | { type: 'question/requested'; sessionId: string; questions: AskUserQuestionItem[] }
  | {
      type: 'question/resolved';
      sessionId: string;
      questionRpcId: RpcId;
      outcome: 'answered' | 'cancelled';
    }
  | { type: 'session/queue'; sessionId: string; items: QueuedInboxItem[] }
  | { type: 'session/jobs'; sessionId: string; jobs: unknown[] }
  | { type: 'session/projection'; sessionId: string; key: string; value: unknown; seq: number }
  | { type: 'stream/error'; error: RpcError };

/**
 * `HostFrame` union, verified from events.schema.ts. Note the `host/` prefix on
 * every member and the three frames docs/DSH_CORE_RESEARCH.md section 5.4 omits
 * (`host/workspace-order-changed`, `host/archived-sessions-changed`,
 * `host/remote-event`).
 */
export type HostFrame =
  | {
      type: 'host/session-added';
      sessionId: string;
      /** Always `true` on this frame: it fires at `session/created`. */
      blank: boolean;
      parentSessionId?: string;
      origin?: 'subagent';
      cwd?: string;
      agentPreset?: string;
    }
  | { type: 'host/session-removed'; sessionId: string }
  | { type: 'host/session-status'; sessionId: string; running: boolean }
  | { type: 'host/agent-error'; sessionId: string; message: string }
  | { type: 'host/workspace-changed'; workspace: unknown }
  | { type: 'host/workspace-removed'; workspaceId: string }
  | { type: 'host/workspace-order-changed'; workspaceIds: string[] }
  | { type: 'host/archived-sessions-changed'; archivedSessionIds: string[] }
  | { type: 'host/remote-event'; event: string; args: unknown[] }
  | { type: 'stream/error'; error: RpcError };

export type DshFrame = MuxFrame | HostFrame;

/** Frame types a client answers via `POST /api/respond`. */
export const ANSWERABLE_FRAME_TYPES: ReadonlySet<string> = new Set([
  'approval/requested',
  'question/requested',
]);

/**
 * Snapshot frames: idempotent, replace-never-merge. Retained per session so a
 * resuming device can be brought current without the full log.
 */
export const SNAPSHOT_FRAME_TYPES: ReadonlySet<string> = new Set([
  'session/queue',
  'session/jobs',
  'session/projection',
  'host/workspace-changed',
]);

/** Prompt content blocks. Narrower than durable core content, by design. */
export type PromptContentPart =
  | { type: 'text'; text: string }
  | { type: 'image'; mediaType: ImageMediaType; data: string; name?: string };

/** The only raster media types the v1 browser wire accepts. */
export const IMAGE_MEDIA_TYPES = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'] as const;
export type ImageMediaType = (typeof IMAGE_MEDIA_TYPES)[number];

/** `/api` physical paths. */
export const API_PATH = '/api';
export const MUX_EVENTS_PATH = '/api/events.mux';
export const HOST_EVENTS_PATH = '/api/events.host';
export const RESPOND_PATH = '/api/respond';

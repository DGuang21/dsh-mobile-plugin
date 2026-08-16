/**
 * Structural validation of the dsh wire, mirroring upstream's zod schemas.
 *
 * We deliberately do not add zod: the bridge validates only what upstream
 * validates at the carrier boundary, and upstream keeps `data`, `value`, and
 * `args` intentionally wide. Deep-validating them here would invent a contract
 * dsh does not promise and would reject frames a browser client accepts.
 *
 * Validation returns a result rather than throwing, because upstream's
 * documented posture for a bad frame is "report and skip" — one corrupt frame
 * must never kill a stream.
 */

import type {
  ClientResponse,
  HostFrame,
  MuxFrame,
  RpcError,
  RpcReceipt,
  ServerRequest,
  ServerResponse,
} from './types.ts';

export type Validated<T> = { ok: true; value: T } | { ok: false; reason: string };

function fail<T>(reason: string): Validated<T> {
  return { ok: false, reason };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isInt(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value);
}

/** Validate an `RpcError`: closed-code union upstream, `details` always present. */
function validateRpcError(value: unknown): Validated<RpcError> {
  if (!isRecord(value)) return fail('error is not an object');
  if (!isNonEmptyString(value.code)) return fail('error.code is not a non-empty string');
  if (typeof value.message !== 'string') return fail('error.message is not a string');
  // `details` is required upstream (`internal` uses an explicit `{}`), but we
  // tolerate absence rather than dropping an otherwise readable error: losing
  // the error entirely is strictly worse for the operator than a missing detail.
  const details = isRecord(value.details) ? value.details : {};
  return { ok: true, value: { code: value.code as RpcError['code'], message: value.message, details } };
}

/** Validate `result` in a `ServerResponse` / `ClientResponse`. */
function validateResult(value: unknown): Validated<ServerResponse['result']> {
  if (!isRecord(value)) return fail('result is not an object');
  if (value.ok === true) return { ok: true, value: { ok: true, value: value.value } };
  if (value.ok === false) {
    const error = validateRpcError(value.error);
    if (!error.ok) return fail(error.reason);
    return { ok: true, value: { ok: false, error: error.value } };
  }
  return fail('result.ok is not a boolean literal');
}

/** Validate a `POST /api/<method>` response body. */
export function validateServerResponse(value: unknown): Validated<ServerResponse> {
  if (!isRecord(value)) return fail('body is not an object');
  if (value.type !== 'server-response') return fail(`type is not "server-response": ${String(value.type)}`);
  if (!isNonEmptyString(value.rpcId)) return fail('rpcId is not a non-empty string');
  const result = validateResult(value.result);
  if (!result.ok) return fail(result.reason);
  return { ok: true, value: { type: 'server-response', rpcId: value.rpcId, result: result.value } };
}

/** Validate a downlink frame envelope. */
export function validateServerRequest(value: unknown): Validated<ServerRequest> {
  if (!isRecord(value)) return fail('frame is not an object');
  if (value.type !== 'server-request') return fail(`type is not "server-request": ${String(value.type)}`);
  if (!isNonEmptyString(value.rpcId)) return fail('rpcId is not a non-empty string');
  if (!isNonEmptyString(value.method)) return fail('method is not a non-empty string');
  return {
    ok: true,
    value: { type: 'server-request', rpcId: value.rpcId, method: value.method, payload: value.payload },
  };
}

/** Validate a `POST /api/respond` receipt. Carrier-layer, not an RPC message. */
export function validateRpcReceipt(value: unknown): Validated<RpcReceipt> {
  if (!isRecord(value)) return fail('receipt is not an object');
  if (value.accepted === true) return { ok: true, value: { accepted: true } };
  if (value.accepted === false) {
    if (value.reason === 'not-pending' || value.reason === 'bad-response') {
      return { ok: true, value: { accepted: false, reason: value.reason } };
    }
    return fail(`receipt.reason is not a known literal: ${String(value.reason)}`);
  }
  return fail('receipt.accepted is not a boolean literal');
}

/**
 * Validate a `MuxFrame`. Checks the discriminant and the fields our fanout,
 * policy, and resume layers actually read; wide slots (`event.data`,
 * `projection.value`, `jobs`) stay wide, as upstream leaves them.
 */
export function validateMuxFrame(value: unknown): Validated<MuxFrame> {
  if (!isRecord(value)) return fail('frame is not an object');
  const type = value.type;
  if (typeof type !== 'string') return fail('frame.type is not a string');

  // `stream/error` is the only mux frame with no sessionId.
  if (type === 'stream/error') {
    const error = validateRpcError(value.error);
    if (!error.ok) return fail(error.reason);
    return { ok: true, value: { type: 'stream/error', error: error.value } };
  }

  if (!isNonEmptyString(value.sessionId)) return fail(`${type}: sessionId is not a non-empty string`);
  const sessionId = value.sessionId;

  switch (type) {
    case 'session/event': {
      if (!isRecord(value.event)) return fail('session/event: event is not an object');
      const event = value.event;
      if (typeof event.type !== 'string') return fail('session/event: event.type is not a string');
      if (!isInt(event.seq) || event.seq < 0) return fail('session/event: event.seq is not a non-negative integer');
      if (typeof event.time !== 'number') return fail('session/event: event.time is not a number');
      return { ok: true, value: value as unknown as MuxFrame };
    }
    case 'session/subscribed':
      if (!isInt(value.lastSeq)) return fail('session/subscribed: lastSeq is not an integer');
      return { ok: true, value: { type, sessionId, lastSeq: value.lastSeq } };
    case 'approval/requested':
      if (!isNonEmptyString(value.approvalId)) return fail('approval/requested: approvalId missing');
      if (typeof value.toolName !== 'string') return fail('approval/requested: toolName is not a string');
      return { ok: true, value: value as unknown as MuxFrame };
    case 'approval/resolved': {
      if (!isNonEmptyString(value.approvalId)) return fail('approval/resolved: approvalId missing');
      const outcomes = ['allowed-once', 'rejected', 'cancelled', 'unavailable'];
      if (typeof value.outcome !== 'string' || !outcomes.includes(value.outcome)) {
        return fail(`approval/resolved: unknown outcome ${String(value.outcome)}`);
      }
      return { ok: true, value: value as unknown as MuxFrame };
    }
    case 'question/requested': {
      // Non-empty by wire contract: the user-questions service rejects empty
      // batches at ask(), so an empty array is host breakage, not a valid frame.
      if (!Array.isArray(value.questions) || value.questions.length === 0) {
        return fail('question/requested: questions must be a non-empty array');
      }
      for (const item of value.questions) {
        if (!isRecord(item) || typeof item.id !== 'string' || typeof item.question !== 'string') {
          return fail('question/requested: item is missing id or question');
        }
      }
      return { ok: true, value: value as unknown as MuxFrame };
    }
    case 'question/resolved':
      if (!isNonEmptyString(value.questionRpcId)) return fail('question/resolved: questionRpcId missing');
      if (value.outcome !== 'answered' && value.outcome !== 'cancelled') {
        return fail(`question/resolved: unknown outcome ${String(value.outcome)}`);
      }
      return { ok: true, value: value as unknown as MuxFrame };
    case 'session/queue': {
      if (!Array.isArray(value.items)) return fail('session/queue: items is not an array');
      const placements = ['queued', 'steering', 'context'];
      for (const item of value.items) {
        if (!isRecord(item) || typeof item.id !== 'string') return fail('session/queue: item.id missing');
        if (typeof item.placement !== 'string' || !placements.includes(item.placement)) {
          return fail(`session/queue: unknown placement ${String(item.placement)}`);
        }
      }
      return { ok: true, value: value as unknown as MuxFrame };
    }
    case 'session/jobs':
      if (!Array.isArray(value.jobs)) return fail('session/jobs: jobs is not an array');
      return { ok: true, value: { type, sessionId, jobs: value.jobs } };
    case 'session/projection':
      if (!isNonEmptyString(value.key)) return fail('session/projection: key is not a non-empty string');
      if (!isInt(value.seq) || value.seq < 0) return fail('session/projection: seq is not a non-negative integer');
      return { ok: true, value: { type, sessionId, key: value.key, value: value.value, seq: value.seq } };
    default:
      // An unknown frame type is a newer harness, not corruption. The caller
      // decides; we refuse to guess a shape we cannot read.
      return fail(`unknown mux frame type: ${type}`);
  }
}

/** Validate a `HostFrame`. Same posture as {@link validateMuxFrame}. */
export function validateHostFrame(value: unknown): Validated<HostFrame> {
  if (!isRecord(value)) return fail('frame is not an object');
  const type = value.type;
  if (typeof type !== 'string') return fail('frame.type is not a string');

  switch (type) {
    case 'stream/error': {
      const error = validateRpcError(value.error);
      if (!error.ok) return fail(error.reason);
      return { ok: true, value: { type: 'stream/error', error: error.value } };
    }
    case 'host/session-added':
      if (!isNonEmptyString(value.sessionId)) return fail('host/session-added: sessionId missing');
      if (typeof value.blank !== 'boolean') return fail('host/session-added: blank is not a boolean');
      return { ok: true, value: value as unknown as HostFrame };
    case 'host/session-removed':
      if (!isNonEmptyString(value.sessionId)) return fail('host/session-removed: sessionId missing');
      return { ok: true, value: { type, sessionId: value.sessionId } };
    case 'host/session-status':
      if (!isNonEmptyString(value.sessionId)) return fail('host/session-status: sessionId missing');
      if (typeof value.running !== 'boolean') return fail('host/session-status: running is not a boolean');
      return { ok: true, value: { type, sessionId: value.sessionId, running: value.running } };
    case 'host/agent-error':
      if (!isNonEmptyString(value.sessionId)) return fail('host/agent-error: sessionId missing');
      if (typeof value.message !== 'string') return fail('host/agent-error: message is not a string');
      return { ok: true, value: { type, sessionId: value.sessionId, message: value.message } };
    case 'host/workspace-changed':
      if (value.workspace === undefined) return fail('host/workspace-changed: workspace missing');
      return { ok: true, value: { type, workspace: value.workspace } };
    case 'host/workspace-removed':
      if (!isNonEmptyString(value.workspaceId)) return fail('host/workspace-removed: workspaceId missing');
      return { ok: true, value: { type, workspaceId: value.workspaceId } };
    case 'host/workspace-order-changed':
      if (!Array.isArray(value.workspaceIds)) return fail('host/workspace-order-changed: workspaceIds is not an array');
      return { ok: true, value: { type, workspaceIds: value.workspaceIds as string[] } };
    case 'host/archived-sessions-changed':
      if (!Array.isArray(value.archivedSessionIds)) {
        return fail('host/archived-sessions-changed: archivedSessionIds is not an array');
      }
      return { ok: true, value: { type, archivedSessionIds: value.archivedSessionIds as string[] } };
    case 'host/remote-event':
      if (!isNonEmptyString(value.event)) return fail('host/remote-event: event is not a non-empty string');
      if (!Array.isArray(value.args)) return fail('host/remote-event: args is not an array');
      return { ok: true, value: { type, event: value.event, args: value.args } };
    default:
      return fail(`unknown host frame type: ${type}`);
  }
}

/** Build a `ClientResponse` for `POST /api/respond`, echoing the frame's `rpcId`. */
export function clientResponse(rpcId: string, value: unknown): ClientResponse {
  return { type: 'client-response', rpcId, result: { ok: true, value } };
}

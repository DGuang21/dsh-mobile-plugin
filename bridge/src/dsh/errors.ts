/**
 * Typed errors for the dsh client.
 *
 * The split mirrors the verified upstream layering: HTTP status describes only
 * the carrier, business failures arrive as HTTP 200 with `result.ok === false`.
 * We therefore never collapse the two into a single "request failed".
 */

import type { RpcError, RpcErrorCode } from './types.ts';

/** Base for everything this client throws. */
export class DshClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * Carrier-layer failure: a non-2xx status, an unreachable socket, a timeout, or
 * a body that is not a valid envelope. Distinct from a business error.
 */
export interface DshTransportDetail {
  /** HTTP status when one was received. */
  status?: number;
  /** dsh method or path being called. */
  method?: string;
  /** Underlying cause, when this wraps a socket/abort failure. */
  cause?: unknown;
}

export class DshTransportError extends DshClientError {
  readonly detail: DshTransportDetail;

  constructor(message: string, detail: DshTransportDetail = {}) {
    super(message);
    this.detail = detail;
  }

  /** True when retrying the same call could plausibly succeed. */
  get retryable(): boolean {
    const status = this.detail.status;
    if (status === undefined) return true; // socket-level: reachability may return
    if (status === 415 || status === 400 || status === 404) return false; // our bug, not transient
    return status >= 500 || status === 426 || status === 408 || status === 429;
  }
}

/** The request timed out or was aborted by the caller. */
export class DshTimeoutError extends DshTransportError {
  constructor(method: string, timeoutMs: number) {
    super(`dsh request timed out after ${String(timeoutMs)}ms: ${method}`, { method });
  }
}

/**
 * dsh returned a well-formed response for a different `rpcId` than we sent.
 * Upstream's own client throws here, and so do we: a mismatched correlation id
 * means the response cannot be trusted to belong to this call.
 */
export class DshRpcIdMismatchError extends DshClientError {
  readonly method: string;
  readonly sent: string;
  readonly received: string;

  constructor(method: string, sent: string, received: string) {
    super(`rpcId mismatch for ${method}: sent ${sent}, got ${received}`);
    this.method = method;
    this.sent = sent;
    this.received = received;
  }
}

/**
 * Business failure: HTTP 200 with `result.ok === false`. Carries the upstream
 * closed error code and its `details` object verbatim.
 */
export class DshRpcError extends DshClientError {
  readonly method: string;
  readonly code: RpcErrorCode;
  readonly details: Record<string, unknown>;

  constructor(method: string, error: RpcError) {
    super(`${method} failed: ${error.code}: ${error.message}`);
    this.method = method;
    this.code = error.code;
    this.details = error.details;
  }

  /** The raw upstream error, for forwarding across our own protocol. */
  toRpcError(): RpcError {
    return { code: this.code, message: this.message, details: this.details };
  }
}

/** The bridge is not currently connected to dsh (readiness handshake incomplete). */
export class DshUnavailableError extends DshClientError {
  readonly reason: string;

  constructor(reason: string) {
    super(`dsh unavailable: ${reason}`);
    this.reason = reason;
  }
}

/**
 * Fold any thrown value into the upstream `RpcError` shape so our own protocol
 * can carry it. Mirrors upstream `transportError`, which uses `internal` as the
 * catch-all with an explicit empty `details`.
 */
export function toRpcError(error: unknown): RpcError {
  if (error instanceof DshRpcError) return error.toRpcError();
  return {
    code: 'internal',
    message: error instanceof Error ? error.message : String(error),
    details: {},
  };
}

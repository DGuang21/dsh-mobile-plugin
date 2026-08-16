/**
 * Unary `/api` client: `POST /api/<method>`.
 *
 * Verified behavior this implements (docs/DSH_CORE_RESEARCH.md section 2.1):
 *   - `content-type: application/json` is mandatory; anything else is 415
 *     before dispatch.
 *   - Body is the `ClientRequest` full form; `message.method` must equal the
 *     path method.
 *   - Success AND business failure both return HTTP 200 with a
 *     `ServerResponse`. HTTP status describes only the carrier.
 *   - The echoed `rpcId` must match what we sent.
 *   - `POST /api/respond` answers with an `RpcReceipt`, not an RPC message.
 *
 * We send `Host: 127.0.0.1:<port>` so the upstream browser-trust fence passes on
 * loopback with no `trustedHosts` configuration required from the user. The
 * fence is a reachability policy, not authentication — passing it is not a
 * security claim, and the bridge does its own authorization in policy/.
 */

import { anySignal } from '../runtime.ts';
import { DshRpcError, DshRpcIdMismatchError, DshTimeoutError, DshTransportError } from './errors.ts';
import { validateRpcReceipt, validateServerResponse } from './validate.ts';
import type { ClientRequest, ClientResponse, RpcReceipt, RpcResult } from './types.ts';
import { RESPOND_PATH } from './types.ts';

/** Minimal fetch surface, injectable so tests need no live dsh. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface DshApiClientOptions {
  /** dsh web origin. Must be loopback: `/api` reachability is RCE-equivalent. */
  baseUrl: string;
  /** Per-request timeout. Upstream's own client applies a default too. */
  timeoutMs?: number;
  fetchImpl?: FetchLike;
  /** Mints correlation ids; injectable for deterministic tests. */
  rpcIdFactory?: () => string;
}

const DEFAULT_TIMEOUT_MS = 30_000;

export class DshApiClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: FetchLike;
  private readonly mintRpcId: () => string;
  /** Authority sent as `Host`, derived from baseUrl so the fence sees loopback. */
  readonly authority: string;

  constructor(options: DshApiClientOptions) {
    const url = new URL(options.baseUrl);
    this.baseUrl = url.origin;
    this.authority = url.host;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? ((input, init) => fetch(input, init));
    this.mintRpcId = options.rpcIdFactory ?? (() => crypto.randomUUID());
  }

  /**
   * Invoke a unary method and return the business result without throwing on a
   * business error. Callers that want an exception use {@link callOrThrow}.
   *
   * Throws only on carrier failures: unreachable socket, timeout, non-2xx,
   * unreadable envelope, or an `rpcId` mismatch.
   */
  async call(method: string, payload: unknown, signal?: AbortSignal): Promise<RpcResult<unknown>> {
    const rpcId = this.mintRpcId();
    const message: ClientRequest = { type: 'client-request', rpcId, method, payload };
    const body = await this.postJson(`/api/${method}`, message, method, signal);

    const envelope = validateServerResponse(body);
    if (!envelope.ok) {
      throw new DshTransportError(`unreadable server-response for ${method}: ${envelope.reason}`, { method });
    }
    // Correlation check before trusting anything in the body. Upstream's client
    // throws here too: a mismatched id means this response may belong to
    // another call, so its result cannot be attributed to ours.
    if (envelope.value.rpcId !== rpcId) {
      throw new DshRpcIdMismatchError(method, rpcId, envelope.value.rpcId);
    }
    return envelope.value.result;
  }

  /** {@link call}, folding a business error into a thrown {@link DshRpcError}. */
  async callOrThrow(method: string, payload: unknown, signal?: AbortSignal): Promise<unknown> {
    const result = await this.call(method, payload, signal);
    if (!result.ok) throw new DshRpcError(method, result.error);
    return result.value;
  }

  /**
   * Answer a server-initiated request. The `rpcId` is echoed from the frame,
   * never minted, and the response is a carrier receipt.
   *
   * `{accepted: false, reason: 'not-pending'}` is a normal outcome for a late or
   * duplicate answer, not an error, so it is returned rather than thrown.
   */
  async respond(rpcId: string, value: unknown, signal?: AbortSignal): Promise<RpcReceipt> {
    const message: ClientResponse = { type: 'client-response', rpcId, result: { ok: true, value } };
    const body = await this.postJson(RESPOND_PATH, message, 'respond', signal);
    const receipt = validateRpcReceipt(body);
    if (!receipt.ok) {
      throw new DshTransportError(`unreadable respond receipt: ${receipt.reason}`, { method: 'respond' });
    }
    return receipt.value;
  }

  /** Readiness probe. Mirrors the official client's handshake requirement. */
  async describeHost(signal?: AbortSignal): Promise<unknown> {
    return this.callOrThrow('host.describe', {}, signal);
  }

  private async postJson(path: string, body: unknown, method: string, signal?: AbortSignal): Promise<unknown> {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    const requestSignal = anySignal([timeout, signal]) ?? timeout;

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          // Mandatory: any other media type is a 415 before dispatch.
          'content-type': 'application/json',
          // Passes the upstream trust fence on loopback without user config.
          host: this.authority,
        },
        body: JSON.stringify(body),
        signal: requestSignal,
      });
    } catch (error) {
      if (timeout.aborted) throw new DshTimeoutError(method, this.timeoutMs);
      throw new DshTransportError(`dsh unreachable for ${method}: ${String(error)}`, { method, cause: error });
    }

    if (!response.ok) {
      // 415/400/404 here mean we built a bad request, not that dsh is unwell.
      throw new DshTransportError(`transport failure for ${path}: HTTP ${String(response.status)}`, {
        status: response.status,
        method,
      });
    }

    try {
      return await response.json();
    } catch (error) {
      throw new DshTransportError(`response body is not JSON for ${method}`, { method, cause: error });
    }
  }
}

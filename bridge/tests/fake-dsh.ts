/**
 * Fake dsh `/api` carrier for tests.
 *
 * Reproduces the verified upstream carrier rules so the client is tested against
 * the real contract rather than a convenient one:
 *   - 415 unless `content-type` is exactly `application/json`
 *   - 400 when the body is not JSON
 *   - 404 for an unknown method
 *   - 200 + `ServerResponse` for both success and business failure
 *   - `bad-request` when `message.method` disagrees with the path
 *   - `/api/respond` answers an `RpcReceipt`, never an RPC message
 */

import type { RpcError, RpcReceipt } from '../src/dsh/types.ts';

export type MethodHandler = (payload: unknown) => unknown | Promise<unknown>;

export interface FakeDshOptions {
  /** Methods that exist. Anything else 404s, as the real route dispatch does. */
  methods?: Record<string, MethodHandler>;
  /** Methods that return a business error (HTTP 200, `result.ok === false`). */
  errors?: Record<string, RpcError>;
  /** Force the echoed rpcId, to exercise the mismatch guard. */
  forceRpcId?: string;
  respondReceipt?: RpcReceipt;
}

export interface RecordedRequest {
  path: string;
  method: string | undefined;
  contentType: string | undefined;
  host: string | undefined;
  body: unknown;
}

export class FakeDsh {
  readonly requests: RecordedRequest[] = [];
  private readonly methods: Record<string, MethodHandler>;
  private readonly errors: Record<string, RpcError>;

  constructor(private readonly options: FakeDshOptions = {}) {
    this.methods = options.methods ?? {};
    this.errors = options.errors ?? {};
  }

  /** A `fetch`-shaped function to hand to DshApiClient. */
  readonly fetch = async (input: string, init: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const path = url.pathname;
    const headers = new Headers(init.headers as HeadersInit);
    const contentType = headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();

    if (contentType !== 'application/json') {
      return new Response('content type must be application/json', { status: 415 });
    }

    let body: unknown;
    try {
      body = JSON.parse(String(init.body));
    } catch {
      return new Response('body is not JSON', { status: 400 });
    }

    const envelope = body as { rpcId?: string; method?: string; payload?: unknown };
    this.requests.push({
      path,
      method: envelope.method,
      contentType,
      host: headers.get('host') ?? undefined,
      body,
    });

    const rpcId = this.options.forceRpcId ?? envelope.rpcId ?? 'missing';

    if (path === '/api/respond') {
      return Response.json(this.options.respondReceipt ?? { accepted: true });
    }

    const wireMethod = path.slice('/api/'.length);
    if (!Object.hasOwn(this.methods, wireMethod) && !Object.hasOwn(this.errors, wireMethod)) {
      return new Response('not found', { status: 404 });
    }
    if (envelope.method !== wireMethod) {
      return Response.json({
        type: 'server-response',
        rpcId,
        result: {
          ok: false,
          error: {
            code: 'bad-request',
            message: `method "${String(envelope.method)}" does not match path "${wireMethod}"`,
            details: { issues: [] },
          },
        },
      });
    }

    const businessError = this.errors[wireMethod];
    if (businessError !== undefined) {
      return Response.json({ type: 'server-response', rpcId, result: { ok: false, error: businessError } });
    }

    const handler = this.methods[wireMethod];
    const value = await handler?.(envelope.payload);
    return Response.json({ type: 'server-response', rpcId, result: { ok: true, value } });
  };
}

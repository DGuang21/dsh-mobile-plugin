/**
 * [OUR DESIGN] Request plumbing for the `m1` server.
 *
 * Node's `http` module, no framework. Adding Express to a tree that also holds an
 * Expo app buys nothing here: we serve six routes, one of which is a WebSocket
 * upgrade that a framework would only get in the way of.
 *
 * Security-relevant behavior in this file:
 * - Body reads are hard-capped and the cap is enforced *while streaming*, not
 *   after buffering, so an oversized body cannot allocate before it is refused.
 * - `content-type` must be JSON. Mirrors dsh's own 415, and blocks
 *   `<form>`-based CSRF, which cannot set that header cross-origin.
 * - No CORS headers are ever sent. A browser must not be able to drive this API.
 * - Unknown routes get a JSON 404 with no detail about what does exist.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { BridgeError, BridgeErrorCode } from '../../../src/m1/types.ts';
import { BRIDGE_ERROR_STATUS } from '../m1/wire.ts';

/** Hard ceiling on any `m1` request body. Policy applies its own tighter caps. */
export const MAX_BODY_BYTES = 8 * 1024 * 1024;

export type BodyReadResult =
  | { ok: true; value: unknown }
  | { ok: false; error: BridgeError };

export function bridgeError(code: BridgeErrorCode, message: string, extra: Partial<BridgeError> = {}): BridgeError {
  return { code, message, ...extra };
}

/** Serialize a failure with the status this code maps to. */
export function sendError(response: ServerResponse, error: BridgeError): void {
  sendJson(response, BRIDGE_ERROR_STATUS[error.code] ?? 500, { ok: false, error });
}

export function sendOk(response: ServerResponse, value: unknown): void {
  sendJson(response, 200, { ok: true, value });
}

export function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(payload.byteLength),
    // This is a private API for a paired phone. Nothing here should be cached,
    // sniffed, or framed.
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(payload);
}

/**
 * Read and parse a JSON body.
 *
 * Rejects a wrong `content-type` before reading a single byte, and aborts mid-read
 * once the cap is passed rather than buffering the whole thing first.
 *
 * Uses stream events rather than `for await`: @types/node 26 declares the async
 * iterator through `NodeJS.AsyncIterator`, which this repo's TypeScript 5.3
 * cannot express. Events are also what makes the mid-read abort precise.
 */
export function readJsonBody(request: IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<BodyReadResult> {
  const contentType = request.headers['content-type'];
  if (typeof contentType !== 'string' || !contentType.toLowerCase().includes('application/json')) {
    return Promise.resolve({ ok: false, error: bridgeError('bad-request', 'content-type must be application/json') });
  }

  // Trust the declared length as an early reject only; the streaming check below
  // is what actually enforces the cap, since content-length can lie.
  const declared = Number(request.headers['content-length'] ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) {
    return Promise.resolve({ ok: false, error: bridgeError('payload-too-large', `body exceeds ${maxBytes} bytes`) });
  }

  return new Promise<BodyReadResult>((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const settle = (result: BodyReadResult): void => {
      if (settled) return;
      settled = true;
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.removeListener('error', onError);
      resolve(result);
    };

    function onData(chunk: Buffer): void {
      total += chunk.byteLength;
      if (total > maxBytes) {
        // Destroy rather than drain: we have already decided to refuse, and
        // draining would let a client hold a slot open for as long as it likes.
        request.destroy();
        settle({ ok: false, error: bridgeError('payload-too-large', `body exceeds ${maxBytes} bytes`) });
        return;
      }
      chunks.push(chunk);
    }

    function onEnd(): void {
      if (total === 0) {
        settle({ ok: false, error: bridgeError('bad-request', 'body is empty') });
        return;
      }
      try {
        settle({ ok: true, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
      } catch {
        settle({ ok: false, error: bridgeError('bad-request', 'body is not valid JSON') });
      }
    }

    function onError(error: Error): void {
      settle({ ok: false, error: bridgeError('bad-request', `body read failed: ${error.message}`) });
    }

    request.on('data', onData);
    request.on('end', onEnd);
    request.on('error', onError);
  });
}

/** A record with unknown values, so a handler can probe fields without casts. */
export function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

export function requireString(record: Record<string, unknown>, key: string, maxLength = 4096): string | undefined {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) return undefined;
  return value;
}

/**
 * Parse the request path, discarding the query string.
 *
 * A missing or non-absolute target is treated as no path at all rather than being
 * normalized, so nothing can smuggle a route through a malformed request line.
 */
export function parsePath(request: IncomingMessage): { path: string; query: URLSearchParams } {
  const target = request.url ?? '/';
  const queryStart = target.indexOf('?');
  const path = queryStart === -1 ? target : target.slice(0, queryStart);
  const query = new URLSearchParams(queryStart === -1 ? '' : target.slice(queryStart + 1));
  return { path, query };
}

/**
 * Peer address of a request, for audit logging.
 *
 * Deliberately does NOT consult `x-forwarded-for`: nothing is meant to proxy this
 * server, so honoring that header would only let a client forge its own address
 * in our audit log.
 */
export function peerAddress(request: IncomingMessage): string {
  return request.socket.remoteAddress ?? 'unknown';
}

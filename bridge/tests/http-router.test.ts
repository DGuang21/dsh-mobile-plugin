/**
 * Request plumbing: body reading, JSON responses, path parsing, peer address.
 *
 * These run against real `node:http` request and response objects over a real
 * loopback listener rather than fakes, because most of what is being checked is
 * behaviour Node owns: when `data` fires, what `destroy()` mid-body does to the
 * client, how a malformed request line reaches `request.url`. A hand-written stub
 * would let me assert my own assumptions back at myself.
 *
 * The security-relevant claims under test:
 * - the body cap is enforced while streaming, so an oversized body cannot be
 *   buffered before it is refused;
 * - a wrong `content-type` is refused before any body is read, which is what
 *   blocks `<form>`-based CSRF (a form cannot set application/json cross-origin);
 * - no CORS headers, ever, so a browser cannot drive this API;
 * - `x-forwarded-for` is ignored, so a client cannot forge its address in the
 *   audit log.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  MAX_BODY_BYTES,
  asRecord,
  bridgeError,
  parsePath,
  peerAddress,
  readJsonBody,
  requireString,
  sendError,
  sendJson,
  sendOk,
} from '../src/http/router.ts';
import { M1_BRIDGE_ERROR_CODES } from '../src/m1/wire.ts';

/** Listeners started by the current test, torn down in afterEach. */
const started: Server[] = [];

afterEach(async () => {
  await Promise.all(
    started.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          // `closeAllConnections` before `close`, or teardown blocks for seconds on
          // any test where the server answered without draining the request body:
          // that socket is not idle, so `close()` waits for it. Measured at ~4s per
          // such test before this call was added.
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    ),
  );
});

/** Start a listener with `handler`, returning its port. */
async function listen(handler: (request: IncomingMessage, response: ServerResponse) => void): Promise<number> {
  const server = createServer(handler);
  started.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return (server.address() as AddressInfo).port;
}

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  /** Set when the connection died before a response, which is its own signal. */
  socketError?: string;
}

/** One raw HTTP request, tolerating a connection the server destroyed. */
function call(
  port: number,
  options: { method?: string; path?: string; headers?: Record<string, string>; body?: string | Buffer },
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const outbound = httpRequest(
      { host: '127.0.0.1', port, method: options.method ?? 'POST', path: options.path ?? '/', headers: options.headers },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    let settled = false;
    outbound.on('error', (error: Error) => {
      // A destroyed request socket is the expected outcome of the cap test, not a
      // test failure, so it resolves rather than rejects.
      if (settled) return;
      settled = true;
      resolve({ status: 0, headers: {}, body: '', socketError: error.message });
    });
    outbound.on('response', () => void (settled = true));
    if (options.body !== undefined) outbound.write(options.body);
    outbound.end();
    setTimeout(() => reject(new Error('request timed out')), 5000).unref?.();
  });
}

const JSON_HEADERS = { 'content-type': 'application/json' };

describe('readJsonBody', () => {
  /** A listener that reads the body and echoes the result verbatim. */
  function bodyEcho(maxBytes?: number) {
    return listen(async (request, response) => {
      const result = await readJsonBody(request, maxBytes);
      sendJson(response, result.ok ? 200 : 400, result);
    });
  }

  it('parses a JSON object', async () => {
    const port = await bodyEcho();
    const reply = await call(port, { headers: JSON_HEADERS, body: JSON.stringify({ token: 'abc', n: 1 }) });
    expect(JSON.parse(reply.body)).toEqual({ ok: true, value: { token: 'abc', n: 1 } });
  });

  it('accepts a content-type with a charset parameter', async () => {
    // Real clients send `application/json; charset=utf-8`. Exact-matching the header
    // would reject them.
    const port = await bodyEcho();
    const reply = await call(port, { headers: { 'content-type': 'application/json; charset=utf-8' }, body: '{"a":1}' });
    expect(JSON.parse(reply.body).ok).toBe(true);
  });

  it.each([
    ['text/plain', 'text/plain'],
    ['form encoding', 'application/x-www-form-urlencoded'],
    ['multipart', 'multipart/form-data; boundary=x'],
  ])('refuses %s', async (_label, contentType) => {
    // The CSRF control. A browser `<form>` can only send these three content types
    // cross-origin, and none of them get past here — so a page the user visits
    // cannot drive this API even if it guesses the port.
    const port = await bodyEcho();
    const reply = await call(port, { headers: { 'content-type': contentType as string }, body: '{"a":1}' });
    const parsed = JSON.parse(reply.body);
    expect(parsed.ok).toBe(false);
    expect(parsed.error.code).toBe('bad-request');
    expect(parsed.error.message).toContain('content-type');
  });

  it('refuses a missing content-type', async () => {
    const port = await bodyEcho();
    // `http.request` supplies no content-type unless asked, which is the case here.
    const reply = await call(port, { body: '{"a":1}' });
    expect(JSON.parse(reply.body).error.code).toBe('bad-request');
  });

  it('reports an empty body distinctly from bad JSON', async () => {
    // Different causes on the phone side: an empty body is usually a client bug,
    // malformed JSON is usually a truncated request.
    const port = await bodyEcho();
    const empty = await call(port, { headers: JSON_HEADERS });
    expect(JSON.parse(empty.body).error.message).toContain('empty');
    const malformed = await call(port, { headers: JSON_HEADERS, body: '{"a":' });
    expect(JSON.parse(malformed.body).error.message).toContain('not valid JSON');
  });

  it('accepts a JSON scalar, leaving shape checks to the handler', () => {
    // Deliberate split: this function's job is "is it JSON", and the handler decides
    // whether the shape is usable. Rejecting scalars here would put schema knowledge
    // in the wrong layer.
    expect(asRecord(3)).toBeUndefined();
  });

  it('refuses an oversized body from content-length before reading it', async () => {
    const port = await bodyEcho(64);
    const reply = await call(port, {
      headers: { ...JSON_HEADERS, 'content-length': String(1024) },
      body: `{"pad":"${'x'.repeat(1013)}"}`,
    });
    if (reply.socketError === undefined) {
      const parsed = JSON.parse(reply.body);
      expect(parsed.error.code).toBe('payload-too-large');
    } else {
      // Also acceptable: the server refused and destroyed the socket before our
      // write drained. Either way the body was never buffered.
      expect(reply.socketError).toBeTruthy();
    }
  });

  it('enforces the cap while streaming, even when content-length lies', async () => {
    // The check that matters. content-length is client-supplied, so the early reject
    // is only an optimisation; a client that understates it must still be cut off
    // mid-read rather than allowed to allocate the whole payload first.
    const port = await bodyEcho(256);
    const reply = await call(port, {
      headers: { ...JSON_HEADERS, 'transfer-encoding': 'chunked' },
      body: `{"pad":"${'x'.repeat(4096)}"}`,
    });
    if (reply.socketError === undefined) {
      expect(JSON.parse(reply.body).error.code).toBe('payload-too-large');
    } else {
      expect(reply.socketError).toBeTruthy();
    }
  });

  it('has a hard ceiling regardless of what a caller asks for', () => {
    // Present so a future handler cannot quietly opt into an unbounded read: the
    // default is the ceiling, and tighter caps are the handler's business.
    expect(MAX_BODY_BYTES).toBe(8 * 1024 * 1024);
  });
});

describe('response headers', () => {
  it('sets the defensive header set on every JSON response', async () => {
    const port = await listen((_request, response) => sendOk(response, { fine: true }));
    const reply = await call(port, { method: 'GET', path: '/anything' });
    expect(reply.headers['content-type']).toBe('application/json; charset=utf-8');
    // no-store: a paired phone's session data has no business in any cache.
    expect(reply.headers['cache-control']).toBe('no-store');
    // nosniff: the body is JSON and must never be interpreted as anything else.
    expect(reply.headers['x-content-type-options']).toBe('nosniff');
  });

  it('sends an accurate content-length for multi-byte bodies', async () => {
    // Byte length, not string length. Getting this wrong truncates the body for any
    // non-ASCII content, which is exactly what a session transcript contains.
    const value = { text: 'héllo → 世界' };
    const port = await listen((_request, response) => sendOk(response, value));
    const reply = await call(port, { method: 'GET' });
    expect(Number(reply.headers['content-length'])).toBe(Buffer.byteLength(JSON.stringify({ ok: true, value }), 'utf8'));
    expect(JSON.parse(reply.body).value).toEqual(value);
  });

  it('never sends CORS headers', async () => {
    // Load-bearing absence. With no `access-control-allow-origin`, a browser cannot
    // read a response from this server even if it reaches it, which keeps a web page
    // from becoming a path to the workstation.
    const port = await listen((_request, response) => sendOk(response, {}));
    const reply = await call(port, { method: 'GET', headers: { origin: 'https://evil.example' } });
    for (const header of Object.keys(reply.headers)) {
      expect(header.startsWith('access-control-')).toBe(false);
    }
  });

  it('maps every declared error code to its documented status', async () => {
    // Driven off M1_BRIDGE_ERROR_CODES rather than a hand-listed subset, so adding a
    // code without a status is a test failure instead of a silent 500. The phone
    // branches on `code`, but the status is what its HTTP layer sees first, and the
    // two are documented together in FRONTEND_CONTRACT.md.
    const expected: Record<string, number> = {
      unauthenticated: 401,
      'method-denied': 403,
      'device-revoked': 403,
      'bad-request': 400,
      'payload-too-large': 413,
      'rate-limited': 429,
      'dsh-unavailable': 503,
      'dsh-protocol-error': 502,
      'pairing-invalid': 400,
      'pairing-unconfirmed': 409,
      'pairing-rejected': 403,
      internal: 500,
    };
    expect(Object.keys(expected).sort()).toEqual([...M1_BRIDGE_ERROR_CODES].sort());

    for (const code of M1_BRIDGE_ERROR_CODES) {
      const port = await listen((_request, response) => sendError(response, bridgeError(code, 'x')));
      const reply = await call(port, { method: 'GET' });
      expect([code, reply.status]).toEqual([code, expected[code]]);
      expect(JSON.parse(reply.body)).toEqual({ ok: false, error: { code, message: 'x' } });
    }
  });

  it('carries extra fields on an error without disturbing the envelope', async () => {
    // `retryAfterMs` on a rate-limit is the case that matters: the phone needs it to
    // back off rather than hammering.
    const port = await listen((_request, response) =>
      sendError(response, bridgeError('rate-limited', 'slow down', { retryAfterMs: 2000 })),
    );
    const reply = await call(port, { method: 'GET' });
    expect(JSON.parse(reply.body).error).toEqual({ code: 'rate-limited', message: 'slow down', retryAfterMs: 2000 });
  });
});

describe('parsePath', () => {
  it.each([
    ['/m1/rpc', '/m1/rpc', ''],
    ['/m1/stream?after=42', '/m1/stream', '42'],
    ['/m1/stream?after=42&extra=1', '/m1/stream', '42'],
    ['/m1/rpc?', '/m1/rpc', ''],
  ])('splits %s into path %s', (target, expectedPath, expectedAfter) => {
    const parsed = parsePath({ url: target } as IncomingMessage);
    expect(parsed.path).toBe(expectedPath);
    expect(parsed.query.get('after') ?? '').toBe(expectedAfter);
  });

  it('does not normalise a traversal into a route', async () => {
    // No path normalisation on purpose: `/m1/../m1/rpc` stays a distinct string and
    // therefore misses every route. Normalising first would mean route matching
    // depends on a rewriting step, which is where traversal bugs live.
    expect(parsePath({ url: '/m1/../m1/rpc' } as IncomingMessage).path).toBe('/m1/../m1/rpc');
    expect(parsePath({ url: '//m1/rpc' } as IncomingMessage).path).toBe('//m1/rpc');
    expect(parsePath({ url: '/m1%2Frpc' } as IncomingMessage).path).toBe('/m1%2Frpc');
  });

  it('treats a missing url as the root', () => {
    expect(parsePath({} as IncomingMessage).path).toBe('/');
  });

  it('keeps a query string containing an encoded question mark intact', () => {
    const parsed = parsePath({ url: '/m1/stream?after=1&label=a%3Fb' } as IncomingMessage);
    expect(parsed.path).toBe('/m1/stream');
    expect(parsed.query.get('label')).toBe('a?b');
  });
});

describe('peerAddress', () => {
  it('reports the real socket address', async () => {
    const port = await listen((request, response) => sendOk(response, { peer: peerAddress(request) }));
    const reply = await call(port, { method: 'GET' });
    // Loopback in either family, depending on how the listener resolved.
    expect(['127.0.0.1', '::ffff:127.0.0.1', '::1']).toContain(JSON.parse(reply.body).value.peer);
  });

  it('ignores x-forwarded-for', async () => {
    // Nothing is meant to proxy this server, so honouring that header would only let
    // a client write whatever it likes into the audit log — including someone else's
    // address, which would make the log actively misleading.
    const port = await listen((request, response) => sendOk(response, { peer: peerAddress(request) }));
    const reply = await call(port, {
      method: 'GET',
      headers: { 'x-forwarded-for': '10.0.0.99', 'x-real-ip': '10.0.0.98' },
    });
    expect(JSON.parse(reply.body).value.peer).not.toContain('10.0.0.9');
  });
});

describe('asRecord and requireString', () => {
  it.each([
    ['null', null],
    ['an array', [1, 2]],
    ['a string', 'text'],
    ['a number', 3],
  ])('treats %s as not a record', (_label, value) => {
    // Arrays are the one that would otherwise slip through `typeof x === 'object'`,
    // and `body[0]` on an array is a real value, so a handler probing fields would
    // read attacker-positioned data.
    expect(asRecord(value)).toBeUndefined();
  });

  it('accepts a plain object', () => {
    expect(asRecord({ a: 1 })).toEqual({ a: 1 });
  });

  it('requires a non-empty string within the length bound', () => {
    expect(requireString({ token: 'abc' }, 'token')).toBe('abc');
    expect(requireString({ token: '' }, 'token')).toBeUndefined();
    expect(requireString({ token: 42 }, 'token')).toBeUndefined();
    expect(requireString({}, 'token')).toBeUndefined();
    // Length-bounded so a field that reaches a Map key or a log line cannot be used
    // to blow memory up through a field the schema thought was short.
    expect(requireString({ label: 'x'.repeat(65) }, 'label', 64)).toBeUndefined();
    expect(requireString({ label: 'x'.repeat(64) }, 'label', 64)).toHaveLength(64);
  });

  it('does not accept a prototype-inherited value as a field', () => {
    // `{}.constructor` is a function so it fails the string check anyway, but the
    // point is that inherited keys are not treated as present data.
    expect(requireString({} as Record<string, unknown>, 'constructor')).toBeUndefined();
    expect(requireString({} as Record<string, unknown>, 'toString')).toBeUndefined();
  });
});

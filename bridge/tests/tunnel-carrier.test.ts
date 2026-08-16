/**
 * Loopback carrier tests.
 *
 * Exercises `LocalBridgeBackend` and the client-side WebSocket against a real HTTP
 * server over a real Unix socket, which is what the connector uses to reach the
 * bridge's own `/m1` routes.
 *
 * Also serves as the interop check for our RFC 6455 codec in both directions: the
 * client masks and the server unmasks, using the same encoder and decoder.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Duplex } from 'node:stream';
import { LocalBridgeBackend } from '../src/relay/backend.ts';
import { ServerWebSocket, checkUpgrade, writeHandshake } from '../src/http/websocket.ts';
import { M1_STREAM_SUBPROTOCOL, M1_TOKEN_SUBPROTOCOL_PREFIX } from '../src/m1/wire.ts';

interface Recorded {
  method: string;
  url: string;
  body: string;
  contentType: string | undefined;
}

describe('local bridge carrier', () => {
  let server: Server;
  let dir: string;
  let socketPath: string;
  let backend: LocalBridgeBackend;
  const recorded: Recorded[] = [];
  const upgrades: { url: string; protocols: string[] }[] = [];
  let sockets: ServerWebSocket[] = [];
  let nextStatus = 200;
  let nextBody: unknown = { ok: true, value: 1 };
  /** Set to send a body that is not JSON at all, bypassing `nextBody`. */
  let nextRawBody: string | undefined;
  let refuseUpgrade: number | undefined;

  beforeEach(async () => {
    recorded.length = 0;
    upgrades.length = 0;
    sockets = [];
    nextStatus = 200;
    nextBody = { ok: true, value: 1 };
    nextRawBody = undefined;
    refuseUpgrade = undefined;
    dir = mkdtempSync(join(tmpdir(), 'dshm-carrier-'));
    socketPath = join(dir, 'bridge.sock');

    server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        recorded.push({
          method: request.method ?? '',
          url: request.url ?? '',
          body: Buffer.concat(chunks).toString('utf8'),
          contentType: request.headers['content-type'],
        });
        const payload = Buffer.from(nextRawBody ?? JSON.stringify(nextBody), 'utf8');
        response.writeHead(nextStatus, {
          'content-type': 'application/json',
          'content-length': String(payload.byteLength),
        });
        response.end(payload);
      });
    });

    server.on('upgrade', (request, rawSocket) => {
      const socket = rawSocket as Duplex;
      const check = checkUpgrade(request);
      if (!check.ok || check.key === undefined) {
        socket.write('HTTP/1.1 400 bad upgrade\r\nconnection: close\r\ncontent-length: 0\r\n\r\n');
        socket.destroy();
        return;
      }
      upgrades.push({ url: request.url ?? '', protocols: check.subprotocols ?? [] });
      if (refuseUpgrade !== undefined) {
        socket.write(`HTTP/1.1 ${refuseUpgrade} refused\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`);
        socket.destroy();
        return;
      }
      writeHandshake(socket, check.key, M1_STREAM_SUBPROTOCOL);
      const ws = new ServerWebSocket(socket, { maxMessageBytes: 64 * 1024 }, {});
      sockets.push(ws);
    });

    await new Promise<void>((resolve) => server.listen(socketPath, () => resolve()));
    backend = new LocalBridgeBackend({ target: { socketPath }, requestTimeoutMs: 2_000 });
  });

  afterEach(async () => {
    for (const ws of sockets) ws.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  });

  it('forwards a POST with a JSON body and content-type', async () => {
    nextBody = { ok: true, value: { rpcId: 'r1' } };
    const response = await backend.request({ method: 'POST', path: '/m1/rpc', body: { method: 'session.list' } });
    expect(response).toEqual({ status: 200, body: { ok: true, value: { rpcId: 'r1' } } });
    expect(recorded[0]).toMatchObject({
      method: 'POST',
      url: '/m1/rpc',
      body: '{"method":"session.list"}',
      contentType: 'application/json',
    });
  });

  it('forwards a GET with no body and no content-type', async () => {
    await backend.request({ method: 'GET', path: '/m1/health' });
    expect(recorded[0]).toMatchObject({ method: 'GET', url: '/m1/health', body: '' });
    expect(recorded[0]?.contentType).toBeUndefined();
  });

  it('preserves a non-2xx status', async () => {
    nextStatus = 429;
    nextBody = { ok: false, error: { code: 'rate-limited', message: 'slow down' } };
    const response = await backend.request({ method: 'POST', path: '/m1/rpc', body: {} });
    expect(response.status).toBe(429);
    expect(response.body).toEqual({ ok: false, error: { code: 'rate-limited', message: 'slow down' } });
  });

  it('reports a 502 when the bridge sends non-JSON', async () => {
    nextRawBody = '<html>proxy error</html>';
    const response = await backend.request({ method: 'GET', path: '/m1/health' });
    expect(response.status).toBe(502);
    expect(response.body).toMatchObject({ ok: false, error: { message: 'bridge sent non-JSON' } });
  });

  it('treats an empty body as null rather than a parse failure', async () => {
    nextRawBody = '';
    const response = await backend.request({ method: 'GET', path: '/m1/health' });
    expect(response).toEqual({ status: 200, body: null });
  });

  it('reports a 502 when the carrier is unreachable', async () => {
    const dead = new LocalBridgeBackend({ target: { socketPath: join(dir, 'nope.sock') }, requestTimeoutMs: 500 });
    const response = await dead.request({ method: 'GET', path: '/m1/health' });
    expect(response.status).toBe(502);
    expect(response.body).toMatchObject({ ok: false, error: { code: 'internal' } });
  });

  it('opens a stream, carrying the token in the subprotocol and not the query', async () => {
    const messages: unknown[] = [];
    const opened = await backend.openStream({
      token: 'tok-xyz',
      after: 42,
      sinks: { onMessage: (value) => messages.push(value), onClose: () => undefined },
    });
    expect(opened.ok).toBe(true);
    expect(upgrades[0]?.url).toBe('/m1/stream?after=42');
    expect(upgrades[0]?.url).not.toContain('tok-xyz');
    expect(upgrades[0]?.protocols).toEqual([M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}tok-xyz`]);
  });

  it('delivers server frames to the sinks and masks what it sends', async () => {
    const messages: unknown[] = [];
    const opened = await backend.openStream({
      token: 't',
      after: 0,
      sinks: { onMessage: (value) => messages.push(value), onClose: () => undefined },
    });
    expect(opened.ok).toBe(true);

    sockets[0]?.sendJson({ v: 1, kind: 'hello', lastBseq: 0 });
    sockets[0]?.sendJson({ v: 1, bseq: 1, kind: 'dsh', frame: { type: 'token', text: 'hi' } });
    await waitFor(() => messages.length === 2);
    expect(messages[1]).toEqual({ v: 1, bseq: 1, kind: 'dsh', frame: { type: 'token', text: 'hi' } });
  });

  it('survives a fragmented and a large server message', async () => {
    const messages: unknown[] = [];
    await backend.openStream({
      token: 't',
      after: 0,
      sinks: { onMessage: (value) => messages.push(value), onClose: () => undefined },
    });
    const big = 'x'.repeat(40_000);
    sockets[0]?.sendJson({ v: 1, bseq: 2, kind: 'dsh', frame: { type: 'token', text: big } });
    await waitFor(() => messages.length === 1);
    expect((messages[0] as { frame: { text: string } }).frame.text).toHaveLength(40_000);
  });

  it('reports close to the sinks', async () => {
    const closes: string[] = [];
    await backend.openStream({
      token: 't',
      after: 0,
      sinks: { onMessage: () => undefined, onClose: (reason) => closes.push(reason) },
    });
    sockets[0]?.close(1000, 'server done');
    await waitFor(() => closes.length === 1);
    expect(closes).toHaveLength(1);
  });

  it('surfaces the refusal status from a rejected upgrade', async () => {
    refuseUpgrade = 401;
    const opened = await backend.openStream({
      token: 'stale',
      after: 0,
      sinks: { onMessage: () => undefined, onClose: () => undefined },
    });
    expect(opened).toMatchObject({ ok: false, status: 401 });
  });

  it('ignores malformed JSON from the stream rather than throwing', async () => {
    const messages: unknown[] = [];
    await backend.openStream({
      token: 't',
      after: 0,
      sinks: { onMessage: (value) => messages.push(value), onClose: () => undefined },
    });
    sockets[0]?.send('not json at all');
    sockets[0]?.sendJson({ v: 1, bseq: 3, kind: 'bridge', frame: { type: 'pong', at: 1 } });
    await waitFor(() => messages.length === 1);
    expect(messages[0]).toMatchObject({ bseq: 3 });
  });
});

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('condition not met in time');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

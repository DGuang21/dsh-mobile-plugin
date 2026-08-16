/**
 * A real HTTP fake dsh, for CLI and end-to-end tests.
 *
 * `FakeDsh` in fake-dsh.ts is a `fetch` stand-in and cannot serve the WebSocket
 * downlinks, so the readiness handshake can never complete against it. This one
 * listens for real: `POST /api/<method>` plus the two `events.*` upgrades, which is
 * the minimum needed for `DshConnection` to reach `connected`.
 *
 * It reproduces the verified upstream carrier rules that matter here and nothing
 * more. It is a test double, not a dsh implementation, so a green test against it is
 * NOT evidence of compatibility with a real harness.
 */

import { createServer, type Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { CLOSE, ServerWebSocket, checkUpgrade, writeHandshake } from '../src/http/websocket.ts';
import type { RpcReceipt } from '../src/dsh/types.ts';

export interface FakeDshServerOptions {
  /** Method handlers. Anything absent 404s, as upstream's dispatch does. */
  methods?: Record<string, (payload: unknown) => unknown>;
  /**
   * Receipt for `POST /api/respond`.
   *
   * A function rather than a value so a test can vary it per call — the whole point
   * of the carrier receipt is that the *second* answer to an rpcId is told
   * `not-pending`, and a fixed value cannot express that.
   */
  respondReceipt?: (rpcId: string, value: unknown) => RpcReceipt;
}

export class FakeDshServer {
  private readonly server: Server;
  private readonly methods: Record<string, (payload: unknown) => unknown>;
  private readonly options: FakeDshServerOptions;
  /** Open downlinks, keyed by the path they were opened on. */
  readonly sockets = new Map<string, ServerWebSocket>();
  /**
   * Every `/api/*` call that reached this server, in order.
   *
   * Recorded so a policy test can assert on absence: a denied method must produce
   * a 403 *and* leave no trace here. Asserting only the status would pass for a
   * bridge that forwarded the call and then reported a denial, which is the
   * failure mode a deny list exists to prevent.
   */
  readonly calls: { method: string; rpcId: string; payload: unknown }[] = [];
  /**
   * The `result` of the most recent `POST /api/respond`.
   *
   * Kept separately from `calls` because a `client-response` carries `result`, not
   * `payload`, so recording it in the shared log would silently store `undefined`
   * and a test asserting on the answer's contents would pass for the wrong reason.
   */
  lastRespondResult: unknown;
  port = 0;

  constructor(options: FakeDshServerOptions = {}) {
    this.options = options;
    this.methods = {
      // The readiness handshake calls exactly this, after both sockets open.
      'host.describe': () => ({ name: 'fake-dsh', version: '0.0.0-test' }),
      'session.list': () => ({ sessions: [] }),
      'workspace.list': () => ({ workspaces: [] }),
      ...(options.methods ?? {}),
    };

    this.server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        const path = (request.url ?? '').split('?')[0] ?? '';
        if (!path.startsWith('/api/')) {
          response.writeHead(404).end();
          return;
        }
        const contentType = request.headers['content-type'];
        if (typeof contentType !== 'string' || !contentType.includes('application/json')) {
          response.writeHead(415).end();
          return;
        }
        let body: { rpcId?: string; method?: string; payload?: unknown };
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as typeof body;
        } catch {
          response.writeHead(400).end();
          return;
        }
        const method = path.slice('/api/'.length);
        // Recorded before the handler lookup, so an unknown method still counts as
        // having reached upstream.
        this.calls.push({ method, rpcId: body.rpcId ?? '', payload: body.payload });

        // `respond` is not in the method map because it is not an RPC: it carries a
        // `client-response` and answers with a bare carrier receipt, no envelope.
        // Serving it through the same table would wrap the receipt in a
        // `server-response` and the client would correctly refuse to read it.
        if (method === 'respond') {
          const result = (body as { result?: unknown }).result;
          this.lastRespondResult = result;
          const receipt = (this.options.respondReceipt ?? (() => ({ accepted: true }) as RpcReceipt))(
            body.rpcId ?? '',
            result,
          );
          const encoded = JSON.stringify(receipt);
          response.writeHead(200, { 'content-type': 'application/json', 'content-length': String(encoded.length) });
          response.end(encoded);
          return;
        }

        const handler = this.methods[method];
        if (handler === undefined) {
          response.writeHead(404).end();
          return;
        }
        // Business results are HTTP 200, and the rpcId is echoed verbatim.
        const payload = JSON.stringify({
          type: 'server-response',
          rpcId: body.rpcId ?? '',
          result: { ok: true, value: handler(body.payload) },
        });
        response.writeHead(200, { 'content-type': 'application/json', 'content-length': String(payload.length) });
        response.end(payload);
      });
    });

    this.server.on('upgrade', (request, rawSocket) => {
      const socket = rawSocket as Duplex;
      const path = (request.url ?? '').split('?')[0] ?? '';
      const check = checkUpgrade(request);
      if (!check.ok || check.key === undefined || !path.startsWith('/api/events.')) {
        socket.write('HTTP/1.1 400 bad upgrade\r\nconnection: close\r\ncontent-length: 0\r\n\r\n');
        socket.destroy();
        return;
      }
      writeHandshake(socket, check.key);
      this.sockets.set(path, new ServerWebSocket(socket, { maxMessageBytes: 1024 * 1024 }, {}));
    });
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', () => resolve()));
    const address = this.server.address();
    this.port = typeof address === 'object' && address !== null ? address.port : 0;
    return this.port;
  }

  get baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  /**
   * Push a frame on the downlinks, as dsh would.
   *
   * `which` exists because the two downlinks carry disjoint frame vocabularies: a
   * mux frame on the host socket is correctly rejected as malformed, so a test that
   * broadcasts to both is really testing one path and logging an error for the
   * other.
   */
  broadcast(frame: unknown, which: 'mux' | 'host' | 'both' = 'both'): void {
    for (const [path, socket] of this.sockets) {
      if (which !== 'both' && !path.endsWith(`events.${which}`)) continue;
      socket.sendJson(frame);
    }
  }

  async close(): Promise<void> {
    for (const socket of this.sockets.values()) socket.close(CLOSE.goingAway, 'fake dsh closing');
    this.sockets.clear();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}

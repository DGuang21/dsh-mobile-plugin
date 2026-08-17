/**
 * [OUR DESIGN] Bridge-side backend for the relay tunnel.
 *
 * A tunnel request has to end up somewhere. The choice made here is that it ends up
 * at the bridge's own `/m1` router over a loopback carrier, rather than at a
 * bespoke tunnel handler. Consequences, in order of importance:
 *
 *   1. There is one authorization path. Pairing, token verification, revocation
 *      re-checks, the method deny list, payload caps, rate limits, and the audit log
 *      all apply to relay traffic without being reimplemented.
 *   2. A bug in the tunnel cannot become an auth bypass, because the tunnel holds no
 *      credentials and makes no decisions. It moves bytes.
 *   3. The cost is one serialization hop on loopback, which is irrelevant next to
 *      the WAN round-trip the relay already imposes.
 *
 * `[NOT INTEGRATION-TESTED]` against a real phone: the tunnel is exercised in-process
 * and over a real loopback socket, but no mobile client has spoken it.
 */

import { connect as netConnect, type Socket } from 'node:net';
import { request as httpRequest } from 'node:http';
import { randomBytes } from 'node:crypto';
import {
  ClientWebSocket,
  clientHandshakeRequest,
  readClientHandshake,
} from '../http/websocket.ts';
import { M1_PATHS, M1_STREAM_SUBPROTOCOL, M1_TOKEN_SUBPROTOCOL_PREFIX } from '../m1/wire.ts';

export interface TunnelRequest {
  method: 'GET' | 'POST';
  path: string;
  /** Bearer token forwarded over the already sealed tunnel, never to the relay. */
  token?: string;
  body?: unknown;
}

export interface TunnelResponse {
  status: number;
  body: unknown;
}

/** A live event subscription owned by the backend. */
export interface TunnelStream {
  close(): void;
}

export interface TunnelStreamSinks {
  /** One `/m1/stream` message, already parsed. Forwarded to the phone verbatim. */
  onMessage: (value: unknown) => void;
  onClose: (reason: string) => void;
}

/**
 * What the connector needs from the bridge.
 *
 * An interface rather than a concrete class so tests can drive the relay path
 * without standing up a full bridge, and so the carrier can change without the
 * connector caring.
 */
export interface TunnelBackend {
  request(input: TunnelRequest): Promise<TunnelResponse>;
  openStream(input: {
    token: string;
    after: number;
    sinks: TunnelStreamSinks;
  }): Promise<{ ok: true; stream: TunnelStream } | { ok: false; status: number; reason: string }>;
}

export interface LocalBackendOptions {
  /** Unix socket path, or `{ port, host }` for a loopback TCP carrier. */
  target: { socketPath: string } | { port: number; host?: string };
  requestTimeoutMs?: number;
}

/**
 * Talks to the bridge's `/m1` routes over a local carrier.
 *
 * Deliberately plaintext HTTP: the carrier is a Unix socket (mode 0600) or a
 * loopback port, so adding TLS would protect nothing that filesystem permissions
 * and the loopback interface do not already protect, at the cost of a second
 * certificate to manage. A caller must not point this at a remote address.
 */
export class LocalBridgeBackend implements TunnelBackend {
  private readonly target: LocalBackendOptions['target'];
  private readonly requestTimeoutMs: number;

  constructor(options: LocalBackendOptions) {
    this.target = options.target;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
  }

  request(input: TunnelRequest): Promise<TunnelResponse> {
    return new Promise((resolve) => {
      const payload = input.body === undefined ? undefined : Buffer.from(JSON.stringify(input.body), 'utf8');
      const headers: Record<string, string> = { host: 'bridge.local', accept: 'application/json' };
      if (input.token !== undefined) headers.authorization = `Bearer ${input.token}`;
      if (payload !== undefined) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = String(payload.byteLength);
      }

      const req = httpRequest(
        {
          ...('socketPath' in this.target
            ? { socketPath: this.target.socketPath }
            : { host: this.target.host ?? '127.0.0.1', port: this.target.port }),
          method: input.method,
          path: input.path,
          headers,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let bytes = 0;
          res.on('data', (chunk: Buffer) => {
            bytes += chunk.byteLength;
            // The bridge's own responses are small; a huge one means something is
            // wrong and buffering it would only make it worse.
            if (bytes > 8 * 1024 * 1024) {
              res.destroy();
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed: unknown;
            try {
              parsed = text.length === 0 ? null : JSON.parse(text);
            } catch {
              resolve({ status: 502, body: { ok: false, error: { code: 'internal', message: 'bridge sent non-JSON' } } });
              return;
            }
            resolve({ status: res.statusCode ?? 502, body: parsed });
          });
          res.on('error', () => {
            resolve({ status: 502, body: { ok: false, error: { code: 'internal', message: 'carrier read failed' } } });
          });
        },
      );

      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy(new Error('carrier timeout'));
      });
      req.on('error', () => {
        resolve({ status: 502, body: { ok: false, error: { code: 'internal', message: 'bridge carrier unreachable' } } });
      });
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }

  openStream(input: {
    token: string;
    after: number;
    sinks: TunnelStreamSinks;
  }): Promise<{ ok: true; stream: TunnelStream } | { ok: false; status: number; reason: string }> {
    return new Promise((resolve) => {
      const key = randomBytes(16).toString('base64');
      const socket: Socket = netConnect(
        'socketPath' in this.target
          ? { path: this.target.socketPath }
          : { host: this.target.host ?? '127.0.0.1', port: this.target.port },
      );
      let settled = false;
      let buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);

      const fail = (status: number, reason: string): void => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve({ ok: false, status, reason });
      };

      socket.on('error', () => fail(502, 'carrier unreachable'));
      socket.on('close', () => fail(502, 'carrier closed during handshake'));

      const onData = (chunk: Buffer): void => {
        buffer = buffer.byteLength === 0 ? chunk : Buffer.concat([buffer, chunk]);
        const outcome = readClientHandshake(buffer, key);
        if ('pending' in outcome) return;
        if (!outcome.ok) {
          // The refusal status is what the phone needs: 401 means "get a new
          // token", 403 means "you were revoked, stop retrying".
          const status = Number(/expected 101, got (\d+)/.exec(outcome.reason)?.[1] ?? 0);
          fail(status > 0 ? status : 502, outcome.reason);
          return;
        }

        settled = true;
        socket.removeListener('data', onData);
        socket.removeAllListeners('close');
        socket.removeAllListeners('error');

        const ws = new ClientWebSocket(socket, { maxMessageBytes: 1024 * 1024 }, {});
        ws.setSinks({
          onMessage: (text) => {
            let parsed: unknown;
            try {
              parsed = JSON.parse(text);
            } catch {
              return;
            }
            input.sinks.onMessage(parsed);
          },
          onClose: (_code, reason) => input.sinks.onClose(reason || 'stream closed'),
        });
        // Bytes that arrived in the same read as the 101 must not be dropped.
        ws.pushInitial(outcome.rest);
        resolve({ ok: true, stream: { close: () => ws.close() } });
      };

      socket.on('data', onData);
      socket.on('connect', () => {
        socket.write(
          clientHandshakeRequest({
            path: `${M1_PATHS.stream}?after=${input.after}`,
            host: 'bridge.local',
            key,
            // Same subprotocol carriage as a LAN phone: the token never goes in the
            // query string, where it would land in logs.
            protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${input.token}`],
          }),
        );
      });
      socket.setTimeout(this.requestTimeoutMs, () => fail(504, 'carrier handshake timeout'));
    });
  }
}

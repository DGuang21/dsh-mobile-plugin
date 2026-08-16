/**
 * Mode A transport: HTTPS plus a WebSocket, straight to the bridge on the LAN.
 *
 * Nothing clever here — that is the point. Mode A is the simple path, and keeping
 * it thin makes the sealed-tunnel path in `relay-transport.ts` the only place with
 * real machinery.
 *
 * ## The Mode A pinning gap, stated plainly
 *
 * **`fp` is stored but not enforced, and Mode A has no other bridge-to-phone
 * authentication.** Two facts combine here:
 *
 *   - RN's `fetch` and `WebSocket` expose no certificate hook, so the pinned TLS
 *     SPKI cannot be compared in JS. Closing this needs a native TLS delegate,
 *     which is outside this core.
 *   - The bridge never signs anything in the Mode A auth exchange. `/m1/auth/session`
 *     is one-way: the *phone* signs a nonce, and the bridge answers with a token
 *     (`bridge/src/auth/tokens.ts`). The pinned `bk` from the QR is therefore
 *     unused on this path.
 *
 * So on the LAN, transport security rests on ordinary TLS, and an attacker holding
 * a certificate the device already trusts can read and alter traffic. The `bridgeId`
 * check in `core.ts` catches a *different* bridge answering, not a proxy relaying to
 * the right one. What still holds: pairing needs the one-shot token plus operator
 * SAS confirmation, and the access token is short-lived and memory-only.
 *
 * Mode B does not share this gap. The seal handshake verifies a signature by the
 * pinned `bk` before any application byte moves, which is why relay transport is
 * the safe path off a trusted network. Tracked in `docs/FRONTEND_CONTRACT.md` §13.
 */

import { M1_PATHS, M1_STREAM_SUBPROTOCOL, M1_TOKEN_SUBPROTOCOL_PREFIX } from './paths';
import { asStreamEnvelope, asStreamHello } from './tunnel';
import {
  type M1Transport,
  type StreamHandlers,
  type StreamSubscription,
  TransportError,
  type TransportResponse,
} from './transport';

export interface LanTransportOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  webSocketImpl?: typeof WebSocket;
  requestTimeoutMs?: number;
  onDiagnostic?: (level: 'info' | 'warn' | 'error', message: string) => void;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 20_000;

export class LanTransport implements M1Transport {
  readonly mode = 'lan' as const;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly webSocketImpl: typeof WebSocket;
  private readonly requestTimeoutMs: number;
  private readonly onDiagnostic: LanTransportOptions['onDiagnostic'];
  private closed = false;
  private sockets = new Set<WebSocket>();

  constructor(options: LanTransportOptions) {
    this.baseUrl = options.baseUrl.trim().replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.webSocketImpl = options.webSocketImpl ?? WebSocket;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.onDiagnostic = options.onDiagnostic;
  }

  /** Mode A has no session to establish: the first request is the first contact. */
  async start(): Promise<void> {
    if (this.closed) throw new TransportError('offline', 'transport is closed');
  }

  async request(input: {
    method: 'GET' | 'POST';
    path: string;
    token?: string;
    body?: unknown;
  }): Promise<TransportResponse> {
    if (this.closed) throw new TransportError('offline', 'transport is closed');

    // AbortController rather than Promise.race: a raced timeout leaves the socket
    // open, and on a phone that means holding the radio awake for a request nobody
    // is waiting for.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${input.path}`, {
        method: input.method,
        signal: controller.signal,
        headers: {
          accept: 'application/json',
          ...(input.body === undefined ? {} : { 'content-type': 'application/json' }),
          ...(input.token === undefined ? {} : { authorization: `Bearer ${input.token}` }),
        },
        ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
      });
      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = text.length > 0 ? JSON.parse(text) : undefined;
      } catch {
        // A non-JSON body from a bridge endpoint means something else answered —
        // a captive portal, a proxy error page. Report the status and let the
        // caller decide; do not invent a body.
        parsed = undefined;
      }
      return { status: response.status, body: parsed };
    } catch (error) {
      if (controller.signal.aborted) {
        throw new TransportError('timeout', `request to ${input.path} timed out`);
      }
      throw new TransportError('offline', `could not reach the bridge: ${errorText(error)}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Open `/m1/stream`.
   *
   * The token rides in a subprotocol rather than a query string because RN's
   * WebSocket cannot set headers and a URL is the one part of a request that ends
   * up in logs and proxy traces.
   */
  subscribe(input: { token: string; after: number; handlers: StreamHandlers }): StreamSubscription {
    if (this.closed) {
      input.handlers.onClosed('transport is closed');
      return { stop: () => undefined };
    }

    const url = `${this.baseUrl.replace(/^http/, 'ws')}${M1_PATHS.stream}?after=${input.after}`;
    let socket: WebSocket;
    try {
      socket = new this.webSocketImpl(url, [
        M1_STREAM_SUBPROTOCOL,
        `${M1_TOKEN_SUBPROTOCOL_PREFIX}${input.token}`,
      ]);
    } catch (error) {
      input.handlers.onClosed(`could not open the stream: ${errorText(error)}`);
      return { stop: () => undefined };
    }
    this.sockets.add(socket);

    let stopped = false;
    let helloSeen = false;
    const finish = (reason: string): void => {
      if (stopped) return;
      stopped = true;
      this.sockets.delete(socket);
      input.handlers.onClosed(reason);
    };

    socket.onmessage = (event) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(String(event.data));
      } catch {
        this.note('warn', 'bridge stream sent a non-JSON frame');
        return;
      }
      if (!helloSeen) {
        const hello = asStreamHello(parsed);
        if (hello !== undefined) {
          helloSeen = true;
          input.handlers.onHello(hello);
          return;
        }
        // The contract guarantees hello first. A frame before it means we have no
        // baseline and no rotated token, so rendering it would be worse than
        // dropping it.
        this.note('warn', 'bridge stream frame arrived before the hello');
        return;
      }
      const envelope = asStreamEnvelope(parsed);
      if (envelope === undefined) {
        this.note('warn', 'bridge stream sent a malformed envelope');
        return;
      }
      input.handlers.onEnvelope(envelope);
    };
    socket.onerror = () => finish('stream connection failed');
    socket.onclose = (event) => {
      const closeEvent = event as { reason?: string; code?: number };
      finish(closeEvent.reason !== undefined && closeEvent.reason.length > 0
        ? closeEvent.reason
        : `stream closed (${closeEvent.code ?? 0})`);
    };

    return {
      stop: () => {
        if (stopped) return;
        stopped = true;
        this.sockets.delete(socket);
        try {
          socket.close();
        } catch {
          // Already closing.
        }
      },
    };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const socket of this.sockets) {
      try {
        socket.close();
      } catch {
        // Already closing.
      }
    }
    this.sockets.clear();
  }

  private note(level: 'info' | 'warn' | 'error', message: string): void {
    this.onDiagnostic?.(level, message);
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

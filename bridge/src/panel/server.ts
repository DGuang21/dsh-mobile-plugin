/**
 * [OUR DESIGN] Management panel HTTP fence + static delivery.
 *
 * Wraps {@link PanelApi} with the security boundary and serves the panel UI. The
 * same `handle()` is used whether the panel lives on its own loopback listener
 * (the guaranteed-safe delivery) or is attached to another server — so the mount
 * decision never changes the fence.
 *
 * SECURITY MODEL, stated plainly. The panel mints access tokens, revokes devices,
 * sets the relay, and opens pairing windows. That is strictly more power than the
 * phone-facing `/m1` surface, so it is gated harder, by four independent checks
 * that ALL must pass before any handler runs:
 *
 *   1. LOOPBACK PEER. The request's remote address must be loopback (or a Unix
 *      socket, which has no remote address and is local by construction). This
 *      holds even if the panel is attached to a server that some operator bound to
 *      0.0.0.0 — a LAN client is refused at the door. The panel's own listener
 *      binds 127.0.0.1 and never accepts a host override.
 *   2. LOCAL HOST HEADER. The `Host` must name a loopback address or `localhost`.
 *      This is the DNS-rebinding defense: a malicious page that re-resolves its own
 *      domain to 127.0.0.1 still sends its original `Host`, which is refused.
 *   3. BEARER TOKEN on every `/api/*` route. A random per-boot secret, delivered
 *      only by injection into the panel HTML that is itself served same-origin over
 *      loopback. A cross-origin page cannot read it (same-origin policy) and cannot
 *      forge it, so it defeats both CSRF and a rebinding attacker who slipped past
 *      the Host check. Compared in constant time.
 *   4. JSON CONTENT-TYPE on every mutating route, and NO CORS headers, ever —
 *      mirroring `/m1`. A cross-origin `<form>` cannot set `application/json`, so it
 *      cannot drive a mutation even if the token leaked.
 *
 * The token is written to the state dir at 0600 so same-user tooling can read it;
 * that file is a convenience, not the boundary. The boundary is that everything
 * above already requires you to be the local workstation user.
 *
 * WHAT IS NEVER SERVED: directory listings, files outside the assets dir (path
 * traversal is refused), the bridge private key, or raw pairing tokens.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import type { PanelApi } from './api.ts';
import { readJsonBody } from '../http/router.ts';

/** File the per-boot panel token is written to, inside the state dir. */
export const PANEL_TOKEN_FILE = 'panel-token';

/** Default mount path. Chosen to not collide with dsh's own routes. */
export const DEFAULT_PANEL_BASE = '/mobile-bridge';

/** The bootstrap global the UI reads for its token and API base. */
const BOOTSTRAP_PLACEHOLDER = '%%DSH_MOBILE_BRIDGE_BOOTSTRAP%%';

const STATIC_MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

export interface PanelServerOptions {
  api: PanelApi;
  /** Directory of static UI assets (the plugin's `panel-ui/`). */
  assetsDir: string;
  /**
   * Bearer token. Generated per boot if absent. When `tokenFile` is set the token
   * is also written there at 0600 so same-user tooling can read it.
   */
  token?: string;
  /** Absolute path to write the token to (usually `<stateDir>/panel-token`). */
  tokenFile?: string;
  /** Route prefix. Defaults to {@link DEFAULT_PANEL_BASE}. */
  basePath?: string;
}

export class PanelServer {
  private readonly api: PanelApi;
  private readonly assetsDir: string;
  private readonly basePath: string;
  readonly token: string;

  constructor(options: PanelServerOptions) {
    this.api = options.api;
    this.assetsDir = resolve(options.assetsDir);
    this.basePath = (options.basePath ?? DEFAULT_PANEL_BASE).replace(/\/$/, '');
    this.token = options.token ?? toBase64Url(randomBytes(32));
    if (options.tokenFile !== undefined) {
      // 0600 from creation: same policy as every other secret in the state dir.
      writeFileSync(options.tokenFile, `${this.token}\n`, { mode: 0o600 });
      chmodSync(options.tokenFile, 0o600);
    }
  }

  /**
   * Attach to an existing server as a `request` listener.
   *
   * Returns nothing; requests outside {@link basePath} are left untouched so other
   * listeners on the same server still see them. Used both by the panel's own
   * listener and, where supported, by a host server.
   */
  attach(server: Server): void {
    server.on('request', (request, response) => {
      const { pathname } = this.parse(request);
      if (pathname === this.basePath || pathname.startsWith(`${this.basePath}/`)) {
        void this.handle(request, response);
      }
    });
  }

  /**
   * Handle one request. Returns `true` if it fell within the panel's base path
   * (and was answered), `false` if the path was not ours.
   */
  async handle(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
    const { pathname, query } = this.parse(request);
    if (pathname !== this.basePath && !pathname.startsWith(`${this.basePath}/`)) return false;

    // ── fence, in order; the first failure answers and stops ──
    if (!isLoopbackPeer(request.socket.remoteAddress)) {
      sendJson(response, 403, { ok: false, error: { code: 'forbidden', message: 'panel is loopback-only' } });
      return true;
    }
    if (!isLocalHostHeader(request.headers.host)) {
      sendJson(response, 403, { ok: false, error: { code: 'forbidden', message: 'panel requires a loopback Host' } });
      return true;
    }

    const method = (request.method ?? 'GET').toUpperCase();
    const sub = pathname.slice(this.basePath.length).replace(/^\//, '');

    // ── static UI (no token; delivering the token is the point) ──
    if (!sub.startsWith('api/')) {
      if (method !== 'GET') return this.answer(response, 405, { ok: false, error: { code: 'bad-request', message: 'GET only' } });
      return this.serveStatic(sub, response);
    }

    // ── API: every route past here needs the bearer token ──
    if (!this.authorized(request)) {
      sendJson(response, 401, { ok: false, error: { code: 'unauthenticated', message: 'missing or invalid panel token' } });
      return true;
    }

    const route = sub.slice('api/'.length);
    return await this.serveApi(method, route, request, response, query);
  }

  // ── API routing ───────────────────────────────────────────────────────────

  private async serveApi(
    method: string,
    route: string,
    request: IncomingMessage,
    response: ServerResponse,
    query: URLSearchParams,
  ): Promise<boolean> {
    // Reads first.
    if (route === 'status' && method === 'GET') return this.emit(response, this.api.getStatus());
    if (route === 'devices' && method === 'GET') return this.emit(response, this.api.listDevices());
    if (route === 'audit' && method === 'GET') return this.emit(response, this.api.getAudit(query.get('limit')));
    if (route === 'relay' && method === 'GET') return this.emit(response, this.api.getRelay());
    if (route === 'pairing' && method === 'GET') return this.emit(response, this.api.getPairing());

    // Mutations: require a JSON body (blocks form-based CSRF) except DELETE, which
    // carries no body but is still same-origin + token-gated.
    if (route === 'relay' && method === 'DELETE') return this.emit(response, this.api.clearRelay());
    if (route === 'pairing' && method === 'DELETE') return this.emit(response, this.api.cancelPairing());

    if (method === 'POST' || method === 'PUT') {
      const body = await readJsonBody(request, 64 * 1024);
      if (!body.ok) return this.answer(response, 400, { ok: false, error: body.error });
      if (route === 'devices/revoke' && method === 'POST') {
        return this.emit(response, this.api.revokeDevice(recordField(body.value, 'deviceId')));
      }
      if (route === 'relay' && method === 'PUT') {
        return this.emit(response, this.api.setRelay(recordField(body.value, 'url')));
      }
      if (route === 'pairing' && method === 'POST') return this.emit(response, this.api.startPairing(body.value));
      if (route === 'pairing/confirm' && method === 'POST') return this.emit(response, this.api.confirmPairing(body.value));
    }

    return this.answer(response, 404, { ok: false, error: { code: 'not-found', message: 'no such panel route' } });
  }

  // ── static delivery ─────────────────────────────────────────────────────────

  private serveStatic(sub: string, response: ServerResponse): boolean {
    const relative = sub === '' ? 'index.html' : sub;
    // Resolve within the assets dir and refuse anything that escapes it.
    const target = resolve(join(this.assetsDir, normalize(relative)));
    if (target !== this.assetsDir && !target.startsWith(`${this.assetsDir}/`)) {
      return this.answer(response, 403, { ok: false, error: { code: 'forbidden', message: 'path escapes assets dir' } });
    }
    let contents: Buffer;
    try {
      contents = readFileSync(target);
    } catch {
      return this.answer(response, 404, { ok: false, error: { code: 'not-found', message: 'no such asset' } });
    }
    const ext = extname(target).toLowerCase();
    const mime = STATIC_MIME[ext] ?? 'application/octet-stream';

    // Inject the bootstrap (token + api base) into index.html only. Any other file
    // is served byte-for-byte, so the token never lands in a cacheable asset.
    let payload = contents;
    if (ext === '.html') {
      const bootstrap =
        `<script>window.__DSH_MOBILE_BRIDGE__=${JSON.stringify({ token: this.token, base: `${this.basePath}/api` })};</script>`;
      const text = contents.toString('utf8');
      payload = Buffer.from(
        text.includes(BOOTSTRAP_PLACEHOLDER) ? text.replace(BOOTSTRAP_PLACEHOLDER, bootstrap) : injectHead(text, bootstrap),
        'utf8',
      );
    }
    response.writeHead(200, {
      'content-type': mime,
      'content-length': String(payload.byteLength),
      // The panel is a private control surface; nothing here should be cached,
      // sniffed, or framed.
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    });
    response.end(payload);
    return true;
  }

  // ── helpers ───────────────────────────────────────────────────────────────

  private authorized(request: IncomingMessage): boolean {
    const header = request.headers.authorization;
    const presented = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7).trim() : undefined;
    if (presented === undefined || presented.length === 0) return false;
    const a = Buffer.from(presented, 'utf8');
    const b = Buffer.from(this.token, 'utf8');
    // Length-guard before timingSafeEqual, which throws on a length mismatch.
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  private emit(response: ServerResponse, result: { status: number; body: unknown }): boolean {
    return this.answer(response, result.status, result.body);
  }

  private answer(response: ServerResponse, status: number, body: unknown): boolean {
    sendJson(response, status, body);
    return true;
  }

  private parse(request: IncomingMessage): { pathname: string; query: URLSearchParams } {
    const target = request.url ?? '/';
    const q = target.indexOf('?');
    const pathname = q === -1 ? target : target.slice(0, q);
    return { pathname, query: new URLSearchParams(q === -1 ? '' : target.slice(q + 1)) };
  }
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(payload.byteLength),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(payload);
}

/** Loopback, or no peer at all (a Unix socket is local by construction). */
export function isLoopbackPeer(remoteAddress: string | undefined): boolean {
  if (remoteAddress === undefined || remoteAddress === '') return true;
  return (
    remoteAddress === '::1' ||
    remoteAddress === '::ffff:127.0.0.1' ||
    remoteAddress.startsWith('127.')
  );
}

/** The `Host` header must name a loopback address or `localhost`. */
export function isLocalHostHeader(host: string | undefined): boolean {
  if (host === undefined || host === '') return false;
  // Strip an IPv6 bracket form `[::1]:port`, else the last `:port`.
  let name = host;
  if (name.startsWith('[')) {
    const close = name.indexOf(']');
    name = close === -1 ? name.slice(1) : name.slice(1, close);
  } else {
    const colon = name.indexOf(':');
    if (colon !== -1) name = name.slice(0, colon);
  }
  name = name.toLowerCase();
  return name === 'localhost' || name === '::1' || name === '127.0.0.1' || name.startsWith('127.');
}

function injectHead(html: string, snippet: string): string {
  const idx = html.indexOf('</head>');
  if (idx !== -1) return `${html.slice(0, idx)}${snippet}${html.slice(idx)}`;
  // No <head>: prepend so the bootstrap runs before any UI script.
  return `${snippet}${html}`;
}

function recordField(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return (value as Record<string, unknown>)[key];
}

function toBase64Url(buffer: Buffer): string {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

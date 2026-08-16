/**
 * Panel security fence + static delivery, over a REAL loopback listener.
 *
 * The four independent checks that gate the panel, each proven to fail closed:
 *   1. loopback peer      — exercised implicitly (the test client is loopback);
 *   2. local Host header   — a non-local Host is refused 403 (DNS-rebinding defense);
 *   3. bearer token        — every /api route is 401 without the exact token;
 *   4. JSON content-type   — a mutation without application/json is refused.
 * Plus: the token is injected into index.html, static files outside the assets
 * dir are refused (path traversal), and no CORS header is ever sent.
 *
 * Runs against a real `http` server via `mountPanel`, not a fake, because the
 * fence lives in how Node parses the request line, the Host header, and the peer
 * address — a stub would only assert my assumptions back at me.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ControlHandlers, ControlResponse } from '../src/control.ts';
import { mountPanel, attachPanel, type MountedPanel, type PanelRouteHost } from '../src/panel/mount.ts';
import { PANEL_TOKEN_FILE } from '../src/panel/server.ts';

const TOKEN = 'test-token-abcdefghijklmnop';

class StubHandlers implements ControlHandlers {
  status(): unknown {
    return { bridgeId: 'b', relay: { url: null, connectors: [] } };
  }
  list(): unknown {
    return [];
  }
  revoke(): { ok: boolean; message: string } {
    return { ok: true, message: 'ok' };
  }
  beginPair(_input: unknown, _emit: (m: ControlResponse) => void): { confirm(a: boolean): void; cancel(): void } {
    return { confirm: () => {}, cancel: () => {} };
  }
}

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** Raw request so we can forge Host, omit the token, and inspect headers. */
function raw(
  panel: MountedPanel,
  method: string,
  path: string,
  opts: { host?: string; token?: string | null; contentType?: string | null; body?: string } = {},
): Promise<Reply> {
  const { host, port } = panel.address;
  return new Promise<Reply>((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (opts.host !== undefined) headers.Host = opts.host;
    if (opts.token !== null && opts.token !== undefined) headers.Authorization = `Bearer ${opts.token}`;
    if (opts.contentType !== null && opts.contentType !== undefined) headers['Content-Type'] = opts.contentType;
    if (opts.body !== undefined) headers['Content-Length'] = String(Buffer.byteLength(opts.body));
    const req = httpRequest({ host, port, method, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
      );
    });
    req.on('error', reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

describe('PanelServer fence', () => {
  let dir: string;
  let assets: string;
  let stateDir: string;
  let panel: MountedPanel;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'panel-test-'));
    assets = join(dir, 'ui');
    stateDir = join(dir, 'state');
    mkdirSync(assets, { recursive: true });
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(join(assets, 'index.html'), '<html><head></head><body>panel</body></html>');
    writeFileSync(join(assets, 'panel.js'), 'console.log("ui");');
    // A secret file that path traversal would try to reach.
    writeFileSync(join(dir, 'secret.txt'), 'TOP SECRET');

    panel = mountPanel({
      bridge: { controlHandlers: new StubHandlers(), identity: fakeIdentity(), audit: fakeAudit() },
      assetsDir: assets,
      stateDir,
      token: TOKEN,
      basePath: '/mobile-bridge',
    });
    await panel.start();
  });

  afterEach(async () => {
    await panel.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes the token to the state dir at the documented path', () => {
    const written = readFileSync(join(stateDir, PANEL_TOKEN_FILE), 'utf8').trim();
    expect(written).toBe(TOKEN);
  });

  it('serves index.html with the bootstrap token injected and no-store', async () => {
    const res = await raw(panel, 'GET', '/mobile-bridge/', { host: '127.0.0.1' });
    expect(res.status).toBe(200);
    expect(res.body).toContain('__DSH_MOBILE_BRIDGE__');
    expect(res.body).toContain(TOKEN);
    expect(res.body).toContain('/mobile-bridge/api');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-frame-options']).toBe('DENY');
    // No CORS, ever.
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('injects an executable bootstrap when the shipped panel placeholder is used', async () => {
    writeFileSync(
      join(assets, 'index.html'),
      '<html><head>%%DSH_MOBILE_BRIDGE_BOOTSTRAP%%</head><body>panel</body></html>',
    );
    const res = await raw(panel, 'GET', '/mobile-bridge/', { host: '127.0.0.1' });
    expect(res.body).toContain(`<script>window.__DSH_MOBILE_BRIDGE__=`);
    expect(res.body).not.toContain(`<!--<script>window.__DSH_MOBILE_BRIDGE__=`);
    expect(res.body).not.toContain('%%DSH_MOBILE_BRIDGE_BOOTSTRAP%%');
  });

  it('serves a static asset verbatim WITHOUT injecting the token', async () => {
    const res = await raw(panel, 'GET', '/mobile-bridge/panel.js', { host: '127.0.0.1' });
    expect(res.status).toBe(200);
    expect(res.body).toBe('console.log("ui");');
    expect(res.body).not.toContain(TOKEN);
  });

  it('refuses a non-local Host header (rebinding defense)', async () => {
    const res = await raw(panel, 'GET', '/mobile-bridge/', { host: 'evil.example.com' });
    expect(res.status).toBe(403);
  });

  it('requires the bearer token on API routes', async () => {
    expect((await raw(panel, 'GET', '/mobile-bridge/api/status', { host: '127.0.0.1', token: null })).status).toBe(401);
    expect((await raw(panel, 'GET', '/mobile-bridge/api/status', { host: '127.0.0.1', token: 'wrong' })).status).toBe(401);
    expect((await raw(panel, 'GET', '/mobile-bridge/api/status', { host: '127.0.0.1', token: TOKEN })).status).toBe(200);
  });

  it('refuses path traversal out of the assets dir', async () => {
    const res = await raw(panel, 'GET', '/mobile-bridge/../secret.txt', { host: '127.0.0.1' });
    // Node normalizes ../ in the client, so also try an encoded form the server sees raw.
    expect([403, 404]).toContain(res.status);
    expect(res.body).not.toContain('TOP SECRET');
    const encoded = await raw(panel, 'GET', '/mobile-bridge/%2e%2e/secret.txt', { host: '127.0.0.1' });
    expect(encoded.body).not.toContain('TOP SECRET');
  });

  it('enforces JSON content-type on mutations (blocks form CSRF)', async () => {
    const bad = await raw(panel, 'POST', '/mobile-bridge/api/devices/revoke', {
      host: '127.0.0.1',
      token: TOKEN,
      contentType: 'application/x-www-form-urlencoded',
      body: 'deviceId=dev-1',
    });
    expect(bad.status).toBe(400);
  });

  it('routes an authorized JSON mutation to the API', async () => {
    const ok = await raw(panel, 'POST', '/mobile-bridge/api/devices/revoke', {
      host: '127.0.0.1',
      token: TOKEN,
      contentType: 'application/json',
      body: JSON.stringify({ deviceId: 'dev-1' }),
    });
    expect(ok.status).toBe(200);
  });

  it('does not answer paths outside its base', async () => {
    const res = await raw(panel, 'GET', '/somewhere-else', { host: '127.0.0.1' });
    // No listener answers → the server ends the socket; our client sees a 404-less
    // empty reply. We assert the panel did NOT serve its UI there.
    expect(res.body).not.toContain('__DSH_MOBILE_BRIDGE__');
  });
});

describe('mountPanel bind policy', () => {
  it('refuses a non-loopback bind host', () => {
    expect(() =>
      mountPanel({
        bridge: { controlHandlers: new StubHandlers(), identity: fakeIdentity(), audit: fakeAudit() },
        assetsDir: tmpdir(),
        host: '0.0.0.0',
      }),
    ).toThrow(/loopback/);
  });
});

/**
 * A stand-in for dsh's `webServer` route registry (upstream
 * `packages/host/webserver`), backed by a real loopback `http` server. It
 * reproduces the two behaviours `attachPanel` depends on: it passes the handler
 * the RAW `req`/`res` (so `req.url` keeps the `/mobile-bridge/...` prefix and the
 * peer address survives), and it dispatches by exact-then-longest-prefix match with
 * a 404 for anything unclaimed. This is the same-origin equivalent of the `raw()`
 * helper's dedicated listener — the panel's fence must hold identically on both.
 */
class FakeWebServer implements PanelRouteHost {
  private readonly exact = new Map<string, (req: IncomingMessage, res: ServerResponse) => void | Promise<void>>();
  private readonly prefixes = new Map<string, (req: IncomingMessage, res: ServerResponse) => void | Promise<void>>();
  readonly server: Server;
  registrations = 0;

  constructor() {
    this.server = createServer((req, res) => {
      const pathname = new URL(req.url ?? '/', 'http://x').pathname;
      const handler = this.match(pathname);
      if (handler === undefined) {
        res.writeHead(404);
        res.end();
        return;
      }
      void Promise.resolve(handler(req, res)).catch(() => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
      });
    });
  }

  register(route: {
    kind: 'exact' | 'prefix';
    path: string;
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
  }): () => void {
    this.registrations += 1;
    const table = route.kind === 'exact' ? this.exact : this.prefixes;
    if (table.has(route.path)) throw new Error(`duplicate ${route.kind} route "${route.path}"`);
    table.set(route.path, route.handler);
    return () => {
      table.delete(route.path);
    };
  }

  private match(pathname: string): ((req: IncomingMessage, res: ServerResponse) => void | Promise<void>) | undefined {
    const exact = this.exact.get(pathname);
    if (exact !== undefined) return exact;
    let bestPrefix: string | undefined;
    let best: ((req: IncomingMessage, res: ServerResponse) => void | Promise<void>) | undefined;
    for (const [prefix, handler] of this.prefixes) {
      if (pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue;
      if (bestPrefix === undefined || prefix.length > bestPrefix.length) {
        bestPrefix = prefix;
        best = handler;
      }
    }
    return best;
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    return (this.server.address() as AddressInfo).port;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}

/** GET/DELETE/POST/PUT against a raw loopback port (the shared dsh listener). */
function rawPort(
  port: number,
  method: string,
  path: string,
  opts: { host?: string; token?: string | null; contentType?: string | null; body?: string } = {},
): Promise<Reply> {
  return new Promise<Reply>((resolve, reject) => {
    const headers: Record<string, string> = {};
    headers.Host = opts.host ?? '127.0.0.1';
    if (opts.token !== null && opts.token !== undefined) headers.Authorization = `Bearer ${opts.token}`;
    if (opts.contentType !== null && opts.contentType !== undefined) headers['Content-Type'] = opts.contentType;
    if (opts.body !== undefined) headers['Content-Length'] = String(Buffer.byteLength(opts.body));
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
      );
    });
    req.on('error', reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

describe('attachPanel (same-origin route on dsh webserver)', () => {
  let dir: string;
  let assets: string;
  let stateDir: string;
  let web: FakeWebServer;
  let port: number;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'panel-attach-'));
    assets = join(dir, 'ui');
    stateDir = join(dir, 'state');
    mkdirSync(assets, { recursive: true });
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(join(assets, 'index.html'), '<html><head></head><body>panel</body></html>');
    web = new FakeWebServer();
    port = await web.listen();
  });

  afterEach(async () => {
    await web.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('serves the token-injected UI same-origin and enforces the bearer fence', async () => {
    const attached = attachPanel(web, {
      bridge: { controlHandlers: new StubHandlers(), identity: fakeIdentity(), audit: fakeAudit() },
      assetsDir: assets,
      stateDir,
      token: TOKEN,
    });
    expect(web.registrations).toBe(1);
    // The token lands in the state dir, exactly as on the dedicated listener.
    expect(readFileSync(join(stateDir, PANEL_TOKEN_FILE), 'utf8').trim()).toBe(TOKEN);

    // UI served at the base path, token injected.
    const index = await rawPort(port, 'GET', '/mobile-bridge/');
    expect(index.status).toBe(200);
    expect(index.body).toContain('__DSH_MOBILE_BRIDGE__');
    expect(index.body).toContain(TOKEN);

    // The fence holds on the shared listener: no token → 401, right token → 200.
    expect((await rawPort(port, 'GET', '/mobile-bridge/api/status', { token: null })).status).toBe(401);
    const ok = await rawPort(port, 'GET', '/mobile-bridge/api/status', { token: TOKEN });
    expect(ok.status).toBe(200);
    expect(ok.body).toContain('bridgeId');

    // A non-local Host is refused even though the socket is loopback (rebinding).
    expect((await rawPort(port, 'GET', '/mobile-bridge/', { host: 'evil.example.com' })).status).toBe(403);

    // The disposer removes the route: afterwards dsh answers 404 there.
    attached.dispose();
    expect((await rawPort(port, 'GET', '/mobile-bridge/')).status).toBe(404);
  });

  it('leaves dsh routes outside the base path untouched', async () => {
    attachPanel(web, {
      bridge: { controlHandlers: new StubHandlers(), identity: fakeIdentity(), audit: fakeAudit() },
      assetsDir: assets,
      stateDir,
      token: TOKEN,
    });
    // A path dsh owns but the panel does not: the panel never claims it, so the
    // FakeWebServer's own 404 answers — proving the prefix route is scoped.
    const res = await rawPort(port, 'GET', '/api/some-dsh-route');
    expect(res.status).toBe(404);
    expect(res.body).not.toContain('__DSH_MOBILE_BRIDGE__');
  });

  it('reads a POST JSON body same-origin and enforces JSON content-type', async () => {
    // A revoke that the stub reports as success, driven by a real request line +
    // JSON body through dsh's shared listener — the body-read path the dedicated
    // listener exercised is now proven on the same-origin route too.
    attachPanel(web, {
      bridge: { controlHandlers: new StubHandlers(), identity: fakeIdentity(), audit: fakeAudit() },
      assetsDir: assets,
      stateDir,
      token: TOKEN,
    });

    // No token → 401, before the body is even read.
    const noAuth = await rawPort(port, 'POST', '/mobile-bridge/api/devices/revoke', {
      token: null,
      contentType: 'application/json',
      body: JSON.stringify({ deviceId: 'dev-1' }),
    });
    expect(noAuth.status).toBe(401);

    // Wrong content-type → 400 (form CSRF cannot set application/json cross-origin).
    const wrongType = await rawPort(port, 'POST', '/mobile-bridge/api/devices/revoke', {
      token: TOKEN,
      contentType: 'application/x-www-form-urlencoded',
      body: 'deviceId=dev-1',
    });
    expect(wrongType.status).toBe(400);

    // Correct token + JSON body → routed to the API, 200 with the ok envelope.
    const ok = await rawPort(port, 'POST', '/mobile-bridge/api/devices/revoke', {
      token: TOKEN,
      contentType: 'application/json',
      body: JSON.stringify({ deviceId: 'dev-1' }),
    });
    expect(ok.status).toBe(200);
    expect(ok.body).toContain('"ok":true');
  });

  it('applies a PUT /relay mutation same-origin and reflects it on the next GET', async () => {
    // A REAL mutation end to end: PUT persists via the identity setter, and the
    // subsequent GET /relay reports it as `configured`. Uses a live identity so the
    // write is observable rather than stubbed away.
    const identity = fakeIdentity();
    attachPanel(web, {
      bridge: { controlHandlers: new StubHandlers(), identity, audit: fakeAudit() },
      assetsDir: assets,
      stateDir,
      token: TOKEN,
    });

    expect(identity.relayUrl).toBeUndefined();
    const put = await rawPort(port, 'PUT', '/mobile-bridge/api/relay', {
      token: TOKEN,
      contentType: 'application/json',
      body: JSON.stringify({ url: 'wss://relay.example/ws' }),
    });
    expect(put.status).toBe(200);
    expect(put.body).toContain('"restartRequired":true');

    // The mutation actually landed on the identity (the on-disk surface).
    expect(identity.relayUrl).toBe('wss://relay.example/ws');

    // And a fresh same-origin read sees it as the configured value.
    const get = await rawPort(port, 'GET', '/mobile-bridge/api/relay', { token: TOKEN });
    expect(get.status).toBe(200);
    expect(get.body).toContain('"configured":"wss://relay.example/ws"');
    expect(get.body).toContain('"pinned":false');

    // A malformed URL is refused (validation mirrors the CLI) and does not clobber
    // the stored value.
    const bad = await rawPort(port, 'PUT', '/mobile-bridge/api/relay', {
      token: TOKEN,
      contentType: 'application/json',
      body: JSON.stringify({ url: 'http://not-a-relay' }),
    });
    expect(bad.status).toBe(400);
    expect(identity.relayUrl).toBe('wss://relay.example/ws');
  });
});

function fakeIdentity(): { relayUrl: string | undefined; setRelayUrl(url: string | undefined): void } {
  let value: string | undefined;
  return {
    get relayUrl() {
      return value;
    },
    setRelayUrl(url: string | undefined) {
      value = url;
    },
  };
}

function fakeAudit(): { tail(count?: number): readonly never[] } {
  return { tail: () => [] };
}

/**
 * Fixture-level loader test for the `dsh-mobile-bridge` Cordis plugin.
 *
 * The real thing this guards is `plugins/dsh-bridge/src/index.ts` — the
 * workstation half that `dsh web` loads in-process. `scripts/integration-test`
 * proves it loads under a *real* `dsh web` (that is the compatibility claim),
 * but a real harness cannot run in `npm run verify`: it needs a built upstream
 * tree, pnpm, and a booted server. This test is the deterministic stand-in that
 * DOES run in CI. It exercises the plugin's actual export contract —
 * `name`, `inject`, `apply(ctx, config)` — against a hand-written `MinimalContext`
 * and the same `FakeDshServer` the rest of the suite uses, and asserts the
 * behaviour the plugin promises: it starts the bridge on its own listener, the
 * bridge reaches `dshState: connected` against the host dsh, and the `ctx.effect`
 * disposer stops it so an orphaned bridge cannot outlive the harness.
 *
 * What it deliberately does NOT do is mock `apply`. The function under test is
 * imported and run unmodified; only Cordis's `Context` is faked, because
 * `@deepseek-ai/cordis` is not — and must not become — a dependency of this repo
 * (see plugins/dsh-bridge/src/index.ts and bridge/tsconfig.json). A green run
 * here is evidence the plugin's own code is correct; it is NOT evidence that the
 * Cordis loader resolves and mounts it. That is what the integration script is
 * for, and its result is recorded in docs/DSH_PLUGIN_INTEGRATION.md.
 */

import { afterEach, describe, expect, it } from 'vitest';
import { createServer as createNetServer } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { FakeDshServer } from './fake-dsh-server.ts';
import { apply, inject, name, type Config, type MinimalContext } from '../../plugins/dsh-bridge/src/index.ts';

/** A single `/m1/health` reply, parsed. Only the fields this test asserts on. */
interface HealthReply {
  status: number;
  body: {
    ok?: boolean;
    dsh?: string;
    dshState?: string;
    bridgeVersion?: string;
    pairedDevices?: number;
  } | null;
}

/** Grab a free loopback port by binding, reading it, and releasing it. The
 * plugin logs and binds a concrete port, so this must be resolved before apply;
 * the reuse window on loopback in-process is negligible. */
async function freePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const probe = createNetServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = typeof address === 'object' && address !== null ? address.port : 0;
      probe.close(() => resolve(port));
    });
  });
}

/** One unauthenticated GET to the bridge's self-signed HTTPS listener. `/m1/health`
 * is the only route reachable without a token, which is exactly why it is the
 * liveness probe. `rejectUnauthorized: false` is scoped to this request: the
 * cert is self-signed by design and the phone pins its SPKI from the QR. */
async function health(port: number): Promise<HealthReply> {
  return await new Promise<HealthReply>((resolve, reject) => {
    const req = httpsRequest(
      { host: '127.0.0.1', port, path: '/m1/health', method: 'GET', rejectUnauthorized: false },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          try {
            resolve({ status: response.statusCode ?? 0, body: text.length === 0 ? null : JSON.parse(text) });
          } catch {
            reject(new Error(`bridge returned non-JSON (${response.statusCode ?? 0}): ${text.slice(0, 120)}`));
          }
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/** Poll `/m1/health` until `dshState` reaches `connected`, or the deadline passes.
 * The plugin's `apply` starts the bridge asynchronously inside `ctx.effect`, and
 * the dsh readiness handshake (host.describe + two event sockets) takes a beat. */
async function waitForConnected(port: number, timeoutMs = 10_000): Promise<HealthReply> {
  const deadline = Date.now() + timeoutMs;
  let last: HealthReply | undefined;
  for (;;) {
    try {
      last = await health(port);
      if (last.body?.dshState === 'connected') return last;
    } catch {
      // Listener not up yet, or mid-restart. Keep polling until the deadline.
    }
    if (Date.now() >= deadline) {
      throw new Error(`dsh never reached connected within ${timeoutMs}ms; last=${JSON.stringify(last?.body ?? null)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/** One plain-HTTP GET to the panel's loopback listener. The panel is HTTP (not
 * TLS): it never leaves loopback, so transport secrecy buys nothing and the
 * bearer token is the credential. `token` omitted means no Authorization header,
 * which is exactly how we prove the fence refuses an unauthenticated call. */
async function panelGet(port: number, path: string, token?: string): Promise<{ status: number; body: string }> {
  return panelReq(port, 'GET', path, { token });
}

/** A panel request with an optional method, bearer token, and JSON body. The panel
 * is HTTP on loopback (the token is the credential, not TLS); a JSON body + token is
 * exactly how the injected UI drives a mutation. */
async function panelReq(
  port: number,
  method: string,
  path: string,
  opts: { token?: string; body?: unknown } = {},
): Promise<{ status: number; body: string }> {
  return await new Promise((resolve, reject) => {
    const headers: Record<string, string> = { Host: '127.0.0.1' };
    if (opts.token !== undefined) headers.Authorization = `Bearer ${opts.token}`;
    let payload: string | undefined;
    if (opts.body !== undefined) {
      payload = JSON.stringify(opts.body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(Buffer.byteLength(payload));
    }
    const req = httpRequest({ host: '127.0.0.1', port, path, method, headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

/** Wrap a registered route handler in a bare loopback server so a same-origin
 * route can be probed the same way the dedicated listener is. dsh dispatches only
 * matching paths to the handler; this test only probes `/mobile-bridge/*`, so the
 * handler answers every request here — its own base-path check does the scoping. */
function createNetHttpServer(handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>): {
  server: Server;
} {
  const server = createHttpServer((req, res) => {
    void Promise.resolve(handler(req, res)).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  return { server };
}

/** A route the plugin registered on our fake `webServer` (same-origin mount path). */
interface RecordedRoute {
  kind: 'exact' | 'prefix';
  path: string;
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
}

/**
 * A hand-written stand-in for the slice of Cordis the plugin uses. It records
 * what the plugin registered so the test can drive the same disposer lifecycle
 * Cordis would: `effect(setup)` runs `setup()` synchronously and keeps its
 * returned disposer, and `logger` captures the lines the plugin emits so a
 * start failure surfaces as an assertion rather than a silent hang.
 *
 * `withRegister` toggles whether `webServer` exposes `register` — the real host
 * does, an older one does not — which is exactly the input that decides the
 * panel's mount mode (same-origin route vs. dedicated loopback listener).
 */
class FakeContext implements MinimalContext {
  readonly webServer: {
    readonly host: string;
    readonly port: number;
    register?(route: RecordedRoute): () => void;
  };
  readonly logs: { level: 'info' | 'error'; message: string }[] = [];
  readonly routes: RecordedRoute[] = [];
  private disposer: (() => void) | undefined;

  constructor(webServerPort: number, host = '127.0.0.1', opts: { withRegister?: boolean } = {}) {
    const base = { host, port: webServerPort };
    this.webServer = opts.withRegister
      ? {
          ...base,
          register: (route: RecordedRoute): (() => void) => {
            this.routes.push(route);
            return () => {
              const at = this.routes.indexOf(route);
              if (at !== -1) this.routes.splice(at, 1);
            };
          },
        }
      : base;
  }

  effect(setup: () => () => void): void {
    this.disposer = setup();
  }

  logger(namespace: string): { info(message: string): void; error(message: string): void } {
    return {
      info: (message: string) => this.logs.push({ level: 'info', message: `${namespace}: ${message}` }),
      error: (message: string) => this.logs.push({ level: 'error', message: `${namespace}: ${message}` }),
    };
  }

  /** Run the disposer Cordis would run on teardown. */
  dispose(): void {
    this.disposer?.();
  }
}

describe('dsh-mobile-bridge plugin (fixture-level loader)', () => {
  let dsh: FakeDshServer | undefined;
  let ctx: FakeContext | undefined;
  let stateDir: string | undefined;

  afterEach(async () => {
    ctx?.dispose();
    // Give the async disposer a tick to close the listener before the next test.
    await new Promise((resolve) => setTimeout(resolve, 50));
    await dsh?.close();
    if (stateDir !== undefined) rmSync(stateDir, { recursive: true, force: true });
    dsh = undefined;
    ctx = undefined;
    stateDir = undefined;
  });

  it('exports the Cordis plugin contract the loader mounts by', () => {
    // The loader keys on these three. `name` is the row's stable id; `inject`
    // makes webServer a hard prerequisite so apply never reads an unbound bind.
    expect(name).toBe('mobile-bridge');
    expect(inject).toEqual(['webServer']);
    expect(typeof apply).toBe('function');
  });

  it('starts the bridge against the host dsh and reaches dshState: connected', async () => {
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    stateDir = mkdtempSync(join(tmpdir(), 'dsh-plugin-loader-'));
    const port = await freePort();

    ctx = new FakeContext(dshPort);
    const config: Config = { stateDir, host: '127.0.0.1', port, certHosts: ['localhost', '127.0.0.1'], panelPort: 0 };

    // The function under test, run exactly as Cordis runs it.
    apply(ctx, config);

    const reply = await waitForConnected(port);
    expect(reply.status).toBe(200);
    expect(reply.body?.ok).toBe(true);
    expect(reply.body?.dsh).toBe('up');
    expect(reply.body?.dshState).toBe('connected');
    // A freshly loaded bridge has served nobody yet.
    expect(reply.body?.pairedDevices).toBe(0);

    // The plugin logs the listener it brought up; a start failure would have
    // logged at error and left health unreachable, so this is a redundant but
    // cheap check that the success path — not the catch — is what ran.
    expect(ctx.logs.some((line) => line.level === 'info' && /listening on/.test(line.message))).toBe(true);
    expect(ctx.logs.some((line) => line.level === 'error')).toBe(false);
  });

  it('normalizes a 0.0.0.0 host dsh bind to loopback for its outbound calls', async () => {
    // dsh may serve the LAN on 0.0.0.0, but 0.0.0.0 is not a destination. The
    // plugin must dial dsh over loopback regardless, or the bridge could never
    // reach a host that is genuinely all-interfaces. We prove it by binding the
    // fake dsh to loopback and telling the plugin the bind is 0.0.0.0: if it did
    // not rewrite, the connection would fail and health would never connect.
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    stateDir = mkdtempSync(join(tmpdir(), 'dsh-plugin-loader-'));
    const port = await freePort();

    ctx = new FakeContext(dshPort, '0.0.0.0');
    apply(ctx, { stateDir, host: '127.0.0.1', port, certHosts: ['localhost', '127.0.0.1'], panelPort: 0 });

    const reply = await waitForConnected(port);
    expect(reply.body?.dshState).toBe('connected');
  });

  it('stops the bridge when Cordis disposes the effect', async () => {
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    stateDir = mkdtempSync(join(tmpdir(), 'dsh-plugin-loader-'));
    const port = await freePort();

    ctx = new FakeContext(dshPort);
    apply(ctx, { stateDir, host: '127.0.0.1', port, certHosts: ['localhost', '127.0.0.1'], panelPort: 0 });
    await waitForConnected(port);

    // The disposer is the whole reason the bridge cannot outlive dsh. Run it and
    // confirm the listener is actually gone — a health call must now fail to
    // connect rather than answer.
    ctx.dispose();

    const deadline = Date.now() + 5_000;
    let stopped = false;
    while (Date.now() < deadline) {
      try {
        await health(port);
      } catch {
        stopped = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(stopped).toBe(true);
  });

  it('starts the loopback management panel and enforces its bearer fence', async () => {
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    stateDir = mkdtempSync(join(tmpdir(), 'dsh-plugin-loader-'));
    const port = await freePort();
    const panelPort = await freePort();

    ctx = new FakeContext(dshPort);
    apply(ctx, { stateDir, host: '127.0.0.1', port, certHosts: ['localhost', '127.0.0.1'], panelPort });
    await waitForConnected(port);

    // The plugin logs the panel URL on success; wait for it so we probe only once
    // the listener is actually up (apply mounts the panel asynchronously).
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && !ctx.logs.some((l) => /management panel on/.test(l.message))) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(ctx.logs.some((l) => l.level === 'info' && /management panel on/.test(l.message))).toBe(true);
    expect(ctx.logs.some((l) => l.level === 'error')).toBe(false);

    // The token the plugin wrote to the state dir. The injected UI carries it too,
    // but the fence is what we are proving: the same token unlocks the API, its
    // absence does not.
    const token = readFileSync(join(stateDir, 'panel-token'), 'utf8').trim();
    expect(token.length).toBeGreaterThan(0);

    // UI served, with the bootstrap token injected.
    const index = await panelGet(panelPort, '/mobile-bridge/');
    expect(index.status).toBe(200);
    expect(index.body).toContain('__DSH_MOBILE_BRIDGE__');
    expect(index.body).toContain(token);

    // API refused without the token, served with it.
    const noAuth = await panelGet(panelPort, '/mobile-bridge/api/status');
    expect(noAuth.status).toBe(401);
    const withAuth = await panelGet(panelPort, '/mobile-bridge/api/status', token);
    expect(withAuth.status).toBe(200);
    expect(withAuth.body).toContain('bridgeId');
  });

  it('mounts the panel same-origin on dsh webserver when register is available and dsh is loopback', async () => {
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    stateDir = mkdtempSync(join(tmpdir(), 'dsh-plugin-loader-'));
    const port = await freePort();
    // A real port, but the same-origin branch must NOT bind a dedicated listener on
    // it — we assert that below by confirming the plugin registered a route instead.
    const panelPort = await freePort();

    // Loopback-bound dsh that exposes `register`: the supported client-injection
    // path. The plugin should ride dsh's own webserver rather than open a listener.
    ctx = new FakeContext(dshPort, '127.0.0.1', { withRegister: true });
    apply(ctx, { stateDir, host: '127.0.0.1', port, certHosts: ['localhost', '127.0.0.1'], panelPort });
    await waitForConnected(port);

    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && !ctx.logs.some((l) => /management panel \(same-origin\)/.test(l.message))) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    // Took the same-origin branch: logged it, registered exactly one prefix route
    // at the documented base path, and hit no error.
    expect(ctx.logs.some((l) => l.level === 'info' && /management panel \(same-origin\)/.test(l.message))).toBe(true);
    expect(ctx.logs.some((l) => l.level === 'error')).toBe(false);
    expect(ctx.routes.length).toBe(1);
    expect(ctx.routes[0]?.kind).toBe('prefix');
    expect(ctx.routes[0]?.path).toBe('/mobile-bridge');

    // The token was still written to the state dir (same contract as the listener).
    const token = readFileSync(join(stateDir, 'panel-token'), 'utf8').trim();
    expect(token.length).toBeGreaterThan(0);

    // No dedicated listener came up on panelPort — a probe there is refused.
    let refused = false;
    try {
      await panelGet(panelPort, '/mobile-bridge/');
    } catch {
      refused = true;
    }
    expect(refused).toBe(true);

    // The registered handler is the real fence: serve it from a throwaway loopback
    // server (standing in for dsh's shared listener) and prove token-gating holds.
    const handler = ctx.routes[0]!.handler;
    const probe = createNetHttpServer(handler);
    const probePort = await new Promise<number>((resolve) => {
      probe.server.listen(0, '127.0.0.1', () => resolve((probe.server.address() as { port: number }).port));
    });
    try {
      const index = await panelGet(probePort, '/mobile-bridge/');
      expect(index.status).toBe(200);
      expect(index.body).toContain('__DSH_MOBILE_BRIDGE__');
      expect(index.body).toContain(token);
      expect((await panelGet(probePort, '/mobile-bridge/api/status')).status).toBe(401);
      const ok = await panelGet(probePort, '/mobile-bridge/api/status', token);
      expect(ok.status).toBe(200);
      expect(ok.body).toContain('bridgeId');
    } finally {
      await new Promise<void>((resolve) => probe.server.close(() => resolve()));
    }
  });

  it('reports a config-pinned relay as externally managed and refuses panel edits', async () => {
    // A relay set through plugin config is a PIN: it overrides any panel-saved value
    // at every start. The panel must SAY so (status.relay.pinned/source) and REFUSE
    // to write a value that could never take effect (409), rather than promise a
    // restart it cannot honor. This proves the wiring end to end through `apply`:
    // config.relayUrl → BuildOptions.relaySource → status → PanelApi.
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    stateDir = mkdtempSync(join(tmpdir(), 'dsh-plugin-loader-'));
    const port = await freePort();
    const panelPort = await freePort();

    // A dedicated listener (no register), loopback: keeps the probe simple. The
    // relay is a wss URL the bridge never actually dials — no paired devices, so no
    // connector starts — so pinning it has no network effect here.
    ctx = new FakeContext(dshPort);
    apply(ctx, {
      stateDir,
      host: '127.0.0.1',
      port,
      certHosts: ['localhost', '127.0.0.1'],
      panelPort,
      relayUrl: 'wss://pinned.example/ws',
    });
    await waitForConnected(port);

    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && !ctx.logs.some((l) => /management panel on/.test(l.message))) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const token = readFileSync(join(stateDir, 'panel-token'), 'utf8').trim();

    // status shows the pin; source is `config` (the value did not come from the env
    // var this test never set).
    const status = await panelGet(panelPort, '/mobile-bridge/api/status', token);
    expect(status.status).toBe(200);
    const relay = (JSON.parse(status.body) as { value: { relay: Record<string, unknown> } }).value.relay;
    expect(relay.pinned).toBe(true);
    expect(relay.source).toBe('config');
    expect(relay.active).toBe('wss://pinned.example/ws');
    expect(relay.restartRequired).toBe(false);

    // A PUT is refused with 409 — the panel cannot override the pin.
    const put = await panelReq(panelPort, 'PUT', '/mobile-bridge/api/relay', {
      token,
      body: { url: 'wss://operator.example/ws' },
    });
    expect(put.status).toBe(409);
    expect(put.body).toMatch(/managed externally/);

    // And so is a DELETE.
    const del = await panelReq(panelPort, 'DELETE', '/mobile-bridge/api/relay', { token });
    expect(del.status).toBe(409);
  });
});

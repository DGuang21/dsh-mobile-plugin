/**
 * [OUR DESIGN] Two ways to mount the management panel, one shared fence.
 *
 * SAME-ORIGIN ROUTE ({@link attachPanel}) is the default when dsh is loopback-bound:
 * the panel rides dsh's own webserver via the supported `webServer.register` route
 * API (upstream `packages/host/webserver`), living at `<dsh-origin>/mobile-bridge/`.
 * This is the real, in-contract client-injection path for an out-of-tree plugin —
 * no dsh source change, no allowlist — so an operator finds the panel exactly where
 * it belongs relative to the dsh web UI.
 *
 * DEDICATED LOOPBACK LISTENER ({@link mountPanel}) is used when dsh binds the LAN
 * (0.0.0.0): a second `http` server on 127.0.0.1 keeps the panel not-even-TCP-
 * reachable from another host by construction, so the panel is never served from a
 * listener the operator has exposed.
 *
 * WHY THE CHOICE IS SAFE EITHER WAY. dsh's webserver trust fence is a reachability
 * policy, not authentication — which is why the *phone* surface must never ride it.
 * The panel is different, and *more* privileged (it mints access, revokes devices,
 * opens pairing): it enforces four independent checks (loopback peer, local Host,
 * bearer token, JSON content-type) that do not depend on dsh's model at all. On the
 * same-origin route a LAN client that reaches the path because dsh bound 0.0.0.0 is
 * refused 403 at check #1 before any handler runs and never sees the token; on the
 * dedicated listener that client cannot open the socket in the first place. The
 * plugin picks the stronger option automatically from dsh's bind.
 *
 * Neither listener is TLS: loopback traffic never leaves the machine, so there is no
 * network path to eavesdrop, and pinning a second self-signed cert in a browser
 * would only train the operator to click through cert warnings. The bearer token —
 * not transport secrecy — is the credential, and it never crosses a wire that
 * leaves the host.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { join } from 'node:path';
import type { ControlHandlers } from '../control.ts';
import { PanelApi, type PanelIdentity, type PanelAudit } from './api.ts';
import { PanelServer, PANEL_TOKEN_FILE, DEFAULT_PANEL_BASE } from './server.ts';

/**
 * The bridge surface the panel needs, as narrow structural types.
 *
 * The real `BuiltBridge` satisfies this by construction (`identity` is an
 * `IdentityStore`, `audit` an `AuditLog`), but stating the minimum here keeps the
 * panel honest about what it touches and lets tests supply tiny fakes rather than
 * whole classes.
 */
export interface PanelBridge {
  controlHandlers: ControlHandlers;
  identity: PanelIdentity;
  audit: PanelAudit;
}

export interface MountPanelOptions {
  /** The running bridge whose control surface the panel drives. */
  bridge: PanelBridge;
  /** Static UI assets directory (the plugin's `panel-ui/`). */
  assetsDir: string;
  /**
   * State dir. The panel token is written to `<stateDir>/panel-token` at 0600 so
   * same-user tooling (and the operator) can read it. Omit to keep the token in
   * memory only (tests pass an explicit token instead).
   */
  stateDir?: string;
  /**
   * Loopback interface to bind. Defaults to `127.0.0.1`. A non-loopback host is
   * REFUSED: the panel's entire model is that it is unreachable off-box.
   */
  host?: string;
  /** Port. Defaults to `0` (ephemeral) so it never collides with dsh. */
  port?: number;
  /** Route prefix. Defaults to {@link DEFAULT_PANEL_BASE}. */
  basePath?: string;
  /** Override the token (tests). Otherwise a per-boot random token is minted. */
  token?: string;
}

export interface MountedPanel {
  /** The full URL an operator opens, including the base path. */
  url: string;
  /** The bearer token the injected UI uses. Also written to the state dir. */
  token: string;
  address: { host: string; port: number };
  server: PanelServer;
  api: PanelApi;
  start(): Promise<void>;
  stop(): Promise<void>;
}

function isLoopbackBind(host: string): boolean {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost' || host.startsWith('127.');
}

/**
 * The slice of dsh's `webServer` service the panel needs to mount same-origin.
 *
 * A structural subset of the real service (packages/host/webserver): `register`
 * with `kind: 'prefix'` claims `path` and everything under `path/`, and returns a
 * disposer. Stated locally so this module never imports the harness.
 */
export interface PanelRouteHost {
  register(route: {
    kind: 'exact' | 'prefix';
    path: string;
    handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
  }): () => void;
}

export interface AttachPanelOptions {
  bridge: PanelBridge;
  assetsDir: string;
  stateDir?: string;
  basePath?: string;
  token?: string;
}

export interface AttachedPanel {
  token: string;
  basePath: string;
  server: PanelServer;
  api: PanelApi;
  /** Remove the route. Call from the plugin's effect disposer. */
  dispose(): void;
}

/**
 * Mount the panel SAME-ORIGIN on dsh's own webserver, via the supported
 * `webServer.register` route API (upstream `packages/host/webserver`). This is the
 * real client-injection contract for an out-of-tree plugin — no dsh source change,
 * no allowlist — so the panel lives at `<dsh-origin>/mobile-bridge/`, exactly where
 * an operator expects to find it relative to the dsh web UI.
 *
 * SAFE ONLY BECAUSE THE PANEL CARRIES ITS OWN FENCE. dsh's webserver trust model
 * is a reachability policy, not authentication — which is why the *phone* surface
 * must never ride it. The panel is different: it enforces four independent checks
 * (loopback peer, local Host, bearer token, JSON content-type) that do not depend
 * on dsh's model at all. A LAN client that reaches this route because dsh bound
 * 0.0.0.0 is refused 403 at check #1 before any handler runs, and never receives
 * the bootstrap token. Callers that want the panel to be not-even-TCP-reachable on
 * a LAN-bound dsh should use {@link mountPanel} (a dedicated 127.0.0.1 listener)
 * instead; the plugin picks between the two by dsh's bind.
 */
export function attachPanel(host: PanelRouteHost, options: AttachPanelOptions): AttachedPanel {
  const basePath = (options.basePath ?? DEFAULT_PANEL_BASE).replace(/\/$/, '');

  const api = new PanelApi({
    handlers: options.bridge.controlHandlers,
    identity: options.bridge.identity,
    audit: options.bridge.audit,
  });
  const server = new PanelServer({
    api,
    assetsDir: options.assetsDir,
    ...(options.token === undefined ? {} : { token: options.token }),
    ...(options.stateDir === undefined ? {} : { tokenFile: join(options.stateDir, PANEL_TOKEN_FILE) }),
    basePath,
  });

  const dispose = host.register({
    kind: 'prefix',
    path: basePath,
    handler: async (req: IncomingMessage, res: ServerResponse) => {
      const handled = await server.handle(req, res);
      // dsh's prefix match guarantees the path is ours, so `handled` is effectively
      // always true; the guard is defensive against a future match change.
      if (!handled && !res.headersSent) {
        const payload = Buffer.from(JSON.stringify({ ok: false, error: { code: 'not-found', message: 'not found' } }), 'utf8');
        res.writeHead(404, { 'content-type': 'application/json; charset=utf-8', 'content-length': String(payload.byteLength), 'cache-control': 'no-store' });
        res.end(payload);
      }
    },
  });

  return { token: server.token, basePath, server, api, dispose };
}

/**
 * Build (but do not yet start) a panel on its own loopback listener.
 *
 * Returns handles to `start()`/`stop()` the listener. The caller — the plugin's
 * `ctx.effect`, or a test — owns the lifecycle so the panel dies with whatever
 * started it.
 */
export function mountPanel(options: MountPanelOptions): MountedPanel {
  const host = options.host ?? '127.0.0.1';
  if (!isLoopbackBind(host)) {
    // Fail loud rather than silently binding the control surface to the LAN. The
    // handler would refuse LAN peers anyway, but advertising the port at all is a
    // footgun we decline to hand the operator.
    throw new Error(`panel host must be loopback; refusing to bind ${host}`);
  }
  const port = options.port ?? 0;
  const basePath = (options.basePath ?? DEFAULT_PANEL_BASE).replace(/\/$/, '');

  const api = new PanelApi({
    handlers: options.bridge.controlHandlers,
    identity: options.bridge.identity,
    audit: options.bridge.audit,
  });

  const server = new PanelServer({
    api,
    assetsDir: options.assetsDir,
    ...(options.token === undefined ? {} : { token: options.token }),
    ...(options.stateDir === undefined ? {} : { tokenFile: join(options.stateDir, PANEL_TOKEN_FILE) }),
    basePath,
  });

  const httpServer: Server = createServer();
  // A DEDICATED listener owns every path, so an unmatched one must get a clean 404
  // rather than hang forever waiting for another listener that will never exist.
  // (`attach()` is for the shared-server case, where non-panel paths belong to
  // someone else and must be left untouched.)
  httpServer.on('request', (request, response) => {
    void server.handle(request, response).then((handled) => {
      if (!handled && !response.headersSent) {
        const payload = Buffer.from(JSON.stringify({ ok: false, error: { code: 'not-found', message: 'not found' } }), 'utf8');
        response.writeHead(404, {
          'content-type': 'application/json; charset=utf-8',
          'content-length': String(payload.byteLength),
          'cache-control': 'no-store',
        });
        response.end(payload);
      }
    });
  });

  let boundPort = port;

  const start = (): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      httpServer.once('error', reject);
      httpServer.listen(port, host, () => {
        httpServer.removeListener('error', reject);
        const address = httpServer.address();
        if (address !== null && typeof address === 'object') boundPort = address.port;
        resolve();
      });
    });

  const stop = (): Promise<void> => new Promise<void>((resolve) => httpServer.close(() => resolve()));

  return {
    get url() {
      return `http://${host === '::1' ? '[::1]' : host}:${boundPort}${basePath}/`;
    },
    token: server.token,
    get address() {
      return { host, port: boundPort };
    },
    server,
    api,
    start,
    stop,
  };
}

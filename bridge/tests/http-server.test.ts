/**
 * `BridgeServer` routing and upgrade refusals.
 *
 * Plain HTTP rather than the TLS listener `buildBridge` creates: this file is about
 * dispatch, not transport, and an unencrypted loopback listener lets it use `fetch`
 * directly instead of threading a self-signed-certificate exception through every
 * call. TLS itself is covered by tls.test.ts, and the full TLS-plus-identity stack
 * by bridge-e2e.test.ts.
 *
 * `BridgeServer.attach` makes this legitimate rather than a shortcut: the server is
 * designed to serve the same routes on a second listener (the relay carrier), so
 * "these routes on an arbitrary `Server`" is a supported configuration and not a
 * test-only arrangement.
 *
 * [NOT INTEGRATION-TESTED] Nothing here involves a real phone or a real dsh. The
 * upstream side is the in-repo fake, so a green run says the bridge is
 * self-consistent, not that it is compatible with a real harness.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { connect as netConnect, type AddressInfo } from 'node:net';
import { AuditLog } from '../src/audit/log.ts';
import { AuthService } from '../src/auth/tokens.ts';
import { DshApiClient } from '../src/dsh/client.ts';
import { DshConnection } from '../src/dsh/connection.ts';
import { DshDownlink } from '../src/dsh/downlink.ts';
import { BridgeServer } from '../src/http/server.ts';
import { DeviceRegistry } from '../src/identity/registry.ts';
import { PairingManager } from '../src/identity/pairing.ts';
import { StreamHub } from '../src/stream/hub.ts';
import { M1_PATHS, M1_STREAM_SUBPROTOCOL, M1_TOKEN_SUBPROTOCOL_PREFIX } from '../src/m1/wire.ts';
import { FakeDshServer, type FakeDshServerOptions } from './fake-dsh-server.ts';
import { ClientWebSocket, clientHandshakeRequest, readClientHandshake } from '../src/http/websocket.ts';
import { randomBytes } from 'node:crypto';
import { generateEd25519KeyPair, signMessage, toBase64Url } from '../src/identity/crypto.ts';
import { pairingProofMessage } from '../src/identity/pairing.ts';
import { authProofMessage } from '../src/auth/tokens.ts';

const BRIDGE_ID = 'bridge-test-id';

interface Harness {
  url: string;
  server: Server;
  bridge: BridgeServer;
  hub: StreamHub;
  registry: DeviceRegistry;
  auth: AuthService;
  pairing: PairingManager;
  audit: AuditLog;
  dsh: FakeDshServer;
  connection: DshConnection;
  stop(): Promise<void>;
}

/** Poll until `check` passes, so no test depends on a fixed sleep. */
async function until(check: () => boolean, label: string, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/** A bridge wired to a real fake-dsh, listening on loopback HTTP. */
async function startHarness(options: { connectDsh?: boolean; dsh?: FakeDshServerOptions } = {}): Promise<Harness> {
  const dsh = new FakeDshServer(options.dsh);
  await dsh.listen();

  const hub = new StreamHub();
  const client = new DshApiClient({ baseUrl: dsh.baseUrl });
  const downlink = new DshDownlink({ baseUrl: dsh.baseUrl });
  const connection = new DshConnection({
    client,
    downlink,
    sinks: {
      onConnected: () => hub.onDshReady(),
      onDisconnected: (reason) => hub.onDshDisconnected(reason),
      onMuxFrame: (envelope) => hub.ingestMux(envelope),
      onHostFrame: (envelope) => hub.ingestHost(envelope),
    },
  });
  const registry = DeviceRegistry.inMemory();
  const auth = new AuthService({ registry, bridgeId: BRIDGE_ID });
  const pairing = new PairingManager({
    registry,
    bridgeId: BRIDGE_ID,
    bridgeName: 'test bridge',
    isDshReachable: () => connection.getState() === 'connected',
  });

  const audit = new AuditLog();
  const server = createServer();
  const bridge = new BridgeServer({
    server,
    client,
    connection,
    hub,
    registry,
    auth,
    pairing,
    audit,
    bridgeId: BRIDGE_ID,
    bridgeName: 'test bridge',
    bridgeVersion: '0.0.0-test',
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  if (options.connectDsh !== false) {
    // `start()` is synchronous and only launches the reconnect loop, so awaiting it
    // proves nothing: readiness needs both downlinks open and `host.describe` to
    // have answered. Without this wait, pairing is refused as `dsh-unavailable`
    // because PairingManager checks reachability — which is the behaviour working
    // correctly, not a flake to sleep past.
    connection.start();
    await until(() => connection.getState() === 'connected', 'dsh connection');
  }

  return {
    url: `http://127.0.0.1:${port}`,
    server,
    bridge,
    hub,
    registry,
    auth,
    pairing,
    audit,
    dsh,
    connection,
    async stop() {
      bridge.closeSockets('test over');
      await connection.stop();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await dsh.close();
    },
  };
}

let harness: Harness;

beforeEach(async () => {
  harness = await startHarness();
});

afterEach(async () => {
  await harness.stop();
});

/**
 * Pair a device and return a usable access token.
 *
 * `target` defaults to the per-test harness. It is a parameter because one test
 * starts a second bridge with a different upstream receipt, and pairing against it
 * must go through the same code path rather than a shortcut that skips proofs.
 */
async function pairDevice(
  target: Harness = harness,
  tier: 'default' | 'extended' = 'default',
): Promise<{ deviceId: string; token: string }> {
  const device = generateEd25519KeyPair();
  const pairSession = target.pairing.begin();
  const proof = toBase64Url(signMessage(device.privateKey, pairingProofMessage(pairSession.token, BRIDGE_ID)));
  const body = JSON.stringify({ token: pairSession.token, devicePublicKey: device.publicKeyB64, label: 'phone', proof });
  const headers = { 'content-type': 'application/json' };

  // First claim spends the token and yields the SAS; the operator's confirm happens
  // out of band; the re-POST is a proof-authenticated read of the decision.
  await fetch(`${target.url}${M1_PATHS.pairClaim}`, { method: 'POST', headers, body });
  if (target.pairing.confirm({ tier }) === undefined) throw new Error('confirm did not register a device');
  const claimed = await (await fetch(`${target.url}${M1_PATHS.pairClaim}`, { method: 'POST', headers, body })).json();
  if (claimed.ok !== true) throw new Error(`pair claim failed in test setup: ${JSON.stringify(claimed)}`);
  const deviceId = claimed.value.deviceId as string;

  const nonceReply = await (await fetch(`${target.url}${M1_PATHS.authSession}`, { method: 'POST', headers, body: JSON.stringify({ deviceId }) })).json();
  if (nonceReply.ok !== true) throw new Error(`auth challenge failed in test setup: ${JSON.stringify(nonceReply)}`);
  const nonce = nonceReply.value.nonce as string;
  // `signature`, and over the domain-separated auth message — not the raw nonce.
  // The purpose string is what stops a pairing proof being replayed here.
  const signature = toBase64Url(signMessage(device.privateKey, authProofMessage(nonce, deviceId, BRIDGE_ID)));
  const session = await (
    await fetch(`${target.url}${M1_PATHS.authSession}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ deviceId, nonce, signature }),
    })
  ).json();
  if (session.ok !== true) throw new Error(`auth failed in test setup: ${JSON.stringify(session)}`);
  return { deviceId, token: session.value.token as string };
}

/** GET/POST helper that returns status and parsed body together. */
async function call(
  path: string,
  init: { method?: string; token?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: any; headers: Headers }> {
  const headers: Record<string, string> = { ...init.headers };
  if (init.body !== undefined) headers['content-type'] ??= 'application/json';
  if (init.token !== undefined) headers.authorization = `Bearer ${init.token}`;
  const response = await fetch(`${harness.url}${path}`, {
    method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
    headers,
    ...(init.body === undefined ? {} : { body: typeof init.body === 'string' ? init.body : JSON.stringify(init.body) }),
  });
  const text = await response.text();
  return { status: response.status, body: text.length > 0 ? JSON.parse(text) : undefined, headers: response.headers };
}

/**
 * Send a request line verbatim and return the status.
 *
 * Written at the socket level because every HTTP client worth using normalises the
 * request target, and normalisation is exactly what must not happen for a test
 * about unnormalised paths to mean anything.
 */
function rawRequestStatus(target: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const url = new URL(harness.url);
    const socket = netConnect({ host: url.hostname, port: Number(url.port) }, () => {
      socket.write(`GET ${target} HTTP/1.1\r\nHost: ${url.host}\r\nConnection: close\r\n\r\n`);
    });
    const chunks: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('close', () => {
      const status = Number(Buffer.concat(chunks).toString('latin1').split(' ')[1] ?? 0);
      resolve(status);
    });
  });
}

describe('routing', () => {
  it('answers health without a credential', async () => {
    // The one route a phone can call before it holds anything: it needs to tell
    // "bridge down" from "harness down" while deciding what to render.
    const reply = await call(M1_PATHS.health);
    expect(reply.status).toBe(200);
    expect(reply.body).toMatchObject({ ok: true, bridgeId: BRIDGE_ID, dsh: 'up', dshState: 'connected' });
  });

  it('says nothing about what routes exist on an unknown path', async () => {
    // Uninformative on purpose. This is not a discoverable API, and a 404 that
    // distinguishes "no such route" from "route exists but needs auth" is a map.
    for (const path of ['/', '/m1', '/m1/', '/admin', '/m1/devices', '/.well-known/x']) {
      const reply = await call(path);
      expect([path, reply.status]).toEqual([path, 404]);
      expect(reply.body).toEqual({ ok: false, error: { code: 'bad-request', message: 'not found' } });
    }
  });

  it('does not treat a path with a traversal segment as its target route', async () => {
    // Raw sockets, not `fetch`. `fetch` resolves `/m1/../m1/health` to `/m1/health`
    // before it ever reaches the wire, so routing this through it would assert
    // nothing about the router — it would test undici's URL normalisation and pass
    // for the wrong reason. The bridge does no normalisation of its own, and the
    // point of this test is that such paths therefore match no route at all.
    for (const target of ['/m1/../m1/health', '/m1/./health', '//m1/health', '/m1//health', '/M1/health', '/m1/health/', '/m1%2Fhealth']) {
      const status = await rawRequestStatus(target);
      expect([target, status]).toEqual([target, 404]);
    }
  });

  it('rejects a known path with the wrong verb, distinguishably from unknown', async () => {
    // 405 rather than 404 here is a deliberate exception to the silence above: the
    // caller already proved it knows the route, so hiding it buys nothing and a
    // clear answer saves a debugging session.
    const wrongVerb = await call(M1_PATHS.rpc, { method: 'GET' });
    expect(wrongVerb.status).toBe(405);
    expect(wrongVerb.body.error.message).toContain('not allowed');

    const healthPost = await call(M1_PATHS.health, { method: 'POST', body: {} });
    expect(healthPost.status).toBe(405);
  });

  it.each([M1_PATHS.pairClaim, M1_PATHS.authSession])(
    'refuses %s with a non-JSON content-type',
    async (path) => {
      // The CSRF control, checked on the two routes that read a body before
      // authorizing: a browser form cannot set application/json cross-origin, so
      // neither is reachable from a page the user happens to visit.
      const reply = await call(path, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' });
      expect(reply.status).toBe(400);
      expect(reply.body.error.message).toContain('content-type');
    },
  );

  it.each([M1_PATHS.rpc, M1_PATHS.respond])('authorizes %s before it looks at the body', async (path) => {
    // 401, not 400. These routes check the bearer token first, so an unauthenticated
    // caller learns nothing about the body schema — not even that its content-type
    // was wrong. The CSRF property still holds here for a different reason: a form
    // post carries no Authorization header either.
    const reply = await call(path, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' });
    expect(reply.status).toBe(401);
    expect(reply.body.error.code).toBe('unauthenticated');
  });

  it('refuses an authenticated request with a non-JSON content-type', async () => {
    const { token } = await pairDevice();
    const reply = await call(M1_PATHS.rpc, { token, method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' });
    expect(reply.status).toBe(400);
    expect(reply.body.error.message).toContain('content-type');
  });

  it('answers a plain GET on the stream path with 426', async () => {
    // A client that forgot to upgrade gets told exactly that, rather than a generic
    // 400 it would have to guess about. Mirrors how dsh answers its own event paths.
    const reply = await call(M1_PATHS.stream);
    expect(reply.status).toBe(426);
    expect(reply.body.error.message).toContain('WebSocket upgrade');
  });

  it('sets no-store and nosniff on every route, including errors', async () => {
    for (const path of [M1_PATHS.health, '/nope', M1_PATHS.stream]) {
      const reply = await call(path);
      expect([path, reply.headers.get('cache-control')]).toEqual([path, 'no-store']);
      expect([path, reply.headers.get('x-content-type-options')]).toEqual([path, 'nosniff']);
      expect(reply.headers.get('access-control-allow-origin')).toBeNull();
    }
  });
});

describe('authorization on /m1/rpc', () => {
  it('refuses a missing, malformed, or unknown bearer token', async () => {
    const cases: [string, Record<string, string>][] = [
      ['no header', {}],
      ['empty bearer', { authorization: 'Bearer ' }],
      ['wrong scheme', { authorization: 'Basic abc' }],
      ['unknown token', { authorization: 'Bearer not-a-real-token' }],
      ['token as raw value', { authorization: 'abcdef' }],
    ];
    for (const [label, headers] of cases) {
      const reply = await call(M1_PATHS.rpc, { method: 'POST', headers, body: { method: 'session.list', payload: {} } });
      expect([label, reply.status]).toEqual([label, 401]);
      expect([label, reply.body.error.code]).toEqual([label, 'unauthenticated']);
    }
  });

  it('forwards an allowed method and unwraps the dsh envelope', async () => {
    // The phone never sees dsh's `{type:'server-response', result:{ok}}` shape, and
    // that is the point of the bridge's `value` field: dsh reports business errors as
    // HTTP 200, which is a trap for a naive client.
    const { token } = await pairDevice();
    const reply = await call(M1_PATHS.rpc, { token, body: { method: 'session.list', payload: {} } });
    expect(reply.status).toBe(200);
    expect(reply.body).toMatchObject({ ok: true, value: { sessions: [] } });
    expect(reply.body.value.type).toBeUndefined();
  });

  it('denies a privileged method before it reaches dsh', async () => {
    // `settings.update` is on the deny list, so the fake upstream must never see it.
    // Checking the upstream call count is the assertion that matters: a 403 that
    // still forwarded would be a policy hole that looks closed.
    const { token } = await pairDevice(harness, 'extended');
    const before = harness.dsh.calls.length;
    const reply = await call(M1_PATHS.rpc, { token, body: { method: 'settings.update', payload: {} } });
    expect(reply.status).toBe(403);
    expect(reply.body.error.code).toBe('method-denied');
    expect(harness.dsh.calls.length).toBe(before);
  });

  it('distinguishes an unknown method from a denied one', async () => {
    // 400 for unknown, 403 for denied, and the difference is deliberate: a typo is a
    // client bug the phone should surface as such, while a denial is a policy
    // decision the user may need explained. Collapsing them would make every
    // misspelled method look like a permissions problem.
    const { token } = await pairDevice(harness, 'extended');
    const unknown = await call(M1_PATHS.rpc, { token, body: { method: 'not.a.method', payload: {} } });
    expect(unknown.status).toBe(400);
    expect(unknown.body.error.message).toContain('not a method this bridge knows');

    const denied = await call(M1_PATHS.rpc, { token, body: { method: 'settings.update', payload: {} } });
    expect(denied.status).toBe(403);
    expect(denied.body.error.code).toBe('method-denied');
  });

  it('refuses to forward `respond` through the generic route', async () => {
    // `respond` must go through /m1/respond, which checks the rpcId against frames
    // this bridge actually delivered. Reaching it here would let a phone answer an
    // arbitrary rpcId — including an approval raised for a different client.
    const { token } = await pairDevice();
    const reply = await call(M1_PATHS.rpc, { token, body: { method: 'respond', payload: { rpcId: 'x' } } });
    expect(reply.status).toBe(400);
    expect(reply.body.error.message).toContain('/m1/respond');
    expect(harness.dsh.calls.some((entry) => entry.method === 'respond')).toBe(false);
  });

  it('requires a method field', async () => {
    const { token } = await pairDevice();
    for (const body of [{}, { method: '' }, { method: 42 }, { payload: {} }]) {
      const reply = await call(M1_PATHS.rpc, { token, body });
      expect(reply.status).toBe(400);
    }
  });

  it('stops accepting a revoked device’s token immediately', async () => {
    // 401 rather than 403: revocation deletes the device's tokens, so by the time
    // this arrives the token is genuinely unknown. That is the stronger answer —
    // it does not confirm to the caller that the token was ever valid.
    const { deviceId, token } = await pairDevice();
    expect((await call(M1_PATHS.rpc, { token, body: { method: 'session.list', payload: {} } })).status).toBe(200);
    harness.registry.revoke(deviceId);
    const after = await call(M1_PATHS.rpc, { token, body: { method: 'session.list', payload: {} } });
    expect(after.status).toBe(401);
    expect(after.body.error.code).toBe('unauthenticated');
  });

  it('rate-limits a device and says how long to wait', async () => {
    // The retryAfterMs is the part that matters. Without it a phone has no basis for
    // backing off and will retry into the limit.
    const { token } = await pairDevice();
    let limited: { status: number; body: any } | undefined;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const reply = await call(M1_PATHS.rpc, { token, body: { method: 'session.list', payload: {} } });
      if (reply.status === 429) {
        limited = reply;
        break;
      }
    }
    expect(limited?.status).toBe(429);
    expect(limited?.body.error.code).toBe('rate-limited');
    expect(typeof limited?.body.error.retryAfterMs).toBe('number');
    expect(limited?.body.error.retryAfterMs).toBeGreaterThan(0);
  });

  it('counts the rate limit per device, not globally', async () => {
    // Otherwise one chatty phone denies service to every other paired device, which
    // turns a fairness control into an availability bug.
    const first = await pairDevice();
    const second = await pairDevice();
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const reply = await call(M1_PATHS.rpc, { token: first.token, body: { method: 'session.list', payload: {} } });
      if (reply.status === 429) break;
    }
    const other = await call(M1_PATHS.rpc, { token: second.token, body: { method: 'session.list', payload: {} } });
    expect(other.status).toBe(200);
  });
});

describe('/m1/stream upgrade', () => {
  /**
   * Attempt an upgrade at the socket level and return the HTTP status.
   *
   * A refusal is an HTTP response on a socket that was never upgraded, which no
   * WebSocket client library will surface — they report "unexpected response" and
   * discard the detail. The status is the contract here, so it is read directly.
   */
  function attemptUpgrade(options: { path?: string; protocols?: string[]; headers?: Record<string, string>; key?: string }): Promise<{ status: number; head: string }> {
    return new Promise((resolve, reject) => {
      const url = new URL(harness.url);
      const key = options.key ?? Buffer.alloc(16, 3).toString('base64');
      const headerLines = {
        Host: url.host,
        Upgrade: 'websocket',
        Connection: 'Upgrade',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': key,
        ...(options.protocols !== undefined && options.protocols.length > 0
          ? { 'Sec-WebSocket-Protocol': options.protocols.join(', ') }
          : {}),
        ...options.headers,
      };
      const socket = netConnect({ host: url.hostname, port: Number(url.port) }, () => {
        const lines = Object.entries(headerLines).map(([name, value]) => `${name}: ${value}`);
        socket.write(`GET ${options.path ?? M1_PATHS.stream} HTTP/1.1\r\n${lines.join('\r\n')}\r\n\r\n`);
      });
      const chunks: Buffer[] = [];
      socket.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
        const text = Buffer.concat(chunks).toString('latin1');
        if (text.includes('\r\n\r\n')) {
          socket.destroy();
          resolve({ status: Number(text.split(' ')[1] ?? 0), head: text });
        }
      });
      socket.on('error', reject);
      socket.on('close', () => {
        const text = Buffer.concat(chunks).toString('latin1');
        if (text.length > 0) resolve({ status: Number(text.split(' ')[1] ?? 0), head: text });
      });
      setTimeout(() => reject(new Error('upgrade attempt timed out')), 5000).unref?.();
    });
  }

  it('refuses an upgrade with no token subprotocol', async () => {
    // The token travels in the subprotocol, never the query string: query strings
    // land in access logs, shell history, and crash reports.
    const refused = await attemptUpgrade({ protocols: [M1_STREAM_SUBPROTOCOL] });
    expect(refused.status).toBe(401);
  });

  it('refuses an upgrade with an unknown token', async () => {
    const refused = await attemptUpgrade({
      protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}not-a-real-token`],
    });
    expect(refused.status).toBe(401);
  });

  it('refuses an upgrade on any path but the stream path', async () => {
    const { token } = await pairDevice();
    const refused = await attemptUpgrade({
      path: M1_PATHS.rpc,
      protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`],
    });
    expect(refused.status).toBe(404);
  });

  it('refuses a malformed handshake before it looks at the token', async () => {
    const { token } = await pairDevice();
    const protocols = [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`];
    // Wrong version → 426, per RFC 6455's own guidance for an unsupported version.
    expect((await attemptUpgrade({ protocols, headers: { 'Sec-WebSocket-Version': '8' } })).status).toBe(426);
    // A key that is not 16 bytes → 400.
    expect((await attemptUpgrade({ protocols, key: 'short' })).status).toBe(400);
  });

  it('refuses an after cursor that is not a non-negative integer', async () => {
    // `after` decides what history is replayed, so it is validated rather than
    // coerced: silently turning `-1` or `abc` into 0 would hand the device a
    // full-history read it did not ask for and cannot distinguish from a resume.
    const { token } = await pairDevice();
    const protocols = [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`];
    for (const after of ['-1', 'abc', '1.5', 'NaN', 'Infinity', '-0.5']) {
      const refused = await attemptUpgrade({ path: `${M1_PATHS.stream}?after=${encodeURIComponent(after)}`, protocols });
      expect([after, refused.status]).toEqual([after, 400]);
    }
  });

  it('lets a cursor above MAX_SAFE_INTEGER through, and the ring makes it safe', async () => {
    // Recorded because it is surprising rather than because it is wrong.
    // `Number('9007199254740993.5')` rounds to an integer above MAX_SAFE_INTEGER, so
    // `Number.isInteger` accepts it and the 400 never fires. Harmless in the end: the
    // ring refuses any cursor ahead of `lastAssigned` with `resync-required`, because
    // a log cannot prove what a client claims to already have. So the bound that
    // matters is enforced where the data is, not at the parse.
    const { token } = await pairDevice();
    const accepted = await attemptUpgrade({
      path: `${M1_PATHS.stream}?after=9007199254740993.5`,
      protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`],
    });
    expect(accepted.status).toBe(101);
  });

  it('accepts numeric forms that denote a valid integer', async () => {
    // `1e3` is 1000, `0x10` is 16, and ` ` coerces to 0. Unusual to send, but each
    // denotes a non-negative integer, and rejecting them would make the check about
    // spelling rather than value. The large ones land ahead of the ring, which the
    // ring handles as a resync rather than as an empty read (see stream-ring.test.ts).
    //
    // A fresh token per attempt, because a successful upgrade ROTATES the token: the
    // one dialled with is spent by the handshake. Reusing it gives 401 on the second
    // attempt, which is the rotation working, and is asserted directly below.
    for (const after of ['1e3', '0x10', '0', ' ', '1']) {
      const { token } = await pairDevice();
      const accepted = await attemptUpgrade({
        path: `${M1_PATHS.stream}?after=${encodeURIComponent(after)}`,
        protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`],
      });
      expect([after, accepted.status]).toEqual([after, 101]);
    }
  });

  it('spends the dialled token on a successful upgrade', async () => {
    // Rotation on stream connect, per the auth design: the long-lived secret is the
    // device key, and the token the phone carries afterwards is a fresh one handed
    // over in the `hello` frame. So the token used to dial is single-use, and a
    // replay of a captured handshake fails even within the token's TTL.
    const { token } = await pairDevice();
    const protocols = [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`];
    expect((await attemptUpgrade({ protocols })).status).toBe(101);
    expect((await attemptUpgrade({ protocols })).status).toBe(401);
  });

  it('accepts a valid upgrade and negotiates the subprotocol', async () => {
    const { token } = await pairDevice();
    const accepted = await attemptUpgrade({
      protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`],
    });
    expect(accepted.status).toBe(101);
    // The negotiated protocol is the versioned one, never the token: echoing the
    // token subprotocol back would put the credential in the response headers.
    expect(accepted.head).toContain(`Sec-WebSocket-Protocol: ${M1_STREAM_SUBPROTOCOL}`);
    expect(accepted.head).not.toContain(M1_TOKEN_SUBPROTOCOL_PREFIX);
  });

  it('refuses a revoked device’s token at upgrade time', async () => {
    const { deviceId, token } = await pairDevice();
    harness.registry.revoke(deviceId);
    const refused = await attemptUpgrade({
      protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`],
    });
    // 401 again, because revocation deleted the token rather than marking it.
    expect(refused.status).toBe(401);
  });
});

/**
 * A live stream, driven by the bridge's own `ClientWebSocket`.
 *
 * Uses the real client class rather than a stub for the same reason the codec tests
 * do: this pairing runs in production over the relay carrier, so exercising it here
 * covers the actual peer relationship.
 */
describe('/m1/stream traffic', () => {
  /** Connect a stream and collect every frame it delivers. */
  async function openStream(token: string, after = 0): Promise<{ socket: ClientWebSocket; frames: any[]; close: () => void }> {
    const url = new URL(harness.url);
    const key = randomBytes(16).toString('base64');
    const socket = netConnect({ host: url.hostname, port: Number(url.port) });
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', () => resolve());
      socket.once('error', reject);
    });
    socket.write(
      clientHandshakeRequest({
        path: `${M1_PATHS.stream}?after=${after}`,
        host: url.host,
        key,
        protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`],
      }),
    );

    // Read until the handshake response is complete, keeping any frame bytes that
    // arrived in the same packet — the bridge writes `hello` immediately, so those
    // trailing bytes routinely contain it.
    let buffered = Buffer.alloc(0);
    const rest = await new Promise<Buffer>((resolve, reject) => {
      const onData = (chunk: Buffer): void => {
        buffered = Buffer.concat([buffered, chunk]);
        const parsed = readClientHandshake(buffered, key);
        if ('pending' in parsed) return;
        socket.removeListener('data', onData);
        if (!parsed.ok) {
          reject(new Error(`handshake refused: ${parsed.reason}`));
          return;
        }
        resolve(parsed.rest);
      };
      socket.on('data', onData);
      socket.once('error', reject);
    });

    const frames: any[] = [];
    const client = new ClientWebSocket(socket, {}, { onMessage: (text) => void frames.push(JSON.parse(text)) });
    client.pushInitial(rest);
    return { socket: client, frames, close: () => client.destroy() };
  }

  it('sends hello with a rotated token and the current cursor', async () => {
    const { token } = await pairDevice();
    const stream = await openStream(token);
    try {
      await until(() => stream.frames.length > 0, 'hello');
      const hello = stream.frames[0];
      expect(hello.kind).toBe('hello');
      expect(hello.bridgeId).toBe(BRIDGE_ID);
      // Not the token we dialled with: the phone must adopt this one for its next
      // connect, and the dialled one is already spent.
      expect(typeof hello.token).toBe('string');
      expect(hello.token).not.toBe(token);
      expect(typeof hello.tokenExpiresAt).toBe('number');
      expect(typeof hello.lastBseq).toBe('number');
    } finally {
      stream.close();
    }
  });

  it('forwards a mux frame, tagging an answerable one with its rpcId', async () => {
    const { token } = await pairDevice();
    const stream = await openStream(token);
    try {
      await until(() => stream.frames.length > 0, 'hello');
      // `approval/requested` specifically: it is answerable, so it carries the rpcId
      // the phone needs in order to reply. A non-answerable frame deliberately does
      // not, since a phone that cannot answer should not hold a correlation id.
      harness.dsh.broadcast(
        {
          type: 'server-request',
          rpcId: 'rpc-live-1',
          method: 'events.mux',
          payload: { type: 'approval/requested', sessionId: 's-1', approvalId: 'a-1', toolName: 'shell' },
        },
        'mux',
      );

      await until(() => stream.frames.some((frame) => frame.kind === 'mux'), 'mux frame');
      const mux = stream.frames.find((frame) => frame.kind === 'mux');
      expect(mux.rpcId).toBe('rpc-live-1');
      expect(mux.frame.approvalId).toBe('a-1');
      expect(mux.bseq).toBeGreaterThan(0);
    } finally {
      stream.close();
    }
  });

  it('resumes from a cursor without replaying what the device already has', async () => {
    const { token } = await pairDevice();
    const first = await openStream(token);
    let cursor = 0;
    let rotated = '';
    try {
      await until(() => first.frames.length > 0, 'hello');
      rotated = first.frames[0].token;
      harness.dsh.broadcast(
        { type: 'server-request', rpcId: 'r1', method: 'events.host', payload: { type: 'host/session-status', sessionId: 's-1', running: true } },
        'host',
      );
      await until(() => first.frames.some((frame) => frame.kind === 'host'), 'first host frame');
      cursor = first.frames.filter((frame) => typeof frame.bseq === 'number').at(-1).bseq;
    } finally {
      first.close();
    }

    // A frame published while nothing is attached: this is what resume exists for.
    harness.dsh.broadcast(
      { type: 'server-request', rpcId: 'r2', method: 'events.host', payload: { type: 'host/session-status', sessionId: 's-2', running: false } },
      'host',
    );

    const second = await openStream(rotated, cursor);
    try {
      await until(() => second.frames.length > 0, 'second hello');
      await until(() => second.frames.some((frame) => frame.kind === 'host'), 'backlog frame');
      const hosts = second.frames.filter((frame) => frame.kind === 'host');
      // Only the missed one. Replaying the already-seen frame would double-apply it,
      // and the phone has no way to tell a redelivery from a new event.
      expect(hosts.map((frame) => frame.frame.sessionId)).toEqual(['s-2']);
      expect(second.frames[0].resync).toBe(false);
    } finally {
      second.close();
    }
  });

  it('replays an open approval to a reconnecting device', async () => {
    const { token } = await pairDevice();
    const first = await openStream(token);
    let rotated = '';
    let cursor = 0;
    try {
      await until(() => first.frames.length > 0, 'hello');
      rotated = first.frames[0].token;
      harness.dsh.broadcast(
        {
          type: 'server-request',
          rpcId: 'rpc-pending-1',
          method: 'events.mux',
          payload: { type: 'approval/requested', sessionId: 's-1', approvalId: 'a-1', toolName: 'shell' },
        },
        'mux',
      );
      await until(() => first.frames.some((frame) => frame.kind === 'mux'), 'approval');
      cursor = first.frames.filter((frame) => typeof frame.bseq === 'number').at(-1).bseq;
    } finally {
      first.close();
    }

    // Reconnect at a cursor that has missed nothing. Without pending replay the
    // device would get an empty delta and the session would block forever on an
    // answer nobody knows is owed.
    const second = await openStream(rotated, cursor);
    try {
      await until(() => second.frames.length > 0, 'second hello');
      expect(second.frames[0].pendingCount).toBe(1);
      await until(() => second.frames.some((frame) => frame.kind === 'mux'), 'replayed approval');
      const replayed = second.frames.find((frame) => frame.kind === 'mux');
      // Same rpcId as the first delivery, or the answer cannot be correlated.
      expect(replayed.rpcId).toBe('rpc-pending-1');
    } finally {
      second.close();
    }
  });

  it('answers a client ping over the stream', async () => {
    // Application-level, distinct from the RFC 6455 ping: it is how a phone confirms
    // the bridge is still processing rather than merely holding a socket open.
    const { token } = await pairDevice();
    const stream = await openStream(token);
    try {
      await until(() => stream.frames.length > 0, 'hello');
      stream.socket.sendJson({ v: 1, kind: 'ping' });
      await until(() => stream.frames.some((frame) => frame.frame?.type === 'pong'), 'pong');
      const pong = stream.frames.find((frame) => frame.frame?.type === 'pong');
      expect(pong.kind).toBe('bridge');
      expect(typeof pong.frame.at).toBe('number');
    } finally {
      stream.close();
    }
  });

  it('ignores anything on the stream that is not liveness', async () => {
    // The stream is deliberately not a second way to invoke methods. An unrecognised
    // client frame is ignored rather than errored, so a newer client cannot break an
    // older bridge — but an RPC-shaped frame must not be executed, and the check that
    // it was not is the upstream call log.
    const { token } = await pairDevice();
    const stream = await openStream(token);
    try {
      await until(() => stream.frames.length > 0, 'hello');
      const before = harness.dsh.calls.length;
      for (const payload of [
        { v: 1, kind: 'rpc', method: 'session.list', payload: {} },
        { v: 1, kind: 'respond', rpcId: 'x', payload: {} },
        { method: 'settings.update' },
        'not an object',
        '{malformed',
      ]) {
        stream.socket.send(typeof payload === 'string' ? payload : JSON.stringify(payload));
      }
      // Round-trip a ping afterwards: it proves the socket survived all of the above
      // rather than the assertions passing because the connection died.
      stream.socket.sendJson({ v: 1, kind: 'ping' });
      await until(() => stream.frames.some((frame) => frame.frame?.type === 'pong'), 'pong after junk');
      expect(harness.dsh.calls.length).toBe(before);
      expect(stream.socket.isOpen).toBe(true);
    } finally {
      stream.close();
    }
  });

  it('drops a live stream when the device is revoked, telling it why first', async () => {
    const { deviceId, token } = await pairDevice();
    const stream = await openStream(token);
    try {
      await until(() => stream.frames.length > 0, 'hello');
      harness.registry.revoke(deviceId);
      await until(() => stream.frames.some((frame) => frame.frame?.type === 'device-revoked'), 'revocation notice');
      // The reason arrives as a frame before the socket goes away. A bare close would
      // be indistinguishable from a network drop, and the phone would retry forever.
      expect(stream.frames.at(-1).frame.type).toBe('device-revoked');
    } finally {
      stream.close();
    }
  });
});

describe('POST /m1/respond', () => {
  /** Raise an answerable approval upstream and wait for the hub to hold it open. */
  async function raiseApproval(rpcId: string, approvalId = 'a-1'): Promise<void> {
    harness.dsh.broadcast(
      {
        type: 'server-request',
        rpcId,
        method: 'events.mux',
        payload: { type: 'approval/requested', sessionId: 's-1', approvalId, toolName: 'shell' },
      },
      'mux',
    );
    await until(() => harness.hub.isPending(rpcId), `pending approval ${rpcId}`);
  }

  /**
   * Raise an answerable question.
   *
   * `options` and `multiSelect` are part of the frame because the bridge validates
   * the answer against them — upstream compares `selected` values to the labels it
   * offered, so a test that omits them is not exercising the real path.
   */
  async function raiseQuestion(
    rpcId: string,
    question: { id?: string; options?: { label: string }[]; multiSelect?: boolean } = {},
  ): Promise<void> {
    harness.dsh.broadcast(
      {
        type: 'server-request',
        rpcId,
        method: 'events.mux',
        payload: {
          type: 'question/requested',
          sessionId: 's-1',
          questions: [
            {
              id: question.id ?? 'q1',
              question: 'which branch?',
              options: question.options ?? [{ label: 'main' }, { label: 'dev' }],
              ...(question.multiSelect === undefined ? {} : { multiSelect: question.multiSelect }),
            },
          ],
        },
      },
      'mux',
    );
    await until(() => harness.hub.isPending(rpcId), `pending question ${rpcId}`);
  }

  /** Upstream `respond` calls only, since the readiness handshake fills the log too. */
  function respondCalls(): { method: string; rpcId: string; payload: unknown }[] {
    return harness.dsh.calls.filter((entry) => entry.method === 'respond');
  }

  it('forwards an answer to a frame the bridge delivered', async () => {
    const { token } = await pairDevice();
    await raiseApproval('rpc-answer');

    const reply = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-answer', kind: 'approval', outcome: 'allowed-once' },
    });
    expect(reply.status).toBe(200);
    expect(reply.body).toEqual({ ok: true, value: { status: 'accepted' } });
    expect(respondCalls().map((entry) => entry.rpcId)).toEqual(['rpc-answer']);
    // Consumed locally on the accepted receipt rather than on dsh's later
    // `approval/resolved` frame. Waiting for that frame would leave a window in
    // which a second phone is still told the approval is open.
    expect(harness.hub.isPending('rpc-answer')).toBe(false);
  });

  it('refuses to answer an rpcId it never delivered', async () => {
    // The authorization check that matters most on this route. Without it a phone
    // could answer an approval raised for a different client entirely — it would only
    // need to guess an rpcId, and rpcIds are not secrets.
    //
    // Reported as `already-resolved` rather than an error: it is what the phone should
    // render either way, and it does not disclose whether the rpcId was ever real.
    const { token } = await pairDevice();
    const before = respondCalls().length;
    const reply = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-never-delivered', kind: 'approval', outcome: 'allowed-once' },
    });
    expect(reply.status).toBe(200);
    expect(reply.body.value).toEqual({ status: 'already-resolved' });
    expect(respondCalls().length).toBe(before);
  });

  it('reports a repeated answer as already-resolved, not as a failure', async () => {
    // A retry after a flaky network looks exactly like this. Surfacing it as an error
    // would train the phone to show a scary dialog for an answer that landed.
    const { token } = await pairDevice();
    await raiseApproval('rpc-twice');

    const body = { rpcId: 'rpc-twice', kind: 'approval', outcome: 'rejected' };
    expect((await call(M1_PATHS.respond, { token, body })).body.value).toEqual({ status: 'accepted' });
    const second = await call(M1_PATHS.respond, { token, body });
    expect(second.status).toBe(200);
    expect(second.body.value).toEqual({ status: 'already-resolved' });
    // And the duplicate never reached dsh: the pending check short-circuits it.
    expect(respondCalls().length).toBe(1);
  });

  it('serializes concurrent answers to one rpcId so exactly one reaches dsh', async () => {
    // The item this route exists to get right. dsh `respond` is single-shot, so two
    // phones answering the same approval at once must not both be forwarded — and
    // must not both be told they won. The per-rpcId chain makes the second waiter
    // re-check `isPending` *after* the first has resolved, which is why this is
    // deterministic rather than a race that usually works.
    const first = await pairDevice();
    const second = await pairDevice();
    await raiseApproval('rpc-race');

    const results = await Promise.all([
      call(M1_PATHS.respond, {
        token: first.token,
        body: { rpcId: 'rpc-race', kind: 'approval', outcome: 'allowed-once' },
      }),
      call(M1_PATHS.respond, {
        token: second.token,
        body: { rpcId: 'rpc-race', kind: 'approval', outcome: 'rejected' },
      }),
    ]);

    expect(results.map((reply) => reply.status)).toEqual([200, 200]);
    expect(results.map((reply) => reply.body.value.status).sort()).toEqual(['accepted', 'already-resolved']);
    expect(respondCalls().length).toBe(1);
  });

  it('serializes answers to different rpcIds independently', async () => {
    // The chain is keyed per rpcId, so one slow approval must not queue behind or
    // block another. Both are forwarded, and the count is the proof.
    const { token } = await pairDevice();
    await raiseApproval('rpc-a', 'a-a');
    await raiseApproval('rpc-b', 'a-b');

    const results = await Promise.all([
      call(M1_PATHS.respond, { token, body: { rpcId: 'rpc-a', kind: 'approval', outcome: 'allowed-once' } }),
      call(M1_PATHS.respond, { token, body: { rpcId: 'rpc-b', kind: 'approval', outcome: 'rejected' } }),
    ]);
    expect(results.map((reply) => reply.body.value.status)).toEqual(['accepted', 'accepted']);
    expect(respondCalls().map((entry) => entry.rpcId).sort()).toEqual(['rpc-a', 'rpc-b']);
  });

  it('restricts an approval outcome to allowed-once or rejected', async () => {
    // There is no "always allow" from a phone, and this is the enforcement point.
    // A persistent grant made from a device the operator is not watching outlives the
    // context it was made in, so the wire format simply cannot express it — even
    // though the upstream `approval/resolved` vocabulary has more outcomes.
    const { token } = await pairDevice();
    await raiseApproval('rpc-outcome');

    for (const outcome of ['allowed-always', 'always', 'approved', 'allow', 'cancelled', 'unavailable', '', 1, null]) {
      const reply = await call(M1_PATHS.respond, {
        token,
        body: { rpcId: 'rpc-outcome', kind: 'approval', outcome },
      });
      expect([outcome, reply.status]).toEqual([outcome, 400]);
    }
    // Nothing was forwarded and the approval is still open, so a valid answer can
    // still be given. A rejected malformed answer must not consume the obligation.
    expect(respondCalls().length).toBe(0);
    expect(harness.hub.isPending('rpc-outcome')).toBe(true);
  });

  it('requires a recognised kind', async () => {
    // `kind` is validated before the pending lookup, so this 400s even for an rpcId
    // that is genuinely open — the bridge will not guess which payload shape was
    // meant when the two have incompatible schemas.
    const { token } = await pairDevice();
    await raiseApproval('rpc-kind');
    for (const kind of ['approval-request', 'rpc', 'APPROVAL', '', undefined, 3]) {
      const reply = await call(M1_PATHS.respond, { token, body: { rpcId: 'rpc-kind', kind, outcome: 'rejected' } });
      expect([kind, reply.status]).toEqual([kind, 400]);
    }
    expect(harness.hub.isPending('rpc-kind')).toBe(true);
  });

  it('requires an rpcId', async () => {
    const { token } = await pairDevice();
    for (const rpcId of [undefined, '', 42, null, 'x'.repeat(257)]) {
      const reply = await call(M1_PATHS.respond, { token, body: { rpcId, kind: 'approval', outcome: 'rejected' } });
      expect([rpcId, reply.status]).toEqual([rpcId, 400]);
    }
  });

  it('sends the approval payload dsh actually validates', async () => {
    // The shape is `{sessionId, approvalId, outcome}`, verified against upstream's
    // approvalResponsePayloadSchema — and upstream additionally re-checks both ids
    // against its own pending entry, answering `bad-response` on a mismatch. So an
    // answer carrying only `outcome` is refused by a real dsh, and this assertion is
    // the only thing standing between that and a green test suite.
    //
    // The ids come from the delivered frame, never from the request body: a phone
    // supplies the decision and nothing else, so it cannot attribute its answer to a
    // session it was never shown.
    const { token } = await pairDevice();
    await raiseApproval('rpc-shape', 'approval-77');

    await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-shape', kind: 'approval', outcome: 'allowed-once', sessionId: 'attacker-chosen', approvalId: 'attacker-chosen' },
    });
    expect(harness.dsh.lastRespondResult).toEqual({
      ok: true,
      value: { sessionId: 's-1', approvalId: 'approval-77', outcome: 'allowed-once' },
    });
  });

  it('normalizes a question answer into the batch shape dsh expects', async () => {
    // `{sessionId, answer: {answers: [{id, selected, custom?}]}}`, per upstream's
    // questionResponsePayloadSchema. The phone sends one `value` field and the bridge
    // splits it: values matching an offered label become `selected`, anything else is
    // free text in `custom`. That keeps the phone from having to model the
    // distinction, and keeps the wire honest about which it was.
    const { token } = await pairDevice();
    await raiseQuestion('rpc-q', { multiSelect: true });

    const reply = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-q', kind: 'question', answers: [{ id: 'q1', value: ['main', 'dev'], extra: 'dropped' }] },
    });
    expect(reply.body.value).toEqual({ status: 'accepted' });
    expect(respondCalls().at(-1)?.rpcId).toBe('rpc-q');
    // `extra` is gone: the bridge rebuilds the payload field by field rather than
    // forwarding the client's object, so a phone cannot smuggle keys into a dsh call.
    expect(harness.dsh.lastRespondResult).toEqual({
      ok: true,
      value: { sessionId: 's-1', answer: { answers: [{ id: 'q1', selected: ['main', 'dev'] }] } },
    });
  });

  it('routes a value that is not an offered label into custom', async () => {
    const { token } = await pairDevice();
    await raiseQuestion('rpc-q-custom');

    await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-q-custom', kind: 'question', answers: [{ id: 'q1', value: 'a branch nobody offered' }] },
    });
    // `selected` empty rather than carrying the free text: upstream checks every
    // `selected` value against the labels it offered, so putting free text there
    // would be rejected as `bad-response`.
    expect(harness.dsh.lastRespondResult).toEqual({
      ok: true,
      value: { sessionId: 's-1', answer: { answers: [{ id: 'q1', selected: [], custom: 'a branch nobody offered' }] } },
    });
  });

  it('rejects answers that upstream would refuse, before they are forwarded', async () => {
    // Each of these is a `bad-response` at a real dsh. Catching them here turns an
    // opaque upstream refusal into a 400 that names the problem, which is the
    // difference between a fixable client bug and a mystery.
    const { token } = await pairDevice();
    const cases: { answers: unknown; why: string }[] = [
      { answers: [], why: 'wrong count: one question was asked' },
      { answers: 'text', why: 'not an array' },
      { answers: [{ value: 'main' }], why: 'missing id' },
      { answers: [{ id: 'q2', value: 'main' }], why: 'id does not match the question' },
      { answers: [{ id: 'q1' }], why: 'missing value' },
      { answers: [{ id: 'q1', value: 42 }], why: 'wrong value type' },
      { answers: [{ id: 'q1', value: [1, 2] }], why: 'array of non-strings' },
      { answers: [{ id: 'q1', value: [] }], why: 'nothing selected' },
      { answers: [{ id: 'q1', value: '   ' }], why: 'blank free text' },
      { answers: [{ id: 'q1', value: ['main', 'main'] }], why: 'repeated selection' },
      { answers: [{ id: 'q1', value: ['main', 'dev'] }], why: 'single-select given two labels' },
      { answers: [{ id: 'q1', value: ['main', 'free'] }], why: 'single-select given a label and free text' },
      { answers: [{ id: 'q1', value: ['free one', 'free two'] }], why: 'two free-text values' },
      { answers: [{ id: 'q1', value: 'main' }, { id: 'q1', value: 'dev' }], why: 'more answers than questions' },
    ];
    for (const { answers, why } of cases) {
      await raiseQuestion('rpc-q-bad');
      const reply = await call(M1_PATHS.respond, { token, body: { rpcId: 'rpc-q-bad', kind: 'question', answers } });
      expect([why, reply.status]).toEqual([why, 400]);
      // Still open: a refused answer must not consume the obligation, or a typo would
      // strand the session with nobody able to answer it.
      expect([why, harness.hub.isPending('rpc-q-bad')]).toEqual([why, true]);
    }
    expect(respondCalls().length).toBe(0);
  });

  it('accepts a multi-select answer that mixes labels with one free-text value', async () => {
    // Allowed only when the question said `multiSelect`. Upstream's own check is the
    // same shape, so this is the one case where both halves may be non-empty.
    const { token } = await pairDevice();
    await raiseQuestion('rpc-q-mixed', { multiSelect: true });
    const reply = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-q-mixed', kind: 'question', answers: [{ id: 'q1', value: ['main', 'something else'] }] },
    });
    expect(reply.body.value).toEqual({ status: 'accepted' });
    expect(harness.dsh.lastRespondResult).toEqual({
      ok: true,
      value: { sessionId: 's-1', answer: { answers: [{ id: 'q1', selected: ['main'], custom: 'something else' }] } },
    });
  });

  it('refuses to answer a question with an approval payload, and vice versa', async () => {
    // `kind` must agree with the frame the rpcId names. Without this check the
    // builder would read `outcome` off a question or `answers` off an approval, and
    // send a payload upstream refuses for reasons the phone cannot diagnose.
    const { token } = await pairDevice();
    await raiseApproval('rpc-is-approval');
    await raiseQuestion('rpc-is-question');

    const asQuestion = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-is-approval', kind: 'question', answers: [{ id: 'q1', value: 'main' }] },
    });
    expect(asQuestion.status).toBe(400);
    expect(asQuestion.body.error.message).toContain('approval/requested');

    const asApproval = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-is-question', kind: 'approval', outcome: 'allowed-once' },
    });
    expect(asApproval.status).toBe(400);
    expect(respondCalls().length).toBe(0);
  });

  it('caps an answer at 32 KiB of UTF-8, and calls it too large rather than bad', async () => {
    // 413 rather than 400: the phone can act on the difference by truncating, whereas
    // a generic bad-request tells it to change the shape of something already valid.
    const { token } = await pairDevice();
    await raiseQuestion('rpc-q-big');
    const justUnder = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-q-big', kind: 'question', answers: [{ id: 'q1', value: 'x'.repeat(32_768) }] },
    });
    expect(justUnder.body.value).toEqual({ status: 'accepted' });

    await raiseQuestion('rpc-q-over');
    const justOver = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-q-over', kind: 'question', answers: [{ id: 'q1', value: 'x'.repeat(32_769) }] },
    });
    expect(justOver.status).toBe(413);
    expect(justOver.body.error.code).toBe('payload-too-large');

    // Bytes, not UTF-16 units. 16,385 four-byte characters is 65,540 bytes but only
    // 32,770 `.length`, so a cap measured with `.length` would let this through at
    // twice the intended weight.
    await raiseQuestion('rpc-q-astral');
    const astral = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-q-astral', kind: 'question', answers: [{ id: 'q1', value: '𝄞'.repeat(16_385) }] },
    });
    expect(astral.status).toBe(413);
  });

  it('needs a credential, and checks it before reading the body', async () => {
    // Same ordering as /m1/rpc: an unauthenticated caller learns nothing about the
    // body schema, not even that its content-type was wrong.
    const missing = await call(M1_PATHS.respond, { body: { rpcId: 'x', kind: 'approval', outcome: 'rejected' } });
    expect(missing.status).toBe(401);
    const wrongType = await call(M1_PATHS.respond, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'rpcId=x',
    });
    expect(wrongType.status).toBe(401);
  });

  it('refuses a revoked device with 401, before any pending lookup', async () => {
    const { deviceId, token } = await pairDevice();
    await raiseApproval('rpc-revoked');
    harness.registry.revoke(deviceId);

    const reply = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-revoked', kind: 'approval', outcome: 'allowed-once' },
    });
    // 401, not 403: revocation deletes the device's tokens, so the credential is
    // simply unknown. That is the stronger answer — it does not confirm the token
    // was ever valid.
    expect(reply.status).toBe(401);
    expect(respondCalls().length).toBe(0);
    // And the obligation survives, so another paired device can still answer it.
    expect(harness.hub.isPending('rpc-revoked')).toBe(true);
  });

  it('reports a bad-response receipt distinctly from a resolved one', async () => {
    // The three receipts are not interchangeable. `bad-response` means dsh refused
    // the payload we built, which is a bridge bug the phone cannot fix by retrying —
    // so it must not be reported as `already-resolved`, which invites a retry.
    const custom = await startHarness({ dsh: { respondReceipt: () => ({ accepted: false, reason: 'bad-response' }) } });
    try {
      const { token } = await pairDevice(custom);
      custom.dsh.broadcast(
        {
          type: 'server-request',
          rpcId: 'rpc-bad',
          method: 'events.mux',
          payload: { type: 'approval/requested', sessionId: 's-1', approvalId: 'a-1', toolName: 'shell' },
        },
        'mux',
      );
      await until(() => custom.hub.isPending('rpc-bad'), 'pending approval');

      const reply = await fetch(`${custom.url}${M1_PATHS.respond}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({ rpcId: 'rpc-bad', kind: 'approval', outcome: 'allowed-once' }),
      });
      expect(await reply.json()).toEqual({ ok: true, value: { status: 'rejected', reason: 'bad-response' } });
      // Not consumed: the answer did not land, so the approval is still owed.
      expect(custom.hub.isPending('rpc-bad')).toBe(true);
    } finally {
      await custom.stop();
    }
  });

  it('refuses to answer while dsh is disconnected, without consuming the obligation', async () => {
    // Better than forwarding into a closed socket: the phone gets a code it can
    // retry on, and the pending frame is still there when the harness returns.
    const { token } = await pairDevice();
    await raiseApproval('rpc-offline');
    await harness.connection.stop();
    await until(() => !harness.connection.isConnected(), 'dsh disconnected');

    const reply = await call(M1_PATHS.respond, {
      token,
      body: { rpcId: 'rpc-offline', kind: 'approval', outcome: 'allowed-once' },
    });
    expect(reply.status).toBe(503);
    expect(reply.body.error.code).toBe('dsh-unavailable');
    expect(harness.hub.isPending('rpc-offline')).toBe(true);
  });

  it('records every answer in the audit log with a digest, never the payload', async () => {
    // The digest is what makes the log safe to keep: an approval answer can name a
    // path or a command, and an audit trail that quotes it becomes a second copy of
    // whatever the operator was deciding about.
    const { deviceId, token } = await pairDevice();
    await raiseApproval('rpc-audited');
    await call(M1_PATHS.respond, { token, body: { rpcId: 'rpc-audited', kind: 'approval', outcome: 'allowed-once' } });

    const entries = harness.audit.tail(50).filter((entry) => entry.rpcId === 'rpc-audited');
    const allowed = entries.find((entry) => entry.decision === 'allowed');
    expect(allowed).toMatchObject({ event: 'respond', deviceId, method: 'approval' });
    expect(typeof allowed?.payloadDigest).toBe('string');
    expect(JSON.stringify(entries)).not.toContain('allowed-once');
  });
});

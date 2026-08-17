/**
 * End-to-end test over the real composition root.
 *
 * This is the only test that starts `buildBridge()` whole: real TLS listener, real
 * identity files on disk, real control socket, real dsh carrier against a real (if
 * fake) HTTP server. Everything else in this suite tests one seam in isolation, so
 * this is what catches wiring mistakes that unit tests structurally cannot see —
 * a sink attached to the wrong hub, a route never registered, an ordering bug
 * between revocation and teardown.
 *
 * What it still does NOT prove:
 *   - Compatibility with a real dsh. `FakeDshServer` reproduces the envelope rules
 *     we verified by reading upstream, not upstream itself. [NOT INTEGRATION-TESTED]
 *   - Anything about a real phone. The client side here is `fetch` and our own
 *     WebSocket client, not the RN app. [NOT INTEGRATION-TESTED]
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildBridge, type BuiltBridge } from '../src/bridge.ts';
import { FakeDshServer } from './fake-dsh-server.ts';
import { generateEd25519KeyPair, signMessage, toBase64Url } from '../src/identity/crypto.ts';
import { pairingProofMessage } from '../src/identity/pairing.ts';
import { authProofMessage } from '../src/auth/tokens.ts';
import { ClientWebSocket, clientHandshakeRequest, readClientHandshake } from '../src/http/websocket.ts';
import { M1_STREAM_SUBPROTOCOL, M1_TOKEN_SUBPROTOCOL_PREFIX } from '../src/m1/wire.ts';
import type { ScopeTier } from '../src/policy/methods.ts';

interface HttpReply {
  status: number;
  body: any;
}

/**
 * One HTTPS call to the bridge.
 *
 * `node:https` rather than `fetch`, and `rejectUnauthorized: false` rather than a
 * global env flag: the bridge's cert is self-signed by design (the phone pins its
 * SPKI from the QR code), and scoping the exception to this one client keeps it
 * from leaking into any other test in the process.
 */
async function call(port: number, path: string, init: { method?: string; body?: unknown; token?: string } = {}): Promise<HttpReply> {
  const payload = init.body === undefined ? undefined : Buffer.from(JSON.stringify(init.body));
  return await new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: '127.0.0.1',
        port,
        path,
        method: init.method ?? 'GET',
        rejectUnauthorized: false,
        headers: {
          ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': payload.byteLength }),
          ...(init.token === undefined ? {} : { authorization: `Bearer ${init.token}` }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({ status: response.statusCode ?? 0, body: text.length === 0 ? null : JSON.parse(text) });
        });
      },
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

/** Poll until `check` passes, so no test depends on a fixed sleep. */
async function until(check: () => boolean, label: string, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for ${label}`);
}

describe('bridge end to end', () => {
  let dsh: FakeDshServer;
  let built: BuiltBridge;
  let stateDir: string;
  let port = 0;

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), 'dshm-e2e-'));
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    built = buildBridge({
      stateDir,
      dshUrl: `http://127.0.0.1:${dshPort}`,
      host: '127.0.0.1',
      // Port 0 lets the OS choose, so concurrent test files never collide.
      port: 0,
    });
    await built.start();
    const address = built.httpsServer.address();
    port = typeof address === 'object' && address !== null ? address.port : 0;
    // Pairing is refused unless dsh is reachable, so every pairing test needs the
    // readiness handshake to have completed first.
    await until(() => built.connection.getState() === 'connected', 'dsh connection');
  });

  afterEach(async () => {
    await built.stop();
    await dsh.close();
    rmSync(stateDir, { recursive: true, force: true });
  });

  /**
   * Drive a fresh device all the way to a usable access token, exactly as a phone
   * would: claim, operator confirmation, re-claim, challenge, proof.
   *
   * The one shortcut is `pairing.confirm()` in place of a human at the CLI. The SAS
   * equality that the human actually checks is asserted in its own test above.
   */
  async function pairAndAuthenticate(tier: ScopeTier = 'default'): Promise<{ deviceId: string; token: string; device: ReturnType<typeof generateEd25519KeyPair> }> {
    const device = generateEd25519KeyPair();
    const session = built.pairing.begin();
    const proof = toBase64Url(signMessage(device.privateKey, pairingProofMessage(session.token, built.identity.bridgeId)));
    const claimBody = { token: session.token, devicePublicKey: device.publicKeyB64, label: 'test phone', proof };

    await call(port, '/m1/pair/claim', { method: 'POST', body: claimBody });
    built.pairing.confirm({ tier });
    const paired = await call(port, '/m1/pair/claim', { method: 'POST', body: claimBody });
    const deviceId = paired.body.value.deviceId as string;

    const challenge = await call(port, '/m1/auth/session', { method: 'POST', body: { deviceId } });
    const nonce = challenge.body.value.nonce as string;
    const authed = await call(port, '/m1/auth/session', {
      method: 'POST',
      body: {
        deviceId,
        nonce,
        signature: toBase64Url(signMessage(device.privateKey, authProofMessage(nonce, deviceId, built.identity.bridgeId))),
      },
    });
    return { deviceId, token: authed.body.value.token as string, device };
  }

  it('serves health over TLS and reports a connected dsh', async () => {
    const reply = await call(port, '/m1/health');
    expect(reply.status).toBe(200);
    // Health is deliberately flat rather than `{ok, value}`-enveloped: it is a
    // liveness probe a phone may call before it holds any credential.
    expect(reply.body.ok).toBe(true);
    expect(reply.body.bridgeId).toBe(built.identity.bridgeId);
    expect(reply.body.dsh).toBe('up');
    expect(reply.body.dshState).toBe('connected');
  });

  it('writes private material with owner-only permissions', () => {
    for (const name of ['bridge-key.pem', 'identity.json']) {
      expect(statSync(join(stateDir, name)).mode & 0o777).toBe(0o600);
    }
  });

  it('refuses an unauthenticated rpc', async () => {
    const reply = await call(port, '/m1/rpc', {
      method: 'POST',
      body: { method: 'session.list', payload: {} },
    });
    expect(reply.status).toBe(401);
    expect(reply.body.error.code).toBe('unauthenticated');
  });

  it('pairs, authenticates, and forwards an rpc to dsh', async () => {
    // ── pair ────────────────────────────────────────────────────────────────
    const device = generateEd25519KeyPair();
    const session = built.pairing.begin();
    const proof = toBase64Url(signMessage(device.privateKey, pairingProofMessage(session.token, built.identity.bridgeId)));

    const claim = await call(port, '/m1/pair/claim', {
      method: 'POST',
      body: { token: session.token, devicePublicKey: device.publicKeyB64, label: 'test phone', proof },
    });
    expect(claim.status).toBe(200);
    expect(claim.body.value.status).toBe('awaiting-confirmation');
    // The SAS the phone shows must equal the one the operator sees; that equality is
    // the entire value of the check.
    expect(claim.body.value.sas).toBe(built.pairing.current()?.sas);

    built.pairing.confirm({ tier: 'default' });

    const polled = await call(port, '/m1/pair/claim', {
      method: 'POST',
      body: { token: session.token, devicePublicKey: device.publicKeyB64, label: 'test phone', proof },
    });
    expect(polled.body.value.status).toBe('paired');
    const deviceId = polled.body.value.deviceId as string;

    // ── authenticate ────────────────────────────────────────────────────────
    const challenge = await call(port, '/m1/auth/session', { method: 'POST', body: { deviceId } });
    expect(challenge.status).toBe(200);
    const nonce = challenge.body.value.nonce as string;

    const authed = await call(port, '/m1/auth/session', {
      method: 'POST',
      body: {
        deviceId,
        nonce,
        signature: toBase64Url(signMessage(device.privateKey, authProofMessage(nonce, deviceId, built.identity.bridgeId))),
      },
    });
    expect(authed.status).toBe(200);
    const token = authed.body.value.token as string;
    expect(authed.body.value.scopeTier).toBe('default');

    // ── rpc ─────────────────────────────────────────────────────────────────
    const rpc = await call(port, '/m1/rpc', {
      method: 'POST',
      token,
      body: { method: 'session.list', payload: {} },
    });
    expect(rpc.status).toBe(200);
    expect(rpc.body.ok).toBe(true);
    // `value` is dsh's unwrapped result value: the bridge strips the envelope so
    // the phone never has to know dsh reports business errors as HTTP 200.
    expect(rpc.body.value).toEqual({ sessions: [] });

    // ── revocation cuts access immediately ──────────────────────────────────
    expect(built.controlHandlers.revoke(deviceId).ok).toBe(true);
    const afterRevoke = await call(port, '/m1/rpc', {
      method: 'POST',
      token,
      body: { method: 'session.list', payload: {} },
    });
    // 401 `unauthenticated`, not 403 `device-revoked`: revocation *deletes* the
    // device's access tokens, so by the time this arrives the token is genuinely
    // unknown. That is the stronger answer — it does not confirm to the caller
    // that the token was ever valid.
    expect(afterRevoke.status).toBe(401);
    expect(afterRevoke.body.error.code).toBe('unauthenticated');
  });

  it('denies a privileged method with a live token', async () => {
    const { token } = await pairAndAuthenticate();

    // The gate runs after authentication, so this proves the deny list is not
    // merely an unauthenticated-request filter.
    const denied = await call(port, '/m1/rpc', {
      method: 'POST',
      token,
      body: { method: 'settings.update', payload: {} },
    });
    expect(denied.status).toBe(403);
    expect(denied.body.error.code).toBe('method-denied');
  });

  it('delivers a dsh frame over a live /m1/stream socket', async () => {
    const { token } = await pairAndAuthenticate();

    const messages: any[] = [];
    let closeReason = '';
    const key = randomBytes(16).toString('base64');
    const socket = tlsConnect({ host: '127.0.0.1', port, rejectUnauthorized: false });
    let buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let ws: ClientWebSocket | undefined;

    await new Promise<void>((resolve, reject) => {
      socket.on('error', reject);
      socket.on('data', (chunk: Buffer) => {
        if (ws !== undefined) return;
        buffer = buffer.byteLength === 0 ? chunk : Buffer.concat([buffer, chunk]);
        const outcome = readClientHandshake(buffer, key);
        if ('pending' in outcome) return;
        if (!outcome.ok) {
          reject(new Error(outcome.reason));
          return;
        }
        socket.removeAllListeners('data');
        ws = new ClientWebSocket(socket, { maxMessageBytes: 1024 * 1024 }, {});
        ws.setSinks({
          onMessage: (text) => messages.push(JSON.parse(text)),
          onClose: (_code, reason) => {
            closeReason = reason;
          },
        });
        ws.pushInitial(outcome.rest);
        resolve();
      });
      socket.on('secureConnect', () => {
        socket.write(
          clientHandshakeRequest({
            path: '/m1/stream?after=0',
            host: '127.0.0.1',
            key,
            // The token rides in the subprotocol, never the query string.
            protocols: [M1_STREAM_SUBPROTOCOL, `${M1_TOKEN_SUBPROTOCOL_PREFIX}${token}`],
          }),
        );
      });
    });

    await until(() => messages.some((message) => message.kind === 'hello'), 'stream hello');
    const hello = messages.find((message) => message.kind === 'hello');
    expect(hello.bridgeId).toBe(built.identity.bridgeId);
    // Connecting rotates the token, so the phone must adopt the one in `hello`.
    expect(hello.token).not.toBe(token);
    expect(hello.resync).toBe(false);

    // A frame pushed by dsh must arrive on the phone's socket with a bseq. The
    // shape is the real one: a `server-request` envelope whose payload is the mux
    // frame, which is how dsh drives its downlinks.
    //
    // `approval/requested` specifically, because it is answerable: it exercises the
    // pending set and the rpcId propagation the phone needs in order to reply. A
    // non-answerable frame deliberately carries no rpcId, since a phone that cannot
    // answer should not be handed a correlation id.
    dsh.broadcast({
      type: 'server-request',
      rpcId: 'e2e-1',
      method: 'events.mux',
      payload: {
        type: 'approval/requested',
        sessionId: 's-1',
        approvalId: 'a-1',
        toolName: 'shell',
      },
    }, 'mux');

    await until(() => messages.some((message) => message.kind === 'mux'), 'a forwarded mux frame');
    const forwarded = messages.find((message) => message.kind === 'mux');
    expect(forwarded.bseq).toBeGreaterThan(0);
    expect(forwarded.rpcId).toBe('e2e-1');
    expect(forwarded.frame.approvalId).toBe('a-1');

    ws?.close();
    expect(closeReason).toBeDefined();
  });
});

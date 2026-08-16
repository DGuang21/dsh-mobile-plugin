/**
 * Smoke test: the bridge's own dsh client against a REAL `dsh web`.
 *
 * Everything else in this repo tests against `FakeDshServer`, which reproduces
 * the envelope rules read from upstream source. That is a model, not upstream.
 * This script is the only thing that can support a compatibility claim, so it
 * takes no shortcuts: it uses `DshApiClient` unmodified, talks to a real server
 * over a real socket, and asserts on what came back.
 *
 * Usage:
 *   node --experimental-strip-types bridge/scripts/smoke-real-dsh.ts [origin]
 *
 * `origin` defaults to `$DSH_SMOKE_URL`, then `http://127.0.0.1:13080`.
 *
 * To bring a real dsh up first, see docs/REAL_DSH_SMOKE.md. Exit code is 0 only
 * if every check passed; 2 means the server was unreachable, which is a skip
 * rather than a failure of the bridge.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildBridge } from '../src/bridge.ts';
import { authProofMessage } from '../src/auth/tokens.ts';
import { DshApiClient } from '../src/dsh/client.ts';
import { DshDownlink } from '../src/dsh/downlink.ts';
import { DshRpcError } from '../src/dsh/errors.ts';
import { generateEd25519KeyPair, signMessage, toBase64Url } from '../src/identity/crypto.ts';
import { pairingProofMessage } from '../src/identity/pairing.ts';
import { DENIED_METHODS } from '../src/policy/methods.ts';

const DEFAULT_ORIGIN = 'http://127.0.0.1:13080';

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

const checks: Check[] = [];

function record(name: string, ok: boolean, detail: string): void {
  checks.push({ name, ok, detail });
  process.stdout.write(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail === '' ? '' : `  — ${detail}`}\n`);
}

async function check(name: string, run: () => Promise<string>): Promise<void> {
  try {
    record(name, true, await run());
  } catch (error) {
    record(name, false, error instanceof Error ? error.message : String(error));
  }
}

/** Fail loudly rather than reporting a pass on a value we did not actually see. */
function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function main(): Promise<void> {
  const origin = process.argv[2] ?? process.env.DSH_SMOKE_URL ?? DEFAULT_ORIGIN;
  process.stdout.write(`# real dsh smoke test against ${origin}\n\n`);

  const client = new DshApiClient({ baseUrl: origin, timeoutMs: 15_000 });

  // Reachability first. An unreachable server is a skip, not a bridge failure,
  // so it exits 2 and says why rather than printing 20 identical errors.
  try {
    await client.describeHost();
  } catch (error) {
    process.stdout.write(`\nno dsh at ${origin}: ${error instanceof Error ? error.message : String(error)}\n`);
    process.stdout.write('see docs/REAL_DSH_SMOKE.md to bring one up\n');
    process.exit(2);
  }

  await check('host.describe returns a host descriptor', async () => {
    const value = await client.describeHost();
    assert(typeof value === 'object' && value !== null, 'expected an object');
    const keys = Object.keys(value as object);
    assert(keys.length > 0, 'descriptor was empty');
    return `keys: ${keys.slice(0, 6).join(', ')}`;
  });

  await check('session.list returns an items array', async () => {
    const value = await client.callOrThrow('session.list', {});
    assert(typeof value === 'object' && value !== null, 'expected an object');
    const items = (value as { items?: unknown }).items;
    assert(Array.isArray(items), 'expected value.items to be an array');
    return `${(items as unknown[]).length} session(s)`;
  });

  await check('workspace.list returns an envelope the bridge can read', async () => {
    const result = await client.call('workspace.list', {});
    // Either outcome is fine. What matters is that a real response parsed as a
    // ServerResponse and the rpcId correlated — both enforced inside call().
    return result.ok ? 'ok: true' : `business error: ${result.error.code}`;
  });

  await check('a business error arrives as HTTP 200 + ServerResponse', async () => {
    // A well-formed request for something that does not exist. This is the
    // load-bearing envelope rule: a business failure must NOT be an HTTP error,
    // or the bridge's whole error-passthrough path is wrong.
    const result = await client.call('session.history', { sessionId: 'does-not-exist-smoke' });
    assert(!result.ok, 'expected a business error for a nonexistent session');
    return `code: ${result.error.code}`;
  });

  await check('callOrThrow folds that business error into DshRpcError', async () => {
    try {
      await client.callOrThrow('session.history', { sessionId: 'does-not-exist-smoke' });
    } catch (error) {
      assert(error instanceof DshRpcError, `expected DshRpcError, got ${String(error)}`);
      return `code: ${(error as DshRpcError).code}`;
    }
    throw new Error('expected a throw');
  });

  await check('a malformed payload is a business error, not a carrier error', async () => {
    // Upstream parses the payload with zod and answers 200 + bad-request. If the
    // real server ever made this a 4xx, the bridge would surface it as a
    // transport failure instead of a usable error.
    const result = await client.call('session.history', { sessionId: 42 });
    assert(!result.ok, 'expected a business error');
    assert(result.error.code === 'bad-request', `expected bad-request, got ${result.error.code}`);
    return 'bad-request';
  });

  await check('an unknown method is a carrier 404, not an envelope', async () => {
    try {
      await client.call('definitely.notAMethod', {});
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      assert(/404/.test(message), `expected a 404 in the error, got: ${message}`);
      return 'threw on 404';
    }
    throw new Error('expected a throw');
  });

  await check('method/path mismatch is refused', async () => {
    // Hand-rolled, because DshApiClient always sets them equal — which is the
    // point: this asserts the server enforces the rule the client relies on.
    const response = await fetch(`${new URL(origin).origin}/api/session.list`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'client-request', rpcId: 'smoke-mismatch', method: 'session.create', payload: {} }),
    });
    assert(response.status === 200, `expected 200, got ${response.status}`);
    const body = await response.json() as { result?: { ok?: boolean; error?: { code?: string } } };
    assert(body.result?.ok === false, 'expected a business error');
    return `code: ${body.result?.error?.code ?? 'unknown'}`;
  });

  await check('non-JSON content type is refused at 415', async () => {
    const response = await fetch(`${new URL(origin).origin}/api/session.list`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: JSON.stringify({ type: 'client-request', rpcId: 'smoke-415', method: 'session.list', payload: {} }),
    });
    assert(response.status === 415, `expected 415, got ${response.status}`);
    return '415';
  });

  await check('non-JSON body is refused at 400', async () => {
    const response = await fetch(`${new URL(origin).origin}/api/session.list`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json at all',
    });
    assert(response.status === 400, `expected 400, got ${response.status}`);
    return '400';
  });

  await check('respond to an unknown rpcId returns a receipt, not an error', async () => {
    const receipt = await client.respond('smoke-not-pending', { ok: true });
    assert(receipt.accepted === false, 'expected accepted: false for an unknown rpcId');
    return `reason: ${receipt.accepted ? '(accepted)' : receipt.reason}`;
  });

  await check('every method on the deny list exists upstream', async () => {
    // The deny list is only meaningful if it names real methods. A typo would
    // silently deny nothing. An existing method answers 200 (business error is
    // fine); a nonexistent one answers 404 immediately.
    //
    // Some of these do not answer at all: `host.pickDirectory` opens a native
    // directory dialog and blocks until a human clicks, and `llm.discoverModels`
    // makes the host issue an outbound GET. A short timeout is therefore not a
    // workaround — a method that hangs is *present*, since routing happens
    // before dispatch and an absent path 404s without ever reaching a handler.
    // It is also a live demonstration of why both are denied.
    const missing: string[] = [];
    const blocked: string[] = [];
    for (const method of DENIED_METHODS) {
      let response: Response;
      try {
        response = await fetch(`${new URL(origin).origin}/api/${method}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ type: 'client-request', rpcId: `smoke-deny-${method}`, method, payload: {} }),
          signal: AbortSignal.timeout(3_000),
        });
      } catch {
        blocked.push(method);
        continue;
      }
      if (response.status === 404) missing.push(method);
      await response.body?.cancel();
    }
    assert(missing.length === 0, `not present upstream: ${missing.join(', ')}`);
    const note = blocked.length === 0 ? '' : `; did not answer within 3s (present, and denied for exactly this reason): ${blocked.join(', ')}`;
    return `${DENIED_METHODS.size} method(s) all present${note}`;
  });

  await check('GET /api/events.mux is 426, so a network client must upgrade', async () => {
    // Not a bug and not a workaround. The shipped Web composition intercepts the
    // SSE GET and answers 426 with `upgrade: websocket`; `toFetchHandler`'s SSE
    // codec serves only the in-process (Electron) carrier. bridge/src/dsh/
    // downlink.ts is built on that fact, and this check is what keeps the claim
    // honest against a real server rather than against our reading of the source.
    const response = await fetch(`${new URL(origin).origin}/api/events.mux`, {
      headers: { accept: 'text/event-stream' },
    });
    assert(response.status === 426, `expected 426, got ${response.status}`);
    const upgrade = response.headers.get('upgrade') ?? '';
    assert(upgrade.toLowerCase() === 'websocket', `expected upgrade: websocket, got ${JSON.stringify(upgrade)}`);
    await response.body?.cancel();
    return '426 upgrade: websocket';
  });

  await check('a write path works: session.create then session.list sees it', async () => {
    const created = await client.callOrThrow('session.create', {}) as { sessionId?: unknown };
    const sessionId = created.sessionId;
    assert(typeof sessionId === 'string' && sessionId.length > 0, 'no sessionId returned');
    const listed = await client.callOrThrow('session.list', {}) as { items?: { sessionId?: unknown }[] };
    const found = (listed.items ?? []).some((item) => item.sessionId === sessionId);
    assert(found, `created ${String(sessionId)} but session.list does not show it`);
    return String(sessionId);
  });

  await check('the bridge downlink reads real frames over WebSocket', async () => {
    // The bridge's own reader, unmodified, against the real server. This is the
    // single most load-bearing check in the file: it is the only place the
    // downlink's frame validation meets frames upstream actually emits.
    const downlink = new DshDownlink({ baseUrl: new URL(origin).origin });
    const controller = new AbortController();
    const frames: string[] = [];
    let opened = false;
    const read = (async () => {
      for await (const envelope of downlink.openMux(controller.signal, () => { opened = true; })) {
        frames.push(envelope.frame.type);
        // One frame is enough to prove the socket, the codec, and the validator.
        break;
      }
    })();
    // A read that rejects is a real failure and must not be swallowed by the race.
    let failure: unknown;
    read.catch((error: unknown) => { failure = error; });
    const outcome = await Promise.race([
      read.then(() => 'read', () => 'error'),
      new Promise<string>((resolve) => setTimeout(() => resolve('idle'), 4_000)),
    ]);
    controller.abort();
    if (outcome === 'error') {
      throw failure instanceof Error ? failure : new Error(String(failure));
    }
    // An idle host legitimately has no mux frames to send — the stream carries
    // session activity, and this dsh has no sessions. A clean open is the
    // assertion; a frame, if one arrives, is a bonus.
    assert(opened, 'the WebSocket never reached open');
    return outcome === 'read' ? `frame: ${frames[0] ?? '(none)'}` : 'socket opened, host idle (no frames within 4s)';
  });

  // ── the whole bridge, in front of the real dsh ─────────────────────────────
  //
  // Everything above tests the bridge's dsh-facing half. This stage stands the
  // entire composition up — real TLS listener, real pairing, real policy gate —
  // and drives it the way a phone does, so the forwarded RPC lands on the real
  // server rather than on FakeDshServer.

  const stateDir = mkdtempSync(join(tmpdir(), 'dsh-smoke-bridge-'));
  const built = buildBridge({
    stateDir,
    dshUrl: new URL(origin).origin,
    port: 0,
    host: '127.0.0.1',
    certHosts: ['localhost', '127.0.0.1'],
  });

  try {
    await built.start();
    const address = built.httpsServer.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;

    /**
     * One HTTPS call to the bridge.
     *
     * `node:https` rather than `fetch`, and `rejectUnauthorized: false` rather
     * than a global env flag: the bridge's cert is self-signed by design (the
     * phone pins its SPKI from the QR), and scoping the exception to this one
     * client keeps it from leaking anywhere else in the process.
     */
    async function bridgeCall(
      path: string,
      init: { method?: string; body?: unknown; token?: string } = {},
    ): Promise<{ status: number; body: any }> {
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
              accept: 'application/json',
              ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': payload.byteLength }),
              ...(init.token === undefined ? {} : { authorization: `Bearer ${init.token}` }),
            },
          },
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
        if (payload !== undefined) req.write(payload);
        req.end();
      });
    }

    /**
     * Drive one fresh device to a usable access token, exactly as a phone does:
     * claim, operator confirmation, re-claim, challenge, signature.
     *
     * `pairing.confirm()` stands in for the human at the CLI. The SAS equality
     * the human actually compares is asserted in the unit suite; what matters
     * here is that the path behind it reaches the real server.
     */
    async function pairAndAuthenticate(label: string): Promise<{ deviceId: string; token: string }> {
      const device = generateEd25519KeyPair();
      const session = built.pairing.begin();
      const proof = toBase64Url(
        signMessage(device.privateKey, pairingProofMessage(session.token, built.identity.bridgeId)),
      );
      const claimBody = { token: session.token, devicePublicKey: device.publicKeyB64, label, proof };

      const first = await bridgeCall('/m1/pair/claim', { method: 'POST', body: claimBody });
      assert(first.status === 200, `claim returned ${first.status}`);
      assert(
        first.body?.value?.status === 'awaiting-confirmation',
        `expected awaiting-confirmation, got ${JSON.stringify(first.body).slice(0, 200)}`,
      );

      built.pairing.confirm({ tier: 'default' });

      const paired = await bridgeCall('/m1/pair/claim', { method: 'POST', body: claimBody });
      assert(
        paired.body?.value?.status === 'paired',
        `expected paired, got ${JSON.stringify(paired.body).slice(0, 200)}`,
      );
      const deviceId = paired.body.value.deviceId as string;

      const challenge = await bridgeCall('/m1/auth/session', { method: 'POST', body: { deviceId } });
      assert(challenge.status === 200, `challenge returned ${challenge.status}`);
      const nonce = challenge.body.value.nonce as string;
      const authed = await bridgeCall('/m1/auth/session', {
        method: 'POST',
        body: {
          deviceId,
          nonce,
          signature: toBase64Url(
            signMessage(device.privateKey, authProofMessage(nonce, deviceId, built.identity.bridgeId)),
          ),
        },
      });
      assert(authed.status === 200, `auth returned ${authed.status}`);
      const token = authed.body.value.token as string;
      assert(typeof token === 'string' && token.length > 0, 'no access token issued');
      return { deviceId, token };
    }

    await check('bridge /m1/health reports the real dsh as connected', async () => {
      // Pairing is refused unless dsh is reachable, so this doubles as the gate
      // the two checks below depend on.
      const deadline = Date.now() + 10_000;
      let reply = await bridgeCall('/m1/health');
      while (reply.body?.dshState !== 'connected' && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        reply = await bridgeCall('/m1/health');
      }
      assert(reply.status === 200, `expected 200, got ${reply.status}`);
      assert(reply.body?.ok === true, `health not ok: ${JSON.stringify(reply.body).slice(0, 200)}`);
      assert(
        reply.body.dshState === 'connected',
        `dsh never reached connected: ${JSON.stringify(reply.body).slice(0, 200)}`,
      );
      return `dsh=${String(reply.body.dsh)} state=${String(reply.body.dshState)}`;
    });

    await check('a device pairs and the bridge forwards its rpc to the real dsh', async () => {
      const { deviceId, token } = await pairAndAuthenticate('smoke phone');

      // The payoff: an /m1/rpc the bridge forwards to the REAL dsh.
      const rpc = await bridgeCall('/m1/rpc', {
        method: 'POST',
        token,
        body: { method: 'session.list', payload: {} },
      });
      assert(rpc.status === 200, `rpc returned ${rpc.status}`);
      assert(rpc.body?.ok === true, `rpc envelope not ok: ${JSON.stringify(rpc.body).slice(0, 200)}`);
      const items = rpc.body.value?.items;
      assert(Array.isArray(items), `expected an items array, got ${JSON.stringify(rpc.body.value).slice(0, 200)}`);
      return `device ${deviceId}, ${items.length} session(s) through the bridge`;
    });

    await check('the policy gate refuses a denied method the real dsh would answer', async () => {
      const { token } = await pairAndAuthenticate('smoke phone 2');

      // `settings.describe` exists upstream and would answer. The bridge must
      // refuse it before it ever reaches the socket — 403 from the gate, not a
      // 200 envelope from dsh.
      const denied = await bridgeCall('/m1/rpc', {
        method: 'POST',
        token,
        body: { method: 'settings.describe', payload: {} },
      });
      assert(denied.status === 403, `expected 403 from the gate, got ${denied.status}`);
      assert(
        denied.body?.error?.code === 'method-denied',
        `expected method-denied, got ${JSON.stringify(denied.body).slice(0, 200)}`,
      );
      return `${denied.status} ${String(denied.body.error.code)}`;
    });
  } finally {
    await built.stop();
    rmSync(stateDir, { recursive: true, force: true });
  }

  const failed = checks.filter((c) => !c.ok);
  process.stdout.write(`\n${checks.length - failed.length}/${checks.length} checks passed\n`);
  if (failed.length > 0) {
    process.stdout.write(`failed: ${failed.map((c) => c.name).join('; ')}\n`);
    process.exit(1);
  }
}

await main();

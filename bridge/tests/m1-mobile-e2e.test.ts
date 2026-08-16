/**
 * The RN core against the real bridge and the real relay.
 *
 * Every other mobile test uses a double for the far side. This one does not: a real
 * `RelayServer`, a real `RendezvousListener`, a real bridge with a real
 * `/m1/pair/claim`, a real `FakeDshServer` behind it — and the actual `src/m1` client
 * driving the phone half. Nothing here re-implements the protocol on the phone side,
 * which is the point: the fakes elsewhere encode my understanding of the wire format,
 * and only this file can catch that understanding being wrong.
 *
 * What it proves end to end:
 *
 *   - A relay QR the workstation printed with no knowledge of the phone gets the core
 *     from `unpaired` to `ready` through the sealed tunnel.
 *   - The durable `bridgeRoutingId` the core stores is the one the bridge minted — it
 *     could not have been guessed from the QR, whose `rid` is the rendezvous id.
 *   - Steady-state reconnect works on that durable pair, with the rendezvous long gone.
 *   - Requests, the stream hello and its rotated token, and live envelopes all survive
 *     the round trip through two independent implementations of the seal.
 *
 * ## Why the import of `src/m1` looks odd
 *
 * `bridge/tsconfig.json` compiles this file as CommonJS with `verbatimModuleSyntax`,
 * and `src/m1/core.ts` is ESM authored for Metro. A static import would be TS1287 at
 * `npm run typecheck:bridge`. A dynamic `import()` of a non-literal specifier is not
 * resolved by the compiler at all, so the seam keeps both typechecks clean while
 * vitest still loads the real module. The local interfaces below exist for the same
 * reason: `typeof import('../../src/m1/core')` would drag the module back into the
 * bridge project.
 *
 * Still `[NOT INTEGRATION-TESTED]` after this file: a physical device, a deployed
 * relay behind public WSS, a native build, and NAT rebinding.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RelayServer, RELAY_PATH } from '../src/relay/server.ts';
import { buildBridge, type BuiltBridge } from '../src/bridge.ts';
import { FakeDshServer } from './fake-dsh-server.ts';
import { parsePairingUri } from '../src/identity/pairing.ts';
import type { ControlResponse } from '../src/control.ts';

// ── the seam ────────────────────────────────────────────────────────────────

/** Only what this test touches. See the header for why it is not the real type. */
interface CoreLike {
  getState(): { name: string; [key: string]: unknown };
  getBridge(): Record<string, unknown> | undefined;
  getLastBseq(): number;
  hasToken(): boolean;
  readonly deviceId: string;
  subscribe(listener: (event: Record<string, unknown>) => void): () => void;
  start(): Promise<void>;
  pair(input: { uri: string; label: string }): Promise<{ ok: boolean; [key: string]: unknown }>;
  connect(): Promise<void>;
  reconnectNow(reason: string): Promise<void>;
  rpc<T>(method: string, payload: unknown, requestId?: string): Promise<T>;
  respondApproval(rpcId: string, outcome: 'allowed-once' | 'rejected'): Promise<void>;
  clear(): Promise<void>;
  dispose(): void;
}

interface CoreModule {
  M1Core: new (options: Record<string, unknown>) => CoreLike;
}

interface CryptoModule {
  ed25519PublicKeyFromSeed: (seed: Uint8Array) => Uint8Array;
  deviceIdFromPublicKey: (publicKey: string) => string | undefined;
}

interface BytesModule {
  toBase64Url: (bytes: Uint8Array) => string;
}

interface StateModule {
  isTerminalState: (state: { name: string; [key: string]: unknown }) => boolean;
}

/** Non-literal specifiers: the compiler must not resolve these. See the header. */
const CORE_PATH = '../../src/m1/core';
const CRYPTO_PATH = '../../src/m1/crypto';
const BYTES_PATH = '../../src/m1/bytes';
const STATE_PATH = '../../src/m1/state';

async function loadCore(): Promise<CoreModule> {
  return (await import(/* @vite-ignore */ CORE_PATH)) as unknown as CoreModule;
}

/** The same predicate the UI uses to decide whether retrying is pointless. */
async function loadIsTerminal(): Promise<StateModule['isTerminalState']> {
  return ((await import(/* @vite-ignore */ STATE_PATH)) as unknown as StateModule).isTerminalState;
}

/**
 * Build a device identity from the app's own primitives.
 *
 * Not `src/m1/identity.ts`: that mints and stores the key through
 * `expo-secure-store`, which does not exist here. Deriving it from
 * `ed25519PublicKeyFromSeed` + `deviceIdFromPublicKey` uses the same code the app
 * uses for the parts that matter — the key and the device id — so a change to either
 * derivation breaks this test rather than sliding past it.
 */
async function loadIdentity(seed: number): Promise<{ publicKey: string; privateKey: Uint8Array; deviceId: string }> {
  const crypto = (await import(/* @vite-ignore */ CRYPTO_PATH)) as unknown as CryptoModule;
  const bytes = (await import(/* @vite-ignore */ BYTES_PATH)) as unknown as BytesModule;
  const privateKey = new Uint8Array(32).fill(seed);
  const publicKey = bytes.toBase64Url(crypto.ed25519PublicKeyFromSeed(privateKey));
  const deviceId = crypto.deviceIdFromPublicKey(publicKey);
  if (deviceId === undefined) throw new Error('test seed produced an invalid device id');
  return { publicKey, privateKey, deviceId };
}

// ── helpers ─────────────────────────────────────────────────────────────────

async function until(check: () => boolean, label: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  throw new Error(`timed out waiting for ${label}`);
}

/**
 * Adapt Node's `WebSocket` to the core's `WebSocketLike`.
 *
 * This is the same three-method shim `useDsh.tsx` installs for React Native, which is
 * what makes the adapter itself part of what this test covers.
 */
function nodeSocketFactory(): (url: string, subprotocols: readonly string[]) => unknown {
  return (url, subprotocols) => {
    const socket = new WebSocket(url, [...subprotocols]);
    return {
      send: (data: string) => socket.send(data),
      close: (code?: number, reason?: string) => socket.close(code, reason),
      addEventListener: (type: string, listener: (event: never) => void) => {
        socket.addEventListener(type as 'open', listener as () => void);
      },
    };
  };
}

describe('the RN core against a real relay and a real bridge', () => {
  let dsh: FakeDshServer;
  let relay: RelayServer;
  let relayPort: number;
  let built: BuiltBridge;
  let stateDir: string;
  let core: CoreLike | undefined;
  let stored: Record<string, unknown> | undefined;
  const writes: (Record<string, unknown> | undefined)[] = [];
  const states: { name: string }[] = [];
  const events: Record<string, unknown>[] = [];

  /** A core wired to this relay, with an in-memory store standing in for the keychain. */
  async function buildCore(options: { seed?: number } = {}): Promise<CoreLike> {
    const { M1Core } = await loadCore();
    const identity = await loadIdentity(options.seed ?? 21);
    const instance = new M1Core({
      identity,
      store: {
        read: async () => stored,
        write: async (value: Record<string, unknown> | undefined) => {
          writes.push(value);
          stored = value;
        },
      },
      createSocket: nodeSocketFactory(),
      // `fetch` is never reached on the relay path — every request is a sealed
      // tunnel record — but leaving it unset would hide a Mode A leak behind a
      // confusing `undefined is not a function`.
      fetchImpl: (() => {
        throw new Error('the relay path must not fall back to fetch');
      }) as unknown as typeof fetch,
    });
    instance.subscribe((event) => {
      events.push(event);
      if (event.type === 'state') states.push(event.state as { name: string });
    });
    return instance;
  }

  function openPairing(): {
    messages: ControlResponse[];
    handle: { confirm(accept: boolean): void; cancel(): void };
    uri(): string;
  } {
    const messages: ControlResponse[] = [];
    const handle = built.controlHandlers.beginPair({ tier: 'default', relay: true }, (message) => {
      messages.push(message);
    });
    return {
      messages,
      handle,
      uri: () => {
        const open = messages.find((message) => message.type === 'pair-open');
        if (open?.type !== 'pair-open') throw new Error(`no pair-open; saw ${JSON.stringify(messages)}`);
        return open.uri;
      },
    };
  }

  /** Pair, confirm on the operator side, and wait for a live stream. */
  async function pairAndConnect(): Promise<{ deviceId: string; uri: string }> {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    const uri = pairing.uri();
    core = await buildCore();

    const outcome = core.pair({ uri, label: 'integration phone' });
    // The operator's prompt is driven by the control poll, so it lands a moment
    // after the claim rather than synchronously with it.
    await until(() => pairing.messages.some((message) => message.type === 'pair-claimed'), 'pair-claimed');
    pairing.handle.confirm(true);

    const result = await outcome;
    expect(result.ok).toBe(true);
    const done = pairing.messages.find((message) => message.type === 'pair-done');
    if (done?.type !== 'pair-done') throw new Error('expected pair-done');

    await until(() => core?.getState().name === 'ready', `ready; last was ${JSON.stringify(core?.getState())}`);
    return { deviceId: done.deviceId, uri };
  }

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), 'dshm-m1-e2e-'));
    stored = undefined;
    writes.length = 0;
    states.length = 0;
    events.length = 0;
    dsh = new FakeDshServer();
    const dshPort = await dsh.listen();
    relay = new RelayServer({ frameRatePerMinute: 5_000 });
    relayPort = await relay.listen(0, '127.0.0.1');
    built = buildBridge({
      stateDir,
      dshUrl: `http://127.0.0.1:${dshPort}`,
      host: '127.0.0.1',
      port: 0,
      relayUrl: `ws://127.0.0.1:${relayPort}${RELAY_PATH}`,
    });
    await built.start();
    // Pairing is refused while dsh is unreachable.
    await until(() => built.connection.getState() === 'connected', 'dsh connection');
  });

  afterEach(async () => {
    core?.dispose();
    core = undefined;
    await built.stop();
    await relay.close();
    await dsh.close();
    rmSync(stateDir, { recursive: true, force: true });
  });

  it('pairs from a relay QR and reaches ready through the sealed tunnel', async () => {
    const { deviceId } = await pairAndConnect();

    expect(core?.getState()).toMatchObject({ name: 'ready', dsh: 'up' });
    expect(core?.deviceId).toBe(deviceId);
    expect(core?.hasToken()).toBe(true);

    // The phases the UI shows, in the order the contract promises. `sealing` before
    // `authenticating` is the security-relevant part: no credential is sent until the
    // pinned bridge key has signed the transcript.
    const phases = states
      .filter((state) => state.name === 'connecting')
      .map((state) => (state as unknown as { phase: string }).phase);
    expect(phases.indexOf('relay')).toBeLessThan(phases.indexOf('authenticating'));
    expect(phases).toContain('sealing');
  });

  it('stores the durable route the bridge minted, not the rendezvous id from the QR', async () => {
    const { deviceId, uri } = await pairAndConnect();
    const qr = parsePairingUri(uri);
    if (qr === undefined) throw new Error('unparseable QR');

    const route = built.identity.routeFor(deviceId);
    expect(route).toBeDefined();
    expect(stored).toMatchObject({
      mode: 'relay',
      bridgeId: built.identity.bridgeId,
      bridgeKey: built.identity.publicKeyB64,
      bridgeRoutingId: route?.routingId,
      deviceRoutingId: route?.peerRoutingId,
    });

    // The whole reason `rid` must never be treated as durable: the stored id is a
    // different value, and a phone that kept the QR's would dial a rendezvous that
    // expired 120 seconds after it was printed.
    expect(stored?.bridgeRoutingId).not.toBe(qr.routingId);
    expect(stored?.deviceRoutingId).not.toBe(qr.routingId);
  });

  it('never persists a token, on any of the writes it made', async () => {
    await pairAndConnect();
    expect(writes.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(writes);
    expect(serialized).not.toMatch(/"token"/);
    // The pairing token is single-use and worthless afterwards, but it is still a
    // credential and still must not land in the keychain record.
    expect(serialized).not.toMatch(/access-token/);
  });

  it('serves an rpc over the tunnel and gets a real dsh answer', async () => {
    await pairAndConnect();

    const result = await core!.rpc<{ sessions: unknown[] }>('session.list', {});
    // Answered by FakeDshServer through the bridge, the relay, and the seal.
    expect(Array.isArray(result.sessions)).toBe(true);
  });

  it('reports a policy refusal as a bridge error and keeps the session up', async () => {
    await pairAndConnect();

    // `settings.update` is on the hard deny-list, so the bridge refuses without
    // asking dsh. The phone must get a coded error, not a disconnection.
    await expect(core!.rpc('settings.update', { key: 'x' })).rejects.toMatchObject({ code: 'method-denied' });
    // Nothing reached the harness — a bridge that forwarded and then reported a
    // denial would pass a status-only assertion.
    expect(dsh.calls.some((call) => call.method === 'settings.update')).toBe(false);
    // And the refusal did not cost us the session.
    expect(core?.getState().name).toBe('ready');
    expect(core?.hasToken()).toBe(true);
  });

  it('delivers a live mux envelope pushed by the harness, with an rpcId', async () => {
    await pairAndConnect();
    const before = core!.getLastBseq();

    // The real shape: a `server-request` whose payload is the mux frame. An
    // answerable frame specifically, so the rpcId the phone needs in order to reply
    // is proven to survive the tunnel.
    dsh.broadcast(
      {
        type: 'server-request',
        rpcId: 'e2e-mobile-1',
        method: 'events.mux',
        payload: { type: 'approval/requested', sessionId: 's-1', approvalId: 'a-1', toolName: 'shell' },
      },
      'mux',
    );

    await until(
      () => events.some((event) => event.type === 'envelope' && (event.envelope as { kind: string }).kind === 'mux'),
      'a forwarded mux envelope',
    );
    const forwarded = events
      .filter((event) => event.type === 'envelope')
      .map((event) => event.envelope as { kind: string; bseq: number; rpcId?: string; frame: Record<string, unknown> })
      .find((envelope) => envelope.kind === 'mux');
    expect(forwarded?.rpcId).toBe('e2e-mobile-1');
    expect(forwarded?.frame.approvalId).toBe('a-1');
    expect(forwarded?.bseq).toBeGreaterThan(before);
    expect(core!.getLastBseq()).toBe(forwarded?.bseq);
  });

  it('answers an approval over the tunnel', async () => {
    await pairAndConnect();
    dsh.broadcast(
      {
        type: 'server-request',
        rpcId: 'e2e-mobile-2',
        method: 'events.mux',
        payload: { type: 'approval/requested', sessionId: 's-1', approvalId: 'a-2', toolName: 'shell' },
      },
      'mux',
    );
    await until(
      () => events.some((event) => event.type === 'envelope' && (event.envelope as { rpcId?: string }).rpcId === 'e2e-mobile-2'),
      'the approval envelope',
    );

    await core!.respondApproval('e2e-mobile-2', 'allowed-once');
    // The answer went upstream as a `client-response`, which is the only way an
    // approval can be resolved.
    await until(() => dsh.lastRespondResult !== undefined, 'the forwarded response');
    expect(dsh.calls.some((call) => call.method === 'respond')).toBe(true);
  });

  it('reconnects on the durable route with the rendezvous long gone', async () => {
    await pairAndConnect();
    const bseq = core!.getLastBseq();

    await core!.reconnectNow('integration test');
    await until(() => core?.getState().name === 'ready', 'ready again');

    // A second full session on the stored pair: the rendezvous listener is closed and
    // the pairing token is spent, so nothing from the QR is in play any more.
    expect(core?.hasToken()).toBe(true);
    expect(core!.getLastBseq()).toBeGreaterThanOrEqual(bseq);
    const hellos = events.filter((event) => event.type === 'hello');
    expect(hellos.length).toBeGreaterThanOrEqual(2);
  });

  it('rotates the token on every stream hello', async () => {
    await pairAndConnect();
    const first = (events.find((event) => event.type === 'hello')?.hello as { token: string }).token;

    await core!.reconnectNow('integration test');
    await until(() => events.filter((event) => event.type === 'hello').length >= 2, 'a second hello');

    const hellos = events.filter((event) => event.type === 'hello').map((event) => (event.hello as { token: string }).token);
    // A fresh token per stream, and it is the rotated one the core then uses.
    expect(hellos[1]).not.toBe(first);
    expect(core?.hasToken()).toBe(true);
  });

  it('starts from the stored route on a fresh core, with no QR at all', async () => {
    await pairAndConnect();
    core?.dispose();
    const route = stored;

    // A relaunch: new core, same keychain contents, no pairing interaction.
    core = await buildCore();
    await core.start();
    await until(() => core?.getState().name === 'ready', 'ready from storage');

    expect(stored).toEqual(route);
    const result = await core.rpc<{ sessions: unknown[] }>('session.list', {});
    expect(Array.isArray(result.sessions)).toBe(true);
  });

  /**
   * The phone's half of revocation, driven by the signal the bridge is supposed to
   * send.
   *
   * `hub.disconnectDevice` is exactly what `registry.onRevocation` invokes
   * (bridge/src/http/server.ts), so this is the real frame on the real path — only the
   * trigger is direct, which keeps the bridge-side ordering bug in the test below from
   * hiding whether the core handles the frame at all.
   */
  it('goes revoked and wipes the route when the device-revoked frame arrives', async () => {
    const { deviceId } = await pairAndConnect();
    const seen: string[] = [];
    const stop = core!.subscribe((event) => {
      if (event.type === 'state') seen.push((event.state as { name: string }).name);
    });

    expect(built.hub.disconnectDevice(deviceId)).toBe(1);
    try {
      await until(
        () => core?.getState().name === 'revoked',
        `revoked; saw ${JSON.stringify(seen)}, resting at ${JSON.stringify(core?.getState())}`,
      );
    } finally {
      stop();
    }

    expect(stored).toBeUndefined();
    expect(core?.hasToken()).toBe(false);
    // Terminal: no reconnect may follow, or a revoked phone would spin forever
    // against a bridge that will never let it in.
    await core!.connect();
    expect(core?.getState().name).toBe('revoked');
  });

  /**
   * The operator's `revoke` now reaches the phone as `device-revoked`.
   *
   * `controlHandlers.revoke` fires the revocation listeners — the hub queues
   * `device-revoked` onto the carrier stream, and the connector teardown is *deferred*
   * by a bounded linger (bridge/src/bridge.ts, {@link REVOCATION_LINGER_MS}) so the
   * frame flushes through hub → carrier socket → connector → seal → relay → phone
   * before the tunnel is torn down. The phone therefore lands in the terminal
   * `revoked` state, identically to the direct-frame test above — the earlier
   * ordering bug that stranded it in `relay-unavailable` is fixed.
   */
  it('goes revoked when the operator revokes, and the reason reaches the phone', async () => {
    const { deviceId } = await pairAndConnect();

    expect(built.controlHandlers.revoke(deviceId).ok).toBe(true);
    await until(
      () => core?.getState().name === 'revoked',
      `revoked; resting at ${JSON.stringify(core?.getState())}`,
    );

    // Terminal and credential-free: nothing can be replayed, and the phone will not
    // retry against a bridge that will never let it in.
    expect(core?.getState().name).toBe('revoked');
    expect(core?.hasToken()).toBe(false);
    const isTerminalState = await loadIsTerminal();
    expect(isTerminalState(core!.getState())).toBe(true);

    // The bridge dropped the stream subscriber and the route.
    expect(built.hub.stats().subscribers).toBe(0);
    expect(built.identity.routeFor(deviceId)).toBeUndefined();

    // Revocation is terminal, so a fresh connect stays revoked rather than redialing.
    await core!.connect();
    expect(core?.getState().name).toBe('revoked');
  });

  /**
   * An operator decline over the relay now reaches the phone as `pairing-rejected`.
   *
   * `confirm(false)` calls `pairing.reject()` (which keeps the session in `failed`,
   * not `cancel()` which would erase it) and lingers the rendezvous instead of closing
   * it in the same tick (bridge/src/bridge.ts). The phone's next proof-authenticated
   * poll therefore reads the 403 `pairing-rejected` the LAN path always gave it, so
   * Mode B can now say "declined on the workstation" rather than only "the tunnel
   * vanished". It still fails closed and stores nothing.
   */
  it('reports pairing-rejected and stores nothing when the operator declines over the relay', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    core = await buildCore();

    const outcome = core.pair({ uri: pairing.uri(), label: 'declined phone' });
    await until(() => pairing.messages.some((message) => message.type === 'pair-claimed'), 'pair-claimed');
    pairing.handle.confirm(false);

    const result = await outcome;
    expect(result.ok).toBe(false);
    // The decline now arrives as an explicit refusal, read from the lingering
    // rendezvous, not as a dead tunnel.
    expect(result.failure).toMatchObject({ kind: 'pairing-rejected' });
    // Terminal: the same QR will never work again, so the UI must offer a fresh scan
    // rather than a spinner.
    expect(core.getState()).toEqual({ name: 'unpaired', reason: 'pairing-rejected' });
    const isTerminalState = await loadIsTerminal();
    expect(isTerminalState(core.getState())).toBe(true);
    // The half-finished pairing left nothing behind on either side.
    expect(stored).toBeUndefined();
    expect(core.hasToken()).toBe(false);
    expect(Object.keys(built.identity.routes())).toEqual([]);
  });

  it('refuses a second pairing with a spent token', async () => {
    const { uri } = await pairAndConnect();
    core?.dispose();

    // The token was consumed by the first claim. A phone that re-scanned the same QR
    // must land in a recoverable state, not a half-paired one.
    core = await buildCore({ seed: 22 });
    const result = await core.pair({ uri, label: 'second phone' });
    expect(result.ok).toBe(false);
    expect(core.getState().name).toBe('unpaired');
  });

  it('rejects a QR whose pinned bridge key was tampered with', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    const qr = parsePairingUri(pairing.uri());
    if (qr === undefined) throw new Error('unparseable QR');

    // Swap `bk` for another valid Ed25519 key: exactly what a QR-substitution attack
    // looks like. The bridge cannot sign the transcript under it, so the seal must
    // fail before any application byte — and certainly before the device proof.
    const impostor = built.identity.publicKeyB64.startsWith('A')
      ? `B${built.identity.publicKeyB64.slice(1)}`
      : `A${built.identity.publicKeyB64.slice(1)}`;
    const tampered = pairing.uri().replace(encodeURIComponent(built.identity.publicKeyB64), encodeURIComponent(impostor));
    expect(tampered).not.toBe(pairing.uri());

    core = await buildCore();
    const result = await core.pair({ uri: tampered, label: 'mitm victim' });
    expect(result.ok).toBe(false);
    expect(stored).toBeUndefined();
    // Never `paired`, and never a state that offers the user a way to continue.
    expect(['pin-mismatch', 'unpaired', 'relay-unavailable']).toContain(core.getState().name);
    pairing.handle.cancel();
  });

  it('clear wipes the route and leaves the bridge listing the device', async () => {
    const { deviceId } = await pairAndConnect();

    await core!.clear();
    expect(core?.getState()).toEqual({ name: 'unpaired', reason: 'cleared' });
    expect(stored).toBeUndefined();
    // The bridge still has the route: unpairing on the phone is not revocation, and
    // the operator's list is the operator's to change.
    expect(built.identity.routeFor(deviceId)).toBeDefined();
  });
});

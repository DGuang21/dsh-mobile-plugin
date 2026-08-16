/**
 * Mode B first-pair rendezvous tests.
 *
 * These drive the whole path a phone would: a real `RelayServer`, a real
 * `RendezvousListener`, a real `LocalBridgeBackend` over a Unix socket, and a real
 * `/m1/pair/claim` handler behind it. The phone half is written against the same
 * public seal API the RN client uses, so the transcript rules are exercised by two
 * independent callers rather than by one helper talking to itself.
 *
 * The property that matters most and is asserted directly: a workstation can print a
 * relay QR code without knowing anything about the phone, and the phone can complete
 * a first pairing through it.
 *
 * What these do NOT cover: a real phone, a deployed relay, TLS termination, and NAT
 * rebinding. All still `[NOT INTEGRATION-TESTED]`.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RelayServer, RELAY_PATH } from '../src/relay/server.ts';
import { RELAY_SUBPROTOCOL } from '../src/relay/protocol.ts';
import {
  beginPairingHandshake,
  completePairingHandshakeAsBridge,
  completePairingHandshakeAsPhone,
  newRoutingId,
  pairingTokenBinder,
  signHandshake,
  verifyDeferredPeerProof,
  type SealedChannel,
} from '../src/relay/seal.ts';
import { buildBridge, type BuiltBridge } from '../src/bridge.ts';
import { FakeDshServer } from './fake-dsh-server.ts';
import { generateEd25519KeyPair, signMessage, toBase64Url } from '../src/identity/crypto.ts';
import { deriveRendezvousRoutingId, pairingProofMessage, parsePairingUri } from '../src/identity/pairing.ts';
import type { ControlResponse } from '../src/control.ts';

/** Poll until `check` passes, so nothing depends on a fixed sleep. */
async function until(check: () => boolean, label: string, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`timed out waiting for ${label}`);
}

/**
 * A phone doing a first pairing over a relay.
 *
 * Written against `parsePairingUri` and the seal API only — it is given no bridge
 * internals — because that is exactly the position the RN client is in.
 */
class RendezvousPhone {
  readonly received: Record<string, unknown>[] = [];
  readonly tunnelMessages: Record<string, unknown>[] = [];
  readonly routingId = newRoutingId();
  private socket: WebSocket | undefined;
  private channel: SealedChannel | undefined;
  private keys = generateEd25519KeyPair();

  constructor(
    private readonly qr: NonNullable<ReturnType<typeof parsePairingUri>>,
    private readonly label = 'rendezvous phone',
  ) {}

  get devicePublicKey(): string {
    return this.keys.publicKeyB64;
  }

  /** The rendezvous id the phone computes for itself, from the token. */
  get expectedRendezvousId(): string {
    return deriveRendezvousRoutingId(this.qr.token, this.qr.bridgeId);
  }

  async connect(relayPort: number, options: { routingId?: string } = {}): Promise<void> {
    const socket = new WebSocket(`ws://127.0.0.1:${relayPort}${RELAY_PATH}`, [RELAY_SUBPROTOCOL]);
    this.socket = socket;
    socket.addEventListener('message', (event) => {
      if (typeof event.data === 'string') this.received.push(JSON.parse(event.data) as Record<string, unknown>);
    });
    await new Promise<void>((resolve, reject) => {
      socket.addEventListener('open', () => resolve());
      socket.addEventListener('error', () => reject(new Error('relay dial failed')));
    });
    // The phone mints its OWN routing id and names the rendezvous. Nothing about it
    // had to be known by the workstation in advance.
    this.send({
      v: 1,
      type: 'relay/register',
      role: 'phone',
      routingId: options.routingId ?? this.routingId,
      mode: 'peer',
      peerRoutingId: this.qr.routingId,
    });
    await this.wait('relay/registered');
  }

  /** Run the pairing handshake to completion. Throws if the bridge cannot prove itself. */
  async establish(options: { tokenOverride?: string } = {}): Promise<void> {
    const binder = pairingTokenBinder(options.tokenOverride ?? this.qr.token, this.qr.bridgeId);
    const handshake = beginPairingHandshake({
      role: 'initiator',
      // The bridge builds `${phoneRoutingId}:${rendezvousId}`.
      sessionId: `${this.routingId}:${this.qr.routingId as string}`,
      bridgeStaticPublicKey: this.qr.bridgeKey,
      tokenBinder: binder,
    });
    this.send({ v: 1, type: 'relay/handshake', hs: { v: 1, eph: handshake.message.eph, sig: '' } });

    const signed = await this.waitSignedHandshake();
    // Round two: the phone signs the transcript with its DEVICE key. The bridge
    // cannot check it yet; it retains it until the claim reveals the key.
    const sig = signHandshake(handshake, signed.eph, this.keys.privateKey);
    this.send({ v: 1, type: 'relay/handshake', hs: { v: 1, eph: handshake.message.eph, sig } });

    const completed = completePairingHandshakeAsPhone({ handshake, peerMessage: { v: 1, eph: signed.eph, sig: signed.sig } });
    if (!completed.ok) throw new Error(`phone could not verify the bridge: ${completed.reason}`);
    this.channel = completed.channel;
  }

  /** The claim body, signed with the device key exactly as a LAN claim would be. */
  claimBody(options: { routingId?: string; token?: string } = {}): Record<string, unknown> {
    const token = options.token ?? this.qr.token;
    return {
      token,
      devicePublicKey: this.keys.publicKeyB64,
      label: this.label,
      proof: toBase64Url(signMessage(this.keys.privateKey, pairingProofMessage(token, this.qr.bridgeId))),
      relayRoutingId: options.routingId ?? this.routingId,
    };
  }

  sendTunnel(message: unknown): void {
    if (this.channel === undefined) throw new Error('pairing channel not established');
    this.send({ v: 1, type: 'relay/data', record: this.channel.sealJson(message) });
  }

  /** POST the claim through the sealed channel and return the response body. */
  async claim(id: string, options: { routingId?: string; token?: string } = {}): Promise<Record<string, unknown>> {
    this.sendTunnel({
      v: 1,
      type: 'tunnel/request',
      id,
      method: 'POST',
      path: '/m1/pair/claim',
      body: this.claimBody(options),
    });
    const response = await this.waitTunnel((message) => message.type === 'tunnel/response' && message.id === id);
    return response;
  }

  send(message: unknown): void {
    this.socket?.send(JSON.stringify(message));
  }

  close(): void {
    this.socket?.close(1000, 'test done');
  }

  drain(): Record<string, unknown>[] {
    if (this.channel === undefined) return [];
    for (const message of this.received) {
      if (message.type !== 'relay/data' || message.__drained === true) continue;
      message.__drained = true;
      const opened = this.channel.openJson(message.record);
      if (opened.ok) this.tunnelMessages.push(opened.value as Record<string, unknown>);
    }
    return this.tunnelMessages;
  }

  async wait(type: string, timeoutMs = 3_000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = this.received.find((message) => message.type === type);
      if (found !== undefined) return found;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${type}; saw ${JSON.stringify(this.received)}`);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  async waitTunnel(match: (message: Record<string, unknown>) => boolean, timeoutMs = 3_000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = this.drain().find(match);
      if (found !== undefined) return found;
      if (Date.now() > deadline) throw new Error(`timed out waiting for a tunnel message; saw ${JSON.stringify(this.tunnelMessages)}`);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  private async waitSignedHandshake(): Promise<{ eph: string; sig: string }> {
    const deadline = Date.now() + 3_000;
    for (;;) {
      for (const message of this.received) {
        if (message.type !== 'relay/handshake') continue;
        const hs = message.hs as { eph?: string; sig?: string };
        if (typeof hs?.eph === 'string' && typeof hs.sig === 'string' && hs.sig.length > 0) {
          return { eph: hs.eph, sig: hs.sig };
        }
      }
      if (Date.now() > deadline) throw new Error('no signed handshake from the bridge');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

describe('rendezvous id derivation', () => {
  it('is deterministic and computable from the token alone', () => {
    const token = 'a'.repeat(43);
    const bridgeId = 'bridge-1';
    // The whole point: two parties who share only the token agree on the id.
    expect(deriveRendezvousRoutingId(token, bridgeId)).toBe(deriveRendezvousRoutingId(token, bridgeId));
  });

  it('produces a valid 22-character routing id', () => {
    const id = deriveRendezvousRoutingId('t'.repeat(43), 'bridge-1');
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it('differs per token and per bridge', () => {
    const a = deriveRendezvousRoutingId('token-a', 'bridge-1');
    expect(deriveRendezvousRoutingId('token-b', 'bridge-1')).not.toBe(a);
    expect(deriveRendezvousRoutingId('token-a', 'bridge-2')).not.toBe(a);
  });

  it('is domain-separated from the token binder', () => {
    // Both are derived from the same two inputs. If they collided, a value meant for
    // routing could be replayed as a key-agreement binder.
    const id = deriveRendezvousRoutingId('token-a', 'bridge-1');
    expect(pairingTokenBinder('token-a', 'bridge-1')).not.toBe(id);
  });
});

describe('pairing handshake', () => {
  const bridge = generateEd25519KeyPair();
  const device = generateEd25519KeyPair();
  const binder = pairingTokenBinder('token-xyz', 'bridge-1');
  const sessionId = 'phone-rid:rendezvous-rid';

  /** Drive both halves in-process, returning what each side ended up with. */
  function exchange(options: { phoneBinder?: string; signWith?: typeof device.privateKey } = {}) {
    const phone = beginPairingHandshake({
      role: 'initiator',
      sessionId,
      bridgeStaticPublicKey: bridge.publicKeyB64,
      tokenBinder: options.phoneBinder ?? binder,
    });
    const bridgeSide = beginPairingHandshake({
      role: 'responder',
      sessionId,
      bridgeStaticPublicKey: bridge.publicKeyB64,
      tokenBinder: binder,
    });

    const bridgeSig = signHandshake(bridgeSide, phone.message.eph, bridge.privateKey);
    const phoneSig = signHandshake(phone, bridgeSide.message.eph, options.signWith ?? device.privateKey);

    return {
      phoneResult: completePairingHandshakeAsPhone({
        handshake: phone,
        peerMessage: { v: 1, eph: bridgeSide.message.eph, sig: bridgeSig },
      }),
      bridgeResult: completePairingHandshakeAsBridge(bridgeSide, { v: 1, eph: phone.message.eph, sig: phoneSig }),
    };
  }

  it('agrees on keys and lets both sides talk', () => {
    const { phoneResult, bridgeResult } = exchange();
    expect(phoneResult.ok).toBe(true);
    expect(bridgeResult.ok).toBe(true);
    if (!phoneResult.ok || !bridgeResult.ok) return;

    const sealed = phoneResult.channel.sealJson({ hello: 'from phone' });
    expect(bridgeResult.channel.openJson(sealed)).toEqual({ ok: true, value: { hello: 'from phone' } });
    const back = bridgeResult.channel.sealJson({ hello: 'from bridge' });
    expect(phoneResult.channel.openJson(back)).toEqual({ ok: true, value: { hello: 'from bridge' } });
  });

  it('lets the bridge verify the device key after the fact', () => {
    const { bridgeResult } = exchange();
    expect(bridgeResult.ok).toBe(true);
    if (!bridgeResult.ok) return;
    expect(verifyDeferredPeerProof(bridgeResult.deferred, device.publicKeyB64)).toBe(true);
  });

  it('refuses a claim whose device key did not establish the channel', () => {
    const { bridgeResult } = exchange();
    expect(bridgeResult.ok).toBe(true);
    if (!bridgeResult.ok) return;
    // This is what stops a relay from splicing one device's channel onto another
    // device's claim body.
    const impostor = generateEd25519KeyPair();
    expect(verifyDeferredPeerProof(bridgeResult.deferred, impostor.publicKeyB64)).toBe(false);
  });

  it('refuses a device key that is not a valid Ed25519 key', () => {
    const { bridgeResult } = exchange();
    if (!bridgeResult.ok) throw new Error('handshake should have completed');
    expect(verifyDeferredPeerProof(bridgeResult.deferred, 'not-base64url!!')).toBe(false);
    expect(verifyDeferredPeerProof(bridgeResult.deferred, toBase64Url(Buffer.alloc(31)))).toBe(false);
  });

  it('rejects the bridge if it cannot sign with the pinned static key', () => {
    const phone = beginPairingHandshake({
      role: 'initiator',
      sessionId,
      bridgeStaticPublicKey: bridge.publicKeyB64,
      tokenBinder: binder,
    });
    const impostor = generateEd25519KeyPair();
    const impostorSide = beginPairingHandshake({
      role: 'responder',
      sessionId,
      // An attacker in the path can copy the QR's bridge key into its transcript,
      // but it cannot produce a signature over it.
      bridgeStaticPublicKey: bridge.publicKeyB64,
      tokenBinder: binder,
    });
    const forged = signHandshake(impostorSide, phone.message.eph, impostor.privateKey);
    const result = completePairingHandshakeAsPhone({
      handshake: phone,
      peerMessage: { v: 1, eph: impostorSide.message.eph, sig: forged },
    });
    expect(result).toMatchObject({ ok: false, reason: 'bad-signature' });
  });

  it('produces unopenable records when the binder differs', () => {
    // Someone who never saw the QR cannot compute the binder, so the transcript —
    // and therefore the derived keys — differ, and the first record fails to open.
    const { phoneResult, bridgeResult } = exchange({ phoneBinder: pairingTokenBinder('wrong-token', 'bridge-1') });
    // The phone's own check fails first, because the transcript it verifies against
    // is not the one the bridge signed.
    expect(phoneResult).toMatchObject({ ok: false, reason: 'bad-signature' });
    expect(bridgeResult.ok).toBe(true);
    if (!bridgeResult.ok) return;
    // And the retained proof does not verify either, so the claim would be refused.
    expect(verifyDeferredPeerProof(bridgeResult.deferred, device.publicKeyB64)).toBe(false);
  });

  it('rejects a malformed peer message on the bridge side', () => {
    const bridgeSide = beginPairingHandshake({
      role: 'responder',
      sessionId,
      bridgeStaticPublicKey: bridge.publicKeyB64,
      tokenBinder: binder,
    });
    expect(completePairingHandshakeAsBridge(bridgeSide, null)).toMatchObject({ ok: false, reason: 'bad-version' });
    expect(completePairingHandshakeAsBridge(bridgeSide, { v: 2, eph: 'x', sig: 'y' })).toMatchObject({ ok: false, reason: 'bad-version' });
    expect(completePairingHandshakeAsBridge(bridgeSide, { v: 1, eph: 42, sig: 'y' })).toMatchObject({ ok: false, reason: 'bad-ephemeral' });
    expect(completePairingHandshakeAsBridge(bridgeSide, { v: 1, eph: 'not-a-key', sig: 'y' })).toMatchObject({
      ok: false,
      reason: 'bad-ephemeral',
    });
  });

  it('rejects an all-zero ephemeral', () => {
    const bridgeSide = beginPairingHandshake({
      role: 'responder',
      sessionId,
      bridgeStaticPublicKey: bridge.publicKeyB64,
      tokenBinder: binder,
    });
    // A low-order point would yield a shared secret the attacker also knows.
    const result = completePairingHandshakeAsBridge(bridgeSide, {
      v: 1,
      eph: toBase64Url(Buffer.alloc(32)),
      sig: 'AAAA',
    });
    expect(result).toMatchObject({ ok: false, reason: 'key-agreement-failed' });
  });
});

describe('mode B first pairing end to end', () => {
  let dsh: FakeDshServer;
  let relay: RelayServer;
  let relayPort: number;
  let built: BuiltBridge;
  let stateDir: string;
  let phone: RendezvousPhone | undefined;

  /** Open a pairing window and collect the control messages it emits. */
  function openPairing(): {
    messages: ControlResponse[];
    handle: { confirm(accept: boolean): void; cancel(): void };
    qr(): NonNullable<ReturnType<typeof parsePairingUri>>;
  } {
    const messages: ControlResponse[] = [];
    const handle = built.controlHandlers.beginPair({ tier: 'default', relay: true }, (message) => {
      messages.push(message);
    });
    return {
      messages,
      handle,
      qr: () => {
        const open = messages.find((message) => message.type === 'pair-open');
        if (open === undefined || open.type !== 'pair-open') throw new Error(`no pair-open; saw ${JSON.stringify(messages)}`);
        const parsed = parsePairingUri(open.uri);
        if (parsed === undefined) throw new Error(`unparseable QR: ${open.uri}`);
        return parsed;
      },
    };
  }

  beforeEach(async () => {
    stateDir = mkdtempSync(join(tmpdir(), 'dshm-rdv-'));
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
    // Pairing is refused while dsh is unreachable, so every case needs this first.
    await until(() => built.connection.getState() === 'connected', 'dsh connection');
  });

  afterEach(async () => {
    phone?.close();
    phone = undefined;
    await built.stop();
    await relay.close();
    await dsh.close();
    rmSync(stateDir, { recursive: true, force: true });
  });

  it('gives the carrier socket owner-only permissions', () => {
    // The carrier serves the entire `/m1` router, so its reachability is an
    // authorization question. `stateDir` is created 0o700, but `mkdirSync` does
    // not reapply a mode to a directory that already exists — an operator
    // pointing --state-dir at a pre-existing 0o755 directory would hand every
    // local user the pre-auth routes and the pairing window. The explicit chmod
    // is what makes that harmless, so it is asserted rather than assumed.
    expect(statSync(built.carrierSocketPath).mode & 0o777).toBe(0o600);
  });

  it('prints a relay QR without being told any phone routing id', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    const qr = pairing.qr();

    // The regression this whole change exists to fix: no `--peer-routing-id`, no
    // phone involvement, and a QR that is nonetheless dialable.
    expect(qr.relay).toBe(`ws://127.0.0.1:${relayPort}${RELAY_PATH}`);
    expect(qr.routingId).toBe(deriveRendezvousRoutingId(qr.token, built.identity.bridgeId));
    expect(qr.bridgeKey).toBe(built.identity.publicKeyB64);
    // Mode B pins the bridge's static key, not a TLS fingerprint: there is no TLS
    // session to pin when the relay terminates it.
    expect(qr.fingerprint).toBeUndefined();
    pairing.handle.cancel();
  });

  it('lets a phone verify the QR routing id itself', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    const qr = pairing.qr();
    phone = new RendezvousPhone(qr);
    // Equal by construction, so a mismatch means the QR was altered in transit.
    expect(phone.expectedRendezvousId).toBe(qr.routingId);
    pairing.handle.cancel();
  });

  it('completes a first pairing through the relay and returns a durable route', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    const qr = pairing.qr();

    phone = new RendezvousPhone(qr);
    await phone.connect(relayPort);
    await phone.establish();

    // ── claim ───────────────────────────────────────────────────────────────
    const first = await phone.claim('c1');
    expect(first.status).toBe(200);
    const firstBody = first.body as { ok: boolean; value: Record<string, unknown> };
    expect(firstBody.ok).toBe(true);
    expect(firstBody.value.status).toBe('awaiting-confirmation');
    // The SAS the phone shows must equal the one the operator is asked about.
    expect(firstBody.value.sas).toBe(built.pairing.current()?.sas);

    // The operator's prompt is driven by the control poll, so it arrives shortly
    // after the claim rather than synchronously with it.
    await until(() => pairing.messages.some((message) => message.type === 'pair-claimed'), 'pair-claimed');
    const claimed = pairing.messages.find((message) => message.type === 'pair-claimed');
    expect(claimed).toMatchObject({ type: 'pair-claimed', label: 'rendezvous phone' });
    if (claimed?.type !== 'pair-claimed') throw new Error('expected pair-claimed');
    expect(claimed.sas).toBe(built.pairing.current()?.sas);

    // ── operator confirms ───────────────────────────────────────────────────
    pairing.handle.confirm(true);
    const done = pairing.messages.find((message) => message.type === 'pair-done');
    expect(done).toBeDefined();
    if (done?.type !== 'pair-done') throw new Error('expected pair-done');

    // ── the phone learns the bridge routing id it could not have known ──────
    const second = await phone.claim('c2');
    const secondBody = second.body as { ok: boolean; value: Record<string, unknown> };
    expect(secondBody.value.status).toBe('paired');
    expect(secondBody.value.deviceId).toBe(done.deviceId);
    const relayInfo = secondBody.value.relay as { bridgeRoutingId: string; peerRoutingId: string };
    expect(relayInfo.peerRoutingId).toBe(phone.routingId);

    // ── and the bridge persisted the matching half ──────────────────────────
    const route = built.identity.routeFor(done.deviceId);
    expect(route).toBeDefined();
    expect(route?.routingId).toBe(relayInfo.bridgeRoutingId);
    expect(route?.peerRoutingId).toBe(phone.routingId);
    expect(route?.peerStaticPublicKey).toBe(phone.devicePublicKey);

    // A steady-state connector now exists for that device, dialing the pair the
    // phone just agreed to.
    await until(() => built.connectors.has(done.deviceId), 'a steady-state connector');
  });

  it('records the route even if the phone never polls again', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    phone = new RendezvousPhone(pairing.qr());
    await phone.connect(relayPort);
    await phone.establish();
    await phone.claim('c1');

    pairing.handle.confirm(true);
    const done = pairing.messages.find((message) => message.type === 'pair-done');
    if (done?.type !== 'pair-done') throw new Error('expected pair-done');

    // A phone that is killed right after the operator taps confirm must still end up
    // with a route; otherwise it looks paired but can never connect.
    const route = built.identity.routeFor(done.deviceId);
    expect(route?.peerRoutingId).toBe(phone.routingId);
  });

  it('refuses a claim whose device key did not establish the channel', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    const qr = pairing.qr();
    phone = new RendezvousPhone(qr);
    await phone.connect(relayPort);
    await phone.establish();

    // A different key's claim body, replayed over this channel. The deferred proof
    // is what refuses it.
    const impostor = generateEd25519KeyPair();
    phone.sendTunnel({
      v: 1,
      type: 'tunnel/request',
      id: 'x1',
      method: 'POST',
      path: '/m1/pair/claim',
      body: {
        token: qr.token,
        devicePublicKey: impostor.publicKeyB64,
        label: 'impostor',
        proof: toBase64Url(signMessage(impostor.privateKey, pairingProofMessage(qr.token, qr.bridgeId))),
        relayRoutingId: phone.routingId,
      },
    });

    // The bridge drops the channel rather than answering, so nothing reaches the
    // pairing manager and the token stays unspent.
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(phone.drain().some((message) => message.type === 'tunnel/response')).toBe(false);
    expect(built.pairing.current()?.state).toBe('awaiting-claim');
    pairing.handle.cancel();
  });

  it('refuses a claim that omits the phone routing id', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    const qr = pairing.qr();
    phone = new RendezvousPhone(qr);
    await phone.connect(relayPort);
    await phone.establish();

    const body = phone.claimBody();
    delete body.relayRoutingId;
    phone.sendTunnel({ v: 1, type: 'tunnel/request', id: 'x2', method: 'POST', path: '/m1/pair/claim', body });

    const response = await phone.waitTunnel((message) => message.type === 'tunnel/response');
    expect(response.status).toBe(400);
    // Refused before the claim is replayed: the token must not be spent by a request
    // that could not have produced a usable route anyway.
    expect(built.pairing.current()?.state).toBe('awaiting-claim');
    pairing.handle.cancel();
  });

  it('refuses a malformed routing id in the claim', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    phone = new RendezvousPhone(pairing.qr());
    await phone.connect(relayPort);
    await phone.establish();

    const response = await phone.claim('x3', { routingId: 'too-short' });
    expect(response.status).toBe(400);
    pairing.handle.cancel();
  });

  it('allows only the pair-claim route before pairing', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    phone = new RendezvousPhone(pairing.qr());
    await phone.connect(relayPort);
    await phone.establish();

    // An unpaired phone holds no token, but the rendezvous must not even offer the
    // route: this is the narrowest surface that can complete a pairing.
    phone.sendTunnel({ v: 1, type: 'tunnel/request', id: 'r1', method: 'POST', path: '/m1/rpc', body: { method: 'session.list' } });
    const rpc = await phone.waitTunnel((message) => message.type === 'tunnel/response' && message.id === 'r1');
    expect(rpc.status).toBe(404);

    phone.sendTunnel({ v: 1, type: 'tunnel/request', id: 'r2', method: 'GET', path: '/m1/health' });
    const health = await phone.waitTunnel((message) => message.type === 'tunnel/response' && message.id === 'r2');
    expect(health.status).toBe(404);

    // A GET on the claim path is refused too: the route exists only as a POST.
    phone.sendTunnel({ v: 1, type: 'tunnel/request', id: 'r3', method: 'GET', path: '/m1/pair/claim' });
    const wrongMethod = await phone.waitTunnel((message) => message.type === 'tunnel/response' && message.id === 'r3');
    expect(wrongMethod.status).toBe(404);
    pairing.handle.cancel();
  });

  it('refuses a subscription attempt over a pairing channel', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    phone = new RendezvousPhone(pairing.qr());
    await phone.connect(relayPort);
    await phone.establish();

    phone.sendTunnel({ v: 1, type: 'tunnel/subscribe', id: 's1', token: 'anything', after: 0 });
    const error = await phone.waitTunnel((message) => message.type === 'tunnel/error');
    expect(String(error.message)).toContain('before pairing');
    pairing.handle.cancel();
  });

  it('answers a ping over the pairing channel', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    phone = new RendezvousPhone(pairing.qr());
    await phone.connect(relayPort);
    await phone.establish();

    // Useful to the phone: it confirms the sealed channel works before the user is
    // asked to compare a code.
    phone.sendTunnel({ v: 1, type: 'tunnel/ping', at: 4242 });
    const pong = await phone.waitTunnel((message) => message.type === 'tunnel/pong');
    expect(pong.at).toBe(4242);
    pairing.handle.cancel();
  });

  it('fails the pairing loudly when the relay cannot be reached', async () => {
    // A QR the phone cannot dial is worse than a clear failure: the operator would
    // otherwise wait out the whole 120-second window with no explanation.
    await relay.close();
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-failed'), 'pair-failed');
    expect(pairing.messages.some((message) => message.type === 'pair-open')).toBe(false);
    const failed = pairing.messages.find((message) => message.type === 'pair-failed');
    if (failed?.type !== 'pair-failed') throw new Error('expected pair-failed');
    expect(failed.reason).toContain('rendezvous');
    // The window is closed, so a token that was minted for an unreachable relay
    // cannot be claimed later.
    expect(built.pairing.isOpen()).toBe(false);
  });

  it('lets the phone read pairing-rejected when the operator declines, then lingers', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    phone = new RendezvousPhone(pairing.qr());
    await phone.connect(relayPort);
    await phone.establish();
    await phone.claim('c1');
    await until(() => pairing.messages.some((message) => message.type === 'pair-claimed'), 'pair-claimed');

    pairing.handle.confirm(false);
    expect(pairing.messages.some((message) => message.type === 'pair-failed')).toBe(true);
    // No route recorded: a declined pairing must leave nothing dialable behind.
    expect(Object.keys(built.identity.routes())).toHaveLength(0);

    // The rendezvous now lingers rather than closing in the same tick, so the phone's
    // next poll reads the operator's decision instead of a vanished tunnel. This is
    // what lets Mode B report "declined on the workstation" rather than "unreachable".
    const polled = await phone.claim('c2');
    expect(polled.status).toBe(403);
    const body = polled.body as { ok: boolean; error: { code: string } };
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('pairing-rejected');
    // Still not claimable, and still no route — the linger is read-only.
    expect(built.pairing.isOpen()).toBe(false);
    expect(Object.keys(built.identity.routes())).toHaveLength(0);
  });

  it('stops advertising an open pairing window once pairing completes', async () => {
    const pairing = openPairing();
    await until(() => pairing.messages.some((message) => message.type === 'pair-open'), 'pair-open');
    phone = new RendezvousPhone(pairing.qr());
    await phone.connect(relayPort);
    await phone.establish();
    await phone.claim('c1');
    expect(built.pairing.isOpen()).toBe(true);

    pairing.handle.confirm(true);
    // The session is retained so the phone's final poll can read its result, but
    // nothing is claimable any more.
    expect(built.pairing.isOpen()).toBe(false);
  });
});

/**
 * `RelayClient` tests: registration, the sealed handshake, and the error taxonomy.
 *
 * Requirements (2), (3) and part of (4) from the brief. The security-relevant
 * assertions, and why each is here:
 *
 *   - The client sends round one on `relay/registered`, NOT on `relay/peer-online`.
 *     A rendezvous holder produces no peer notification, so waiting for one would
 *     deadlock every first pairing.
 *   - A signature that does not verify against the **pinned** bridge key ends the
 *     session as `handshake`, never as a retryable transport fault. This is the
 *     branch a man-in-the-middle lands in.
 *   - A peer that changes its ephemeral mid-handshake is refused, so a relay cannot
 *     harvest signatures over transcripts of its choosing.
 *   - A record that will not open ends the session. Fail closed, always.
 */

import { describe, expect, it } from 'vitest';
import { RelayClient, normalizeRelayErrorCode, relayWebSocketUrl, RELAY_SUBPROTOCOL } from '../src/m1/relay';
import { newRoutingId, pairingTokenBinder, type SealedChannel } from '../src/m1/seal';
import type { RelayCloseReason } from '../src/m1/relay';
import { FakeBridgePeer, FakeSocket, routingPair } from './helpers/fake-relay';
import { fixedIdentity, testIdentity } from './helpers/identity';

/** Build a client wired to a fake socket, with everything observable. */
function harness(overrides: { tokenBinder?: string; bridgeStaticPublicKey?: string } = {}) {
  const phone = testIdentity();
  const bridge = fixedIdentity(9);
  const ids = routingPair();
  const sockets: FakeSocket[] = [];
  const closes: RelayCloseReason[] = [];
  const records: unknown[] = [];
  const channels: SealedChannel[] = [];
  const diagnostics: { level: string; message: string }[] = [];

  const client = new RelayClient({
    relayUrl: 'https://relay.example',
    routingId: ids.phone,
    peerRoutingId: ids.bridge,
    bridgeStaticPublicKey: overrides.bridgeStaticPublicKey ?? bridge.publicKey,
    ...(overrides.tokenBinder === undefined ? { identity: phone } : { identity: phone, tokenBinder: overrides.tokenBinder }),
    createSocket: (url, subprotocols) => {
      const socket = new FakeSocket(url, subprotocols);
      sockets.push(socket);
      return socket;
    },
    onChannel: (channel) => channels.push(channel),
    onRecord: (value) => records.push(value),
    onClosed: (reason) => closes.push(reason),
    onDiagnostic: (level, message) => diagnostics.push({ level, message }),
  });

  return {
    client,
    phone,
    bridge,
    ids,
    closes,
    records,
    channels,
    diagnostics,
    get socket(): FakeSocket {
      const socket = sockets[0];
      if (socket === undefined) throw new Error('no socket was created');
      return socket;
    },
    /** The session id both sides must agree on: phone first. */
    get sessionId(): string {
      return `${ids.phone}:${ids.bridge}`;
    },
  };
}

/** Take a client all the way to a sealed tunnel, and return the bridge's side. */
function seal(h: ReturnType<typeof harness>, options: { pairing?: boolean; phoneStatic?: string } = {}): FakeBridgePeer {
  h.client.connect();
  h.socket.open();
  h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });

  const phoneOffer = h.socket.last('relay/handshake');
  const phoneEphemeral = (phoneOffer?.hs as { eph: string }).eph;

  const peer = new FakeBridgePeer({
    identity: h.bridge,
    sessionId: h.sessionId,
    phoneStatic: options.phoneStatic ?? h.phone.publicKey,
    ...(options.pairing === true ? { pairing: true } : {}),
  });

  h.socket.deliver(peer.offer());
  const signed = h.socket.ofType('relay/handshake')[1];
  const signature = (signed?.hs as { sig: string }).sig;
  h.socket.deliver(peer.answer(phoneEphemeral));

  if (options.pairing === true) {
    // The deferred proof: the bridge retains the phone's signature and verifies it
    // against the device key the claim will reveal. Passing both here asserts that
    // binding actually holds.
    peer.completeDeferred(phoneEphemeral, { signature, verifyAs: h.phone.publicKey });
  } else {
    peer.complete(phoneEphemeral, signature);
  }
  return peer;
}

describe('relayWebSocketUrl', () => {
  it('upgrades https to wss and http to ws', () => {
    expect(relayWebSocketUrl('https://relay.example')).toBe('wss://relay.example');
    expect(relayWebSocketUrl('http://127.0.0.1:8080')).toBe('ws://127.0.0.1:8080');
  });

  it('strips trailing slashes and leaves an explicit wss URL alone', () => {
    expect(relayWebSocketUrl('https://relay.example/')).toBe('wss://relay.example');
    expect(relayWebSocketUrl('wss://relay.example')).toBe('wss://relay.example');
  });
});

describe('normalizeRelayErrorCode', () => {
  it('passes through every code in the taxonomy', () => {
    for (const code of ['bad-message', 'routing-id-taken', 'not-registered', 'peer-offline', 'quota-exceeded', 'rendezvous-busy', 'internal']) {
      expect(normalizeRelayErrorCode(code)).toBe(code);
    }
  });

  it('folds anything unrecognized to internal', () => {
    // A newer relay must degrade to "relay problem, back off", not to a crash.
    for (const value of ['teapot', '', undefined, null, 42, {}]) {
      expect(normalizeRelayErrorCode(value)).toBe('internal');
    }
  });
});

describe('registration', () => {
  it('dials the relay with the versioned subprotocol', () => {
    const h = harness();
    h.client.connect();
    expect(h.socket.url).toBe('wss://relay.example');
    expect(h.socket.subprotocols).toEqual([RELAY_SUBPROTOCOL]);
  });

  it('registers as a phone in peer mode, naming the bridge', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    expect(h.socket.last('relay/register')).toEqual({
      v: 1,
      type: 'relay/register',
      role: 'phone',
      routingId: h.ids.phone,
      mode: 'peer',
      peerRoutingId: h.ids.bridge,
    });
  });

  it('never registers a rendezvous', () => {
    // A phone registering a rendezvous would be asking to receive someone else's
    // pairing traffic. The relay refuses it; the client must not attempt it.
    const h = harness({ tokenBinder: pairingTokenBinder('tok', 'bridge-1') });
    h.client.connect();
    h.socket.open();
    expect(h.socket.last('relay/register')?.mode).toBe('peer');
  });

  it('starts the handshake on registered, without waiting for peer-online', () => {
    // The pairing deadlock guard. A rendezvous holder generates no notification.
    const h = harness();
    h.client.connect();
    h.socket.open();
    expect(h.socket.ofType('relay/handshake')).toHaveLength(0);
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: false });
    const offers = h.socket.ofType('relay/handshake');
    expect(offers).toHaveLength(1);
    expect((offers[0]?.hs as { sig: string }).sig).toBe('');
    expect(offers[0]?.to).toBe(h.ids.bridge);
  });

  it('does not start a second handshake when peer-online follows registered', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: false });
    h.socket.deliver({ v: 1, type: 'relay/peer-online' });
    expect(h.socket.ofType('relay/handshake')).toHaveLength(1);
  });

  it('reports a socket that fails to open as a transport fault', () => {
    const h = harness();
    h.client.connect();
    h.socket.fireError();
    expect(h.closes[0]).toEqual({ kind: 'transport', message: 'relay socket error' });
  });

  it('reports a socket factory that throws as a transport fault', () => {
    const closes: RelayCloseReason[] = [];
    const client = new RelayClient({
      relayUrl: 'https://relay.example',
      routingId: newRoutingId(),
      peerRoutingId: newRoutingId(),
      bridgeStaticPublicKey: fixedIdentity(9).publicKey,
      identity: testIdentity(),
      createSocket: () => { throw new Error('no network'); },
      onChannel: () => undefined,
      onRecord: () => undefined,
      onClosed: (reason) => closes.push(reason),
    });
    client.connect();
    expect(closes[0]).toMatchObject({ kind: 'transport' });
    expect(closes[0]?.kind === 'transport' ? closes[0].message : '').toContain('no network');
  });

  it('is not reusable after close', () => {
    const h = harness();
    h.client.connect();
    h.client.close();
    const sent = h.socket.sent.length;
    h.client.connect();
    expect(h.socket.sent.length).toBe(sent);
  });
});

describe('the relay error taxonomy', () => {
  const cases: { code: string; expected: string }[] = [
    { code: 'routing-id-taken', expected: 'routing-id-taken' },
    { code: 'rendezvous-busy', expected: 'rendezvous-busy' },
    { code: 'peer-offline', expected: 'peer-offline' },
    { code: 'quota-exceeded', expected: 'quota-exceeded' },
    { code: 'not-registered', expected: 'not-registered' },
    { code: 'bad-message', expected: 'bad-message' },
    { code: 'internal', expected: 'internal' },
    { code: 'something-new', expected: 'internal' },
  ];

  for (const { code, expected } of cases) {
    it(`surfaces ${code} as a relay-error close with code ${expected}`, () => {
      const h = harness();
      h.client.connect();
      h.socket.open();
      h.socket.deliver({ v: 1, type: 'relay/error', code, message: 'nope' });
      expect(h.closes).toHaveLength(1);
      expect(h.closes[0]).toEqual({ kind: 'relay-error', code: expected, message: 'nope' });
    });
  }

  it('keeps a relay error distinct from a transport fault', () => {
    // The core maps these differently: one is `relay-unavailable` or
    // `routing-collision`, the other is a plain reconnect.
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/error', code: 'routing-id-taken', message: '' });
    expect(h.closes[0]?.kind).toBe('relay-error');
  });

  it('treats peer-offline notification as a transport fault, not a relay error', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/peer-offline' });
    expect(h.closes[0]).toEqual({ kind: 'transport', message: 'bridge went offline' });
  });
});

describe('malformed relay traffic', () => {
  it('rejects a non-text frame', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliverRaw(new Uint8Array([1, 2, 3]));
    expect(h.closes[0]).toEqual({ kind: 'transport', message: 'relay sent a non-text frame' });
  });

  it('rejects non-JSON', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver('{not json');
    expect(h.closes[0]).toEqual({ kind: 'transport', message: 'relay sent non-JSON' });
  });

  it('rejects a wrong protocol version', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 2, type: 'relay/registered' });
    expect(h.closes[0]).toEqual({ kind: 'transport', message: 'relay sent an unsupported message' });
  });

  it('rejects an unknown message type', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/surprise' });
    expect(h.closes[0]).toEqual({ kind: 'transport', message: 'relay sent an unknown message type' });
  });

  it('reports one reason only, even when a close follows', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/error', code: 'quota-exceeded', message: 'slow down' });
    h.socket.fireClose();
    h.socket.fireError();
    expect(h.closes).toHaveLength(1);
    expect(h.closes[0]?.kind).toBe('relay-error');
  });
});

describe('the sealed handshake', () => {
  it('completes and hands back a channel', () => {
    const h = harness();
    seal(h);
    expect(h.channels).toHaveLength(1);
    expect(h.client.isSealed()).toBe(true);
    expect(h.closes).toHaveLength(0);
  });

  it('signs only after the peer ephemeral is known', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    const first = h.socket.ofType('relay/handshake')[0];
    expect((first?.hs as { sig: string }).sig).toBe('');

    const peer = new FakeBridgePeer({ identity: h.bridge, sessionId: h.sessionId, phoneStatic: h.phone.publicKey });
    h.socket.deliver(peer.offer());
    const second = h.socket.ofType('relay/handshake')[1];
    expect((second?.hs as { sig: string }).sig.length).toBeGreaterThan(0);
    // Same ephemeral in both frames: one handshake, two messages.
    expect((second?.hs as { eph: string }).eph).toBe((first?.hs as { eph: string }).eph);
  });

  it('rejects a signature from a key other than the pinned one', () => {
    // The man-in-the-middle case. A relay that substitutes its own static key gets
    // `handshake`/`bad-signature`, which the core treats as terminal `pin-mismatch`.
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    const phoneEphemeral = (h.socket.last('relay/handshake')?.hs as { eph: string }).eph;

    const peer = new FakeBridgePeer({ identity: h.bridge, sessionId: h.sessionId, phoneStatic: h.phone.publicKey });
    peer.signWith = testIdentity().privateKey;
    h.socket.deliver(peer.offer());
    h.socket.deliver(peer.answer(phoneEphemeral));

    expect(h.channels).toHaveLength(0);
    expect(h.closes[0]).toEqual({ kind: 'handshake', reason: 'bad-signature' });
  });

  it('rejects a peer that changes its ephemeral mid-handshake', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    const phoneEphemeral = (h.socket.last('relay/handshake')?.hs as { eph: string }).eph;

    const first = new FakeBridgePeer({ identity: h.bridge, sessionId: h.sessionId, phoneStatic: h.phone.publicKey });
    const second = new FakeBridgePeer({ identity: h.bridge, sessionId: h.sessionId, phoneStatic: h.phone.publicKey });
    h.socket.deliver(first.offer());
    h.socket.deliver(second.answer(phoneEphemeral));

    expect(h.closes[0]).toEqual({ kind: 'handshake', reason: 'peer changed its ephemeral key mid-handshake' });
  });

  it('rejects a malformed peer handshake', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    h.socket.deliver({ v: 1, type: 'relay/handshake', hs: { v: 1, sig: 'x' } });
    expect(h.closes[0]).toEqual({ kind: 'handshake', reason: 'malformed peer handshake' });
  });

  it('rejects an ephemeral of the wrong length', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    h.socket.deliver({ v: 1, type: 'relay/handshake', hs: { v: 1, eph: 'AAAA', sig: 'AAAA' } });
    expect(h.closes[0]).toEqual({ kind: 'handshake', reason: 'bad-ephemeral' });
  });

  it('rejects a corrupt pinned key as bad-static-key rather than bad-signature', () => {
    // A corrupt stored pin must not read as "the bridge is an impostor": the
    // distinction is what tells an operator whether to re-pair or to worry.
    const h = harness({ bridgeStaticPublicKey: 'AAAAAAAAAAAAAAAAAAAAAA' });
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    const peer = new FakeBridgePeer({ identity: h.bridge, sessionId: h.sessionId, phoneStatic: h.phone.publicKey });
    const phoneEphemeral = (h.socket.last('relay/handshake')?.hs as { eph: string }).eph;
    h.socket.deliver(peer.offer());
    h.socket.deliver(peer.answer(phoneEphemeral));
    expect(h.closes[0]).toEqual({ kind: 'handshake', reason: 'bad-static-key' });
  });

  it('refuses a second handshake on an established tunnel', () => {
    // A forced renegotiation is something a relay could use to observe a fresh
    // exchange, or a confused bridge. Either way the tunnel is finished. A fresh
    // peer, because a real renegotiation would carry a new ephemeral.
    const h = harness();
    seal(h);
    const second = new FakeBridgePeer({ identity: h.bridge, sessionId: h.sessionId, phoneStatic: h.phone.publicKey });
    h.socket.deliver(second.offer());
    expect(h.closes[0]).toEqual({ kind: 'handshake', reason: 'handshake on an established tunnel' });
  });

  it('fails when neither an identity nor a binder can sign', () => {
    const closes: RelayCloseReason[] = [];
    const socket = new FakeSocket('wss://relay.example', []);
    const client = new RelayClient({
      relayUrl: 'https://relay.example',
      routingId: newRoutingId(),
      peerRoutingId: newRoutingId(),
      bridgeStaticPublicKey: fixedIdentity(9).publicKey,
      createSocket: () => socket,
      onChannel: () => undefined,
      onRecord: () => undefined,
      onClosed: (reason) => closes.push(reason),
    });
    client.connect();
    socket.open();
    socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    expect(closes[0]).toEqual({ kind: 'handshake', reason: 'no device identity and no pairing binder' });
  });

  it('uses the token binder as its static slot during pairing, and still signs with the device key', () => {
    // Both properties in one test because they are the same design decision: the
    // binder occupies the transcript slot, the real key makes the signature, and
    // that is what lets the bridge bind the channel to the claim.
    const binder = pairingTokenBinder('token-abc', 'bridge-1');
    const h = harness({ tokenBinder: binder });
    const peer = seal(h, { pairing: true, phoneStatic: binder });
    expect(h.channels).toHaveLength(1);
    // A round trip proves both sides derived the same keys from the same transcript.
    h.client.send({ hello: 'pairing' });
    expect(peer.open(h.socket.last('relay/data')?.record)).toEqual({ hello: 'pairing' });
  });
});

describe('sealed records', () => {
  it('round-trips in both directions', () => {
    const h = harness();
    const peer = seal(h);
    expect(h.client.send({ ping: 1 })).toBe(true);
    expect(peer.open(h.socket.last('relay/data')?.record)).toEqual({ ping: 1 });
    h.socket.deliver(peer.data({ pong: 2 }));
    expect(h.records).toEqual([{ pong: 2 }]);
  });

  it('addresses every data frame to the peer', () => {
    const h = harness();
    seal(h);
    h.client.send({ x: 1 });
    expect(h.socket.last('relay/data')?.to).toBe(h.ids.bridge);
  });

  it('refuses to send before the tunnel is sealed', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    expect(h.client.send({ x: 1 })).toBe(false);
    expect(h.socket.ofType('relay/data')).toHaveLength(0);
  });

  it('ends the session when a record will not open', () => {
    // Fail closed. A tampered record means the path is not behaving.
    const h = harness();
    const peer = seal(h);
    const frame = peer.data({ ok: true });
    const record = frame.record as { n: number; c: string };
    h.socket.deliver({ v: 1, type: 'relay/data', record: { n: record.n, c: `${record.c.slice(0, -4)}AAAA` } });
    expect(h.closes[0]).toMatchObject({ kind: 'seal' });
    expect(h.records).toHaveLength(0);
  });

  it('rejects a replayed record and ends the session', () => {
    const h = harness();
    const peer = seal(h);
    const frame = peer.data({ once: true });
    h.socket.deliver(frame);
    expect(h.records).toEqual([{ once: true }]);
    h.socket.deliver(frame);
    expect(h.closes[0]).toEqual({ kind: 'seal', reason: 'replay' });
    // The replay was not delivered to the application.
    expect(h.records).toHaveLength(1);
  });

  it('ignores data that arrives before the tunnel is sealed without ending the session', () => {
    // A bridge may legitimately send early. Nothing can be read, but nothing is
    // wrong either.
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.socket.deliver({ v: 1, type: 'relay/registered', peerPresent: true });
    h.socket.deliver({ v: 1, type: 'relay/data', record: { n: 1, c: 'AAAA' } });
    expect(h.closes).toHaveLength(0);
    expect(h.diagnostics.some((entry) => entry.level === 'warn')).toBe(true);
  });

  it('reports a send failure as a transport fault', () => {
    const h = harness();
    seal(h);
    h.socket.failSend = true;
    h.client.send({ x: 1 });
    expect(h.closes[0]).toMatchObject({ kind: 'transport' });
  });
});

describe('liveness and shutdown', () => {
  it('pings at the control layer before a tunnel exists', () => {
    const h = harness();
    h.client.connect();
    h.socket.open();
    h.client.ping();
    expect(h.socket.last('relay/ping')).toMatchObject({ v: 1, type: 'relay/ping' });
  });

  it('ignores a pong', () => {
    const h = harness();
    seal(h);
    h.socket.deliver({ v: 1, type: 'relay/pong' });
    expect(h.closes).toHaveLength(0);
  });

  it('says goodbye and closes the socket', () => {
    const h = harness();
    seal(h);
    h.client.close('done');
    expect(h.socket.last('relay/bye')).toMatchObject({ type: 'relay/bye' });
    expect(h.socket.closed).toBe(true);
    expect(h.closes[0]).toEqual({ kind: 'local', message: 'done' });
  });

  it('is idempotent on close', () => {
    const h = harness();
    seal(h);
    h.client.close();
    h.client.close();
    expect(h.closes).toHaveLength(1);
  });

  it('treats a socket close during a healthy session as a transport fault', () => {
    const h = harness();
    seal(h);
    h.socket.fireClose();
    expect(h.closes[0]).toEqual({ kind: 'transport', message: 'relay socket closed' });
  });

  it('stops accepting frames after close', () => {
    const h = harness();
    const peer = seal(h);
    h.client.close();
    h.socket.deliver(peer.data({ late: true }));
    expect(h.records).toHaveLength(0);
  });
});

/**
 * Relay routing and connector tests.
 *
 * These use Node's global WebSocket against the real relay server, so the RFC 6455
 * layer is exercised by an independent implementation rather than by our own codec
 * talking to itself.
 *
 * What these tests do NOT cover, and cannot in this environment:
 *   - a real phone client
 *   - a relay behind a TLS terminator or a load balancer
 *   - NAT rebinding and mobile radio transitions
 * Those remain `[NOT INTEGRATION-TESTED]`.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { RelayServer, RELAY_PATH } from '../src/relay/server.ts';
import { RELAY_SUBPROTOCOL, isValidRoutingId, parseClientMessage } from '../src/relay/protocol.ts';
import { newRoutingId, beginHandshake, completeHandshake, signHandshake } from '../src/relay/seal.ts';
import type { SealedChannel } from '../src/relay/seal.ts';
import { RelayConnector } from '../src/relay/connector.ts';
import type { TunnelBackend, TunnelStreamSinks } from '../src/relay/backend.ts';
import { toBase64Url } from '../src/identity/crypto.ts';

/** A minimal test peer: connect, register, collect messages. */
class TestPeer {
  readonly received: Record<string, unknown>[] = [];
  private socket: WebSocket | undefined;

  static async connect(port: number): Promise<TestPeer> {
    const peer = new TestPeer();
    const socket = new WebSocket(`ws://127.0.0.1:${port}${RELAY_PATH}`, [RELAY_SUBPROTOCOL]);
    peer.socket = socket;
    socket.addEventListener('message', (event) => {
      if (typeof event.data === 'string') peer.received.push(JSON.parse(event.data) as Record<string, unknown>);
    });
    await new Promise<void>((resolve, reject) => {
      socket.addEventListener('open', () => resolve());
      socket.addEventListener('error', () => reject(new Error('relay dial failed')));
    });
    return peer;
  }

  send(message: unknown): void {
    this.socket?.send(JSON.stringify(message));
  }

  register(role: 'bridge' | 'phone', routingId: string, peerRoutingId: string): void {
    this.send({ v: 1, type: 'relay/register', role, routingId, peerRoutingId });
  }

  close(): void {
    this.socket?.close(1000, 'test done');
  }

  /** Wait for the first message of `type`, or fail after `timeoutMs`. */
  async wait(type: string, timeoutMs = 2_000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = this.received.find((message) => message.type === type);
      if (found !== undefined) return found;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${type}; saw ${JSON.stringify(this.received)}`);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  count(type: string): number {
    return this.received.filter((message) => message.type === type).length;
  }
}

const RECORD = { n: '0', c: 'AAAA' };

describe('relay protocol parsing', () => {
  it('accepts a well-formed register', () => {
    const result = parseClientMessage({
      v: 1,
      type: 'relay/register',
      role: 'phone',
      routingId: newRoutingId(),
      peerRoutingId: newRoutingId(),
    });
    expect(result.ok).toBe(true);
  });

  it('rejects a wrong protocol version', () => {
    const result = parseClientMessage({ v: 2, type: 'relay/ping', at: 1 });
    expect(result).toMatchObject({ ok: false, code: 'bad-message' });
  });

  it('rejects self-pairing', () => {
    const id = newRoutingId();
    const result = parseClientMessage({ v: 1, type: 'relay/register', role: 'phone', routingId: id, peerRoutingId: id });
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) expect(result.reason).toContain('must differ');
  });

  it('rejects malformed routing ids', () => {
    for (const bad of ['', 'short', 'x'.repeat(23), 'has spaces here 12345!', 'plus+slash/aaaaaaaaaaa']) {
      const result = parseClientMessage({
        v: 1,
        type: 'relay/register',
        role: 'phone',
        routingId: bad,
        peerRoutingId: newRoutingId(),
      });
      expect(result.ok, bad).toBe(false);
    }
  });

  it('validates only the shape of a sealed record', () => {
    expect(parseClientMessage({ v: 1, type: 'relay/data', record: RECORD }).ok).toBe(true);
    expect(parseClientMessage({ v: 1, type: 'relay/data', record: { n: 0, c: 'x' } }).ok).toBe(false);
    expect(parseClientMessage({ v: 1, type: 'relay/data', record: null }).ok).toBe(false);
  });

  it('rejects unknown message types and non-objects', () => {
    expect(parseClientMessage({ v: 1, type: 'relay/admin' }).ok).toBe(false);
    expect(parseClientMessage('hello').ok).toBe(false);
    expect(parseClientMessage([{ v: 1, type: 'relay/ping' }]).ok).toBe(false);
    expect(parseClientMessage(null).ok).toBe(false);
  });

  it('generates routing ids that pass its own validator', () => {
    for (let i = 0; i < 50; i += 1) expect(isValidRoutingId(newRoutingId())).toBe(true);
  });
});

/** A recording stand-in for the bridge's `/m1` router. */
class FakeBackend implements TunnelBackend {
  readonly requests: { method: string; path: string; body?: unknown }[] = [];
  readonly subscribes: { token: string; after: number }[] = [];
  streamSinks: TunnelStreamSinks | undefined;
  /** Counted rather than flagged: a resubscribe opens a new stream, and a flag
   *  reset by the new one would hide the close of the old one. */
  streamCloses = 0;
  nextStatus = 200;
  nextBody: unknown = { ok: true, value: { result: 'ok' } };
  streamFailure: { status: number; reason: string } | undefined;

  request(input: { method: 'GET' | 'POST'; path: string; body?: unknown }): Promise<{ status: number; body: unknown }> {
    this.requests.push(input);
    return Promise.resolve({ status: this.nextStatus, body: this.nextBody });
  }

  openStream(input: { token: string; after: number; sinks: TunnelStreamSinks }): Promise<
    { ok: true; stream: { close(): void } } | { ok: false; status: number; reason: string }
  > {
    this.subscribes.push({ token: input.token, after: input.after });
    if (this.streamFailure !== undefined) return Promise.resolve({ ok: false, ...this.streamFailure });
    this.streamSinks = input.sinks;
    return Promise.resolve({
      ok: true,
      stream: {
        close: () => {
          this.streamCloses += 1;
        },
      },
    });
  }
}

/** The phone half of the sealed tunnel, as an initiator. */
class TestPhone {
  private handshake: ReturnType<typeof beginHandshake> | undefined;
  private channel: SealedChannel | undefined;
  readonly tunnelMessages: Record<string, unknown>[] = [];

  constructor(
    private readonly peer: TestPeer,
    private readonly sessionId: string,
    private readonly ownPublic: string,
    private readonly ownPrivate: Parameters<typeof signHandshake>[2],
    private readonly bridgePublic: string,
  ) {}

  begin(): void {
    this.handshake = beginHandshake({
      role: 'initiator',
      sessionId: this.sessionId,
      ownStaticPublicKey: this.ownPublic,
      peerStaticPublicKey: this.bridgePublic,
    });
    this.peer.send({ v: 1, type: 'relay/handshake', hs: { v: 1, eph: this.handshake.message.eph, sig: '' } });
  }

  /** Drive the two-round handshake to completion, then decrypt tunnel traffic. */
  async establish(): Promise<void> {
    this.begin();
    const first = await this.peer.wait('relay/handshake');
    const handshake = this.handshake;
    if (handshake === undefined) throw new Error('begin() not called');
    const hs = first.hs as { eph: string; sig?: string };
    const sig = signHandshake(handshake, hs.eph, this.ownPrivate);
    this.peer.send({ v: 1, type: 'relay/handshake', hs: { v: 1, eph: handshake.message.eph, sig } });

    // The bridge answers the unsigned round with a signed one.
    const signed = await this.waitSignedHandshake();
    const completed = completeHandshake(handshake, { v: 1, eph: signed.eph, sig: signed.sig });
    if (!completed.ok) throw new Error(`phone handshake failed: ${completed.reason}`);
    this.channel = completed.channel;
  }

  private async waitSignedHandshake(): Promise<{ eph: string; sig: string }> {
    const deadline = Date.now() + 2_000;
    for (;;) {
      for (const message of this.peer.received) {
        if (message.type !== 'relay/handshake') continue;
        const hs = message.hs as { eph?: string; sig?: string };
        if (typeof hs?.eph === 'string' && typeof hs.sig === 'string' && hs.sig.length > 0) {
          return { eph: hs.eph, sig: hs.sig };
        }
      }
      if (Date.now() > deadline) throw new Error('no signed handshake from bridge');
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  send(message: unknown): void {
    if (this.channel === undefined) throw new Error('tunnel not established');
    this.peer.send({ v: 1, type: 'relay/data', record: this.channel.sealJson(message) });
  }

  /** Send a raw sealed record, for tamper tests. */
  sendRaw(record: unknown): void {
    this.peer.send({ v: 1, type: 'relay/data', record });
  }

  /** Decrypt everything the bridge has sent so far. */
  drain(): Record<string, unknown>[] {
    if (this.channel === undefined) return [];
    for (const message of this.peer.received) {
      if (message.type !== 'relay/data' || message.__drained === true) continue;
      message.__drained = true;
      const opened = this.channel.openJson(message.record);
      if (opened.ok) this.tunnelMessages.push(opened.value as Record<string, unknown>);
    }
    return this.tunnelMessages;
  }

  async waitTunnel(type: string, timeoutMs = 2_000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = this.drain().find((message) => message.type === type);
      if (found !== undefined) return found;
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for ${type}; saw ${JSON.stringify(this.tunnelMessages)}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

describe('relay server routing', () => {
  let relay: RelayServer;
  let port: number;
  const peers: TestPeer[] = [];

  beforeEach(async () => {
    relay = new RelayServer({ frameRatePerMinute: 10 });
    port = await relay.listen(0, '127.0.0.1');
  });

  afterEach(async () => {
    for (const peer of peers) peer.close();
    peers.length = 0;
    await relay.close();
  });

  const connect = async (): Promise<TestPeer> => {
    const peer = await TestPeer.connect(port);
    peers.push(peer);
    return peer;
  };

  it('registers a peer and reports the counterpart absent', async () => {
    const bridge = await connect();
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    bridge.register('bridge', bridgeId, phoneId);
    const registered = await bridge.wait('relay/registered');
    expect(registered).toMatchObject({ routingId: bridgeId, peerPresent: false });
  });

  it('notifies both sides when the tunnel completes', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    await bridge.wait('relay/registered');

    const phone = await connect();
    phone.register('phone', phoneId, bridgeId);
    await phone.wait('relay/peer-online');
    await bridge.wait('relay/peer-online');
    expect(relay.stats().tunnels).toBe(1);
  });

  it('forwards a sealed record verbatim to the paired peer only', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    const phone = await connect();
    phone.register('phone', phoneId, bridgeId);
    await phone.wait('relay/peer-online');

    // A third peer paired with nobody relevant must not see the traffic.
    const outsiderId = newRoutingId();
    const outsider = await connect();
    outsider.register('phone', outsiderId, newRoutingId());
    await outsider.wait('relay/registered');

    const record = { n: '7', c: 'c2VjcmV0LWJ5dGVz' };
    phone.send({ v: 1, type: 'relay/data', record });
    const delivered = await bridge.wait('relay/data');
    expect(delivered.record).toEqual(record);
    expect(outsider.count('relay/data')).toBe(0);
  });

  it('forwards handshake blobs on the same path as data', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    const phone = await connect();
    phone.register('phone', phoneId, bridgeId);
    await phone.wait('relay/peer-online');

    phone.send({ v: 1, type: 'relay/handshake', hs: { v: 1, eph: 'abc', sig: '' } });
    const delivered = await bridge.wait('relay/handshake');
    expect(delivered.hs).toEqual({ v: 1, eph: 'abc', sig: '' });
  });

  it('refuses data before registration', async () => {
    const peer = await connect();
    peer.send({ v: 1, type: 'relay/data', record: RECORD });
    const error = await peer.wait('relay/error');
    expect(error.code).toBe('not-registered');
  });

  it('refuses a routing id that is already held', async () => {
    const bridgeId = newRoutingId();
    const first = await connect();
    first.register('bridge', bridgeId, newRoutingId());
    await first.wait('relay/registered');

    const squatter = await connect();
    squatter.register('bridge', bridgeId, newRoutingId());
    const error = await squatter.wait('relay/error');
    expect(error.code).toBe('routing-id-taken');
    // The incumbent must survive: eviction would be a trivial denial of service.
    expect(first.count('relay/error')).toBe(0);
  });

  it('refuses a one-sided pairing claim', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    await bridge.wait('relay/registered');

    // This peer names the bridge, but the bridge does not name it back.
    const impostor = await connect();
    impostor.register('phone', newRoutingId(), bridgeId);
    await impostor.wait('relay/registered');
    impostor.send({ v: 1, type: 'relay/data', record: RECORD });

    const error = await impostor.wait('relay/error');
    expect(error.code).toBe('peer-offline');
    expect(bridge.count('relay/data')).toBe(0);
  });

  it('reports peer-offline when the counterpart disconnects', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    const phone = await TestPeer.connect(port);
    phone.register('phone', phoneId, bridgeId);
    await bridge.wait('relay/peer-online');

    phone.close();
    await bridge.wait('relay/peer-offline');
    expect(relay.stats().peers).toBe(1);
  });

  it('enforces the frame quota and keeps the connection usable', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    const phone = await connect();
    phone.register('phone', phoneId, bridgeId);
    await phone.wait('relay/peer-online');

    for (let i = 0; i < 15; i += 1) phone.send({ v: 1, type: 'relay/data', record: { n: String(i), c: 'AAAA' } });
    const error = await phone.wait('relay/error');
    expect(error.code).toBe('quota-exceeded');
    // Ten allowed, the rest refused: the quota drops frames, it does not drop peers.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(bridge.count('relay/data')).toBe(10);
    expect(relay.stats().framesDropped).toBe(5);
  });

  it('answers ping with pong before a tunnel exists', async () => {
    const peer = await connect();
    peer.send({ v: 1, type: 'relay/ping', at: 1234 });
    const pong = await peer.wait('relay/pong');
    expect(pong.at).toBe(1234);
  });

  it('rejects a malformed message without dropping the peer', async () => {
    const peer = await connect();
    peer.send({ v: 1, type: 'relay/nonsense' });
    const error = await peer.wait('relay/error');
    expect(error.code).toBe('bad-message');
    peer.send({ v: 1, type: 'relay/ping', at: 9 });
    expect((await peer.wait('relay/pong')).at).toBe(9);
  });

  it('refuses an upgrade without the relay subprotocol', async () => {
    const socket = new WebSocket(`ws://127.0.0.1:${port}${RELAY_PATH}`);
    const closed = await new Promise<boolean>((resolve) => {
      socket.addEventListener('open', () => resolve(false));
      socket.addEventListener('error', () => resolve(true));
      socket.addEventListener('close', () => resolve(true));
    });
    expect(closed).toBe(true);
  });

  it('refuses an upgrade on an unknown path', async () => {
    const socket = new WebSocket(`ws://127.0.0.1:${port}/not-the-relay`, [RELAY_SUBPROTOCOL]);
    const closed = await new Promise<boolean>((resolve) => {
      socket.addEventListener('open', () => resolve(false));
      socket.addEventListener('error', () => resolve(true));
      socket.addEventListener('close', () => resolve(true));
    });
    expect(closed).toBe(true);
  });

  it('serves health without revealing routing ids', async () => {
    const response = await fetch(`http://127.0.0.1:${port}/relay/health`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ ok: true, protocol: 1 });
    expect(Object.keys(body)).toEqual(['ok', 'protocol', 'peers']);
  });

  it('404s any other HTTP path', async () => {
    const response = await fetch(`http://127.0.0.1:${port}/`);
    expect(response.status).toBe(404);
  });
});

/**
 * Rendezvous mode is the only place the mutual-naming rule is relaxed, so these
 * tests are about what the relaxation does NOT allow. The pairing sequence itself
 * lives in relay-rendezvous.test.ts.
 */
describe('relay rendezvous routing', () => {
  let relay: RelayServer;
  let port: number;
  const peers: TestPeer[] = [];

  beforeEach(async () => {
    relay = new RelayServer({ frameRatePerMinute: 5_000, maxRendezvousClaimants: 2 });
    port = await relay.listen(0, '127.0.0.1');
  });

  afterEach(async () => {
    for (const peer of peers) peer.close();
    peers.length = 0;
    await relay.close();
  });

  const connect = async (): Promise<TestPeer> => {
    const peer = await TestPeer.connect(port);
    peers.push(peer);
    return peer;
  };

  /** Register a rendezvous holder, which names no peer. */
  const holder = async (routingId: string): Promise<TestPeer> => {
    const peer = await connect();
    peer.send({ v: 1, type: 'relay/register', role: 'bridge', routingId, mode: 'rendezvous' });
    await peer.wait('relay/registered');
    return peer;
  };

  /** Register a caller that names the rendezvous. */
  const caller = async (routingId: string, target: string): Promise<TestPeer> => {
    const peer = await connect();
    peer.send({ v: 1, type: 'relay/register', role: 'phone', routingId, mode: 'peer', peerRoutingId: target });
    await peer.wait('relay/registered');
    return peer;
  };

  it('registers a rendezvous with no peer named', async () => {
    const rid = newRoutingId();
    const peer = await holder(rid);
    const registered = await peer.wait('relay/registered');
    // `peerPresent` is false because there is no counterpart to be present.
    expect(registered).toMatchObject({ routingId: rid, peerPresent: false });
  });

  it('refuses a rendezvous that names a peer', async () => {
    const peer = await connect();
    peer.send({
      v: 1,
      type: 'relay/register',
      role: 'bridge',
      routingId: newRoutingId(),
      mode: 'rendezvous',
      peerRoutingId: newRoutingId(),
    });
    // Naming a peer would mean the holder already knows who is calling, which is
    // the opposite of what a rendezvous is for.
    expect((await peer.wait('relay/error')).code).toBe('bad-message');
  });

  it('refuses a phone claiming to hold a rendezvous', async () => {
    const peer = await connect();
    peer.send({ v: 1, type: 'relay/register', role: 'phone', routingId: newRoutingId(), mode: 'rendezvous' });
    // Only a bridge listens on a rendezvous; a phone in that role has nothing to
    // offer and would only be soaking up ids.
    expect((await peer.wait('relay/error')).code).toBe('bad-message');
  });

  it('tags an inbound frame with the sender so the holder can reply', async () => {
    const rid = newRoutingId();
    const phoneId = newRoutingId();
    const rendezvous = await holder(rid);
    const phone = await caller(phoneId, rid);

    phone.send({ v: 1, type: 'relay/data', record: RECORD });
    const forwarded = await rendezvous.wait('relay/data');
    // The holder cannot know who is calling, so the relay must say. This is the one
    // place `from` appears, and it is only used for reply addressing.
    expect(forwarded).toMatchObject({ from: phoneId, record: RECORD });
  });

  it('routes the holder’s reply back to that claimant', async () => {
    const rid = newRoutingId();
    const phoneId = newRoutingId();
    const rendezvous = await holder(rid);
    const phone = await caller(phoneId, rid);

    phone.send({ v: 1, type: 'relay/data', record: RECORD });
    await rendezvous.wait('relay/data');
    rendezvous.send({ v: 1, type: 'relay/data', record: { n: '1', c: 'BBBB' }, to: phoneId });
    expect(await phone.wait('relay/data')).toMatchObject({ record: { n: '1', c: 'BBBB' } });
  });

  it('does not tag peer-mode traffic with a sender', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    const phone = await caller(phoneId, bridgeId);
    await phone.wait('relay/peer-online');

    phone.send({ v: 1, type: 'relay/data', record: RECORD });
    const forwarded = await bridge.wait('relay/data');
    // A steady-state peer already knows its one counterpart; echoing an id it did
    // not ask for would be a second source of truth about who it is talking to.
    expect(forwarded.from).toBeUndefined();
  });

  it('refuses a holder frame with no target', async () => {
    const rendezvous = await holder(newRoutingId());
    rendezvous.send({ v: 1, type: 'relay/data', record: RECORD });
    expect((await rendezvous.wait('relay/error')).code).toBe('bad-message');
  });

  it('refuses a holder frame aimed at a routing id that never called it', async () => {
    const rid = newRoutingId();
    const rendezvous = await holder(rid);
    const otherId = newRoutingId();
    // A third party, registered but talking to someone else entirely.
    const other = await caller(otherId, newRoutingId());

    rendezvous.send({ v: 1, type: 'relay/data', record: RECORD, to: otherId });
    // Without this, a rendezvous holder would be a frame sprayer: anyone who could
    // register one could push records at arbitrary routing ids.
    expect((await rendezvous.wait('relay/error')).code).toBe('peer-offline');
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(other.count('relay/data')).toBe(0);
  });

  it('refuses a holder reply once the claimant stops naming it', async () => {
    const rid = newRoutingId();
    const phoneId = newRoutingId();
    const rendezvous = await holder(rid);
    const phone = await caller(phoneId, rid);
    phone.send({ v: 1, type: 'relay/data', record: RECORD });
    await rendezvous.wait('relay/data');

    // The claimant drops and something else takes the same routing id, now pointed
    // at a different peer. Addressability must not be inherited.
    phone.close();
    await rendezvous.wait('relay/peer-offline');
    const impostor = await caller(phoneId, newRoutingId());
    rendezvous.send({ v: 1, type: 'relay/data', record: RECORD, to: phoneId });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(impostor.count('relay/data')).toBe(0);
  });

  it('tells the holder when a claimant disconnects', async () => {
    const rid = newRoutingId();
    const rendezvous = await holder(rid);
    const phone = await caller(newRoutingId(), rid);
    phone.send({ v: 1, type: 'relay/data', record: RECORD });
    await rendezvous.wait('relay/data');

    // So a bridge can drop a half-built pairing channel instead of waiting for the
    // token to expire.
    phone.close();
    await rendezvous.wait('relay/peer-offline');
  });

  it('tells claimants when the holder disconnects', async () => {
    const rid = newRoutingId();
    const rendezvous = await holder(rid);
    const first = await caller(newRoutingId(), rid);
    const second = await caller(newRoutingId(), rid);
    first.send({ v: 1, type: 'relay/data', record: RECORD });
    second.send({ v: 1, type: 'relay/data', record: RECORD });
    await rendezvous.wait('relay/data');
    await rendezvous.wait('relay/data');

    // The mutual-naming check cannot cover this: a holder names no counterpart. So
    // without an explicit mirror, a phone mid-pairing would wait for a reply that
    // can never come until the token expired.
    rendezvous.close();
    await first.wait('relay/peer-offline');
    await second.wait('relay/peer-offline');
  });

  it('does not tell a peer that merely named the holder without being admitted', async () => {
    const rid = newRoutingId();
    const rendezvous = await holder(rid);
    // Never sends a frame, so it was never added to the claimant set.
    const lurker = await caller(newRoutingId(), rid);

    rendezvous.close();
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(lurker.count('relay/peer-offline')).toBe(0);
  });

  it('caps concurrent claimants and keeps serving the ones it has', async () => {
    const rid = newRoutingId();
    const rendezvous = await holder(rid);
    const first = await caller(newRoutingId(), rid);
    const second = await caller(newRoutingId(), rid);
    const third = await caller(newRoutingId(), rid);

    first.send({ v: 1, type: 'relay/data', record: RECORD });
    second.send({ v: 1, type: 'relay/data', record: RECORD });
    await new Promise((resolve) => setTimeout(resolve, 60));
    third.send({ v: 1, type: 'relay/data', record: RECORD });

    // Unbounded, this set is a memory-growth lever for anyone who reads a QR.
    expect((await third.wait('relay/error')).code).toBe('rendezvous-busy');
    expect(rendezvous.count('relay/data')).toBe(2);
  });

  it('lets a rendezvous id be reused after the holder leaves', async () => {
    const rid = newRoutingId();
    const first = await holder(rid);
    first.close();
    // Otherwise a crashed pairing would burn the id derived from the next token
    // only if it collided, but an expired one must be reusable in any case.
    await new Promise((resolve) => setTimeout(resolve, 60));
    const second = await connect();
    second.send({ v: 1, type: 'relay/register', role: 'bridge', routingId: rid, mode: 'rendezvous' });
    expect(await second.wait('relay/registered')).toMatchObject({ routingId: rid });
  });

  it('refuses a second holder for a live rendezvous id', async () => {
    const rid = newRoutingId();
    await holder(rid);
    const second = await connect();
    second.send({ v: 1, type: 'relay/register', role: 'bridge', routingId: rid, mode: 'rendezvous' });
    // The bridge treats this as fatal: something else is answering for its id.
    expect((await second.wait('relay/error')).code).toBe('routing-id-taken');
  });

  it('does not count a rendezvous as a tunnel', async () => {
    const rid = newRoutingId();
    await holder(rid);
    const phone = await caller(newRoutingId(), rid);
    phone.send({ v: 1, type: 'relay/data', record: RECORD });
    await new Promise((resolve) => setTimeout(resolve, 60));
    // A tunnel means two peers that name each other. Counting a half-named pairing
    // channel would overstate what the relay is carrying.
    expect(relay.stats().tunnels).toBe(0);
    expect(relay.stats().peers).toBe(2);
  });

  it('refuses a peer-mode frame redirected at an unrelated id', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    bridge.register('bridge', bridgeId, phoneId);
    const phone = await caller(phoneId, bridgeId);
    await phone.wait('relay/peer-online');

    // Refused rather than silently ignored: a sender that believes it redirected a
    // frame is worse off than one told it cannot.
    phone.send({ v: 1, type: 'relay/data', record: RECORD, to: newRoutingId() });
    expect((await phone.wait('relay/error')).code).toBe('bad-message');
    expect(bridge.count('relay/data')).toBe(0);
  });

  it('rejects a malformed to value', async () => {
    const rendezvous = await holder(newRoutingId());
    rendezvous.send({ v: 1, type: 'relay/data', record: RECORD, to: 'not-a-routing-id' });
    // Parsed strictly at the protocol layer, so a malformed target never reaches
    // routing.
    expect((await rendezvous.wait('relay/error')).code).toBe('bad-message');
  });

  it('treats a register with no mode as peer mode', async () => {
    const bridgeId = newRoutingId();
    const phoneId = newRoutingId();
    const bridge = await connect();
    // A v1 peer that predates rendezvous keeps working unchanged.
    bridge.register('bridge', bridgeId, phoneId);
    const phone = await connect();
    phone.register('phone', phoneId, bridgeId);
    await bridge.wait('relay/peer-online');
    expect(relay.stats().tunnels).toBe(1);
  });
});

describe('relay connector over a real relay', () => {
  let relay: RelayServer;
  let port: number;
  let connector: RelayConnector;
  let backend: FakeBackend;
  let phonePeer: TestPeer;
  let phone: TestPhone;
  let bridgeRoutingId: string;
  let phoneRoutingId: string;

  const bridgeKeys = generateKeyPairSync('ed25519');
  const phoneKeys = generateKeyPairSync('ed25519');
  const rawPublic = (key: KeyObject): string =>
    toBase64Url(key.export({ type: 'spki', format: 'der' }).subarray(12));
  const bridgePublic = rawPublic(bridgeKeys.publicKey);
  const phonePublic = rawPublic(phoneKeys.publicKey);

  beforeEach(async () => {
    relay = new RelayServer({ frameRatePerMinute: 5_000 });
    port = await relay.listen(0, '127.0.0.1');
    backend = new FakeBackend();
    bridgeRoutingId = newRoutingId();
    phoneRoutingId = newRoutingId();

    connector = new RelayConnector({
      relayUrl: `ws://127.0.0.1:${port}${RELAY_PATH}`,
      routingId: bridgeRoutingId,
      peerRoutingId: phoneRoutingId,
      ownStaticPublicKey: bridgePublic,
      ownStaticPrivateKey: bridgeKeys.privateKey,
      peerStaticPublicKey: phonePublic,
      backend,
      minBackoffMs: 20,
      maxBackoffMs: 60,
    });
    connector.start();

    phonePeer = await TestPeer.connect(port);
    phonePeer.register('phone', phoneRoutingId, bridgeRoutingId);
    await phonePeer.wait('relay/peer-online');
    phone = new TestPhone(
      phonePeer,
      // Session id is `initiator:responder`, matching the connector.
      `${phoneRoutingId}:${bridgeRoutingId}`,
      phonePublic,
      phoneKeys.privateKey,
      bridgePublic,
    );
  });

  afterEach(async () => {
    connector.stop();
    phonePeer.close();
    await relay.close();
  });

  it('establishes a sealed tunnel through the relay', async () => {
    await phone.establish();
    expect(connector.getState()).toBe('tunneled');
    expect(connector.stats().tunneled).toBe(true);
  });

  it('forwards a tunnel request to the bridge and returns the response', async () => {
    await phone.establish();
    backend.nextBody = { ok: true, value: { rpcId: 'r1', result: { ok: true } } };
    phone.send({ v: 1, type: 'tunnel/request', id: 'q1', method: 'POST', path: '/m1/rpc', body: { method: 'session.list' } });

    const response = await phone.waitTunnel('tunnel/response');
    expect(response).toMatchObject({ id: 'q1', status: 200 });
    expect(response.body).toEqual({ ok: true, value: { rpcId: 'r1', result: { ok: true } } });
    expect(backend.requests).toEqual([{ method: 'POST', path: '/m1/rpc', body: { method: 'session.list' } }]);
  });

  it('passes a non-200 status through unchanged', async () => {
    await phone.establish();
    backend.nextStatus = 403;
    backend.nextBody = { ok: false, error: { code: 'method-denied', message: 'denied' } };
    phone.send({ v: 1, type: 'tunnel/request', id: 'q2', method: 'POST', path: '/m1/rpc', body: {} });

    const response = await phone.waitTunnel('tunnel/response');
    // The phone must see the real status: 403 means stop, 401 means re-auth.
    expect(response).toMatchObject({ id: 'q2', status: 403 });
  });

  it('never inspects or rewrites the bearer token', async () => {
    await phone.establish();
    phone.send({
      v: 1,
      type: 'tunnel/request',
      id: 'q3',
      method: 'POST',
      path: '/m1/rpc',
      body: { authorization: 'Bearer opaque', method: 'session.list' },
    });
    await phone.waitTunnel('tunnel/response');
    // The connector holds no credentials: whatever the phone sent is what the
    // bridge's own router sees.
    expect(backend.requests[0]?.body).toEqual({ authorization: 'Bearer opaque', method: 'session.list' });
  });

  it('rejects a request for a path outside /m1', async () => {
    await phone.establish();
    phone.send({ v: 1, type: 'tunnel/request', id: 'q4', method: 'GET', path: '/etc/passwd' });
    const error = await phone.waitTunnel('tunnel/error');
    expect(error.message).toContain('/m1');
    expect(backend.requests).toHaveLength(0);
  });

  it('subscribes and forwards stream envelopes', async () => {
    await phone.establish();
    phone.send({ v: 1, type: 'tunnel/subscribe', id: 's1', token: 'tok-abc', after: 12 });
    await phone.waitTunnel('tunnel/subscribed');
    expect(backend.subscribes).toEqual([{ token: 'tok-abc', after: 12 }]);

    backend.streamSinks?.onMessage({ v: 1, kind: 'hello', lastBseq: 12 });
    backend.streamSinks?.onMessage({ v: 1, bseq: 13, kind: 'dsh', frame: { type: 'token' } });
    const events = await phone.waitTunnel('tunnel/event').then(() => phone.drain().filter((m) => m.type === 'tunnel/event'));
    expect(events).toHaveLength(2);
    expect(events[1]?.envelope).toEqual({ v: 1, bseq: 13, kind: 'dsh', frame: { type: 'token' } });
  });

  it('reports a refused subscription with the bridge status', async () => {
    await phone.establish();
    backend.streamFailure = { status: 401, reason: 'token expired' };
    phone.send({ v: 1, type: 'tunnel/subscribe', id: 's2', token: 'stale', after: 0 });
    const failed = await phone.waitTunnel('tunnel/subscribe-failed');
    expect(failed).toMatchObject({ id: 's2', status: 401 });
  });

  it('replaces a previous subscription on resubscribe', async () => {
    await phone.establish();
    phone.send({ v: 1, type: 'tunnel/subscribe', id: 's3', token: 't1', after: 0 });
    await phone.waitTunnel('tunnel/subscribed');
    phone.send({ v: 1, type: 'tunnel/subscribe', id: 's4', token: 't2', after: 5 });
    // Two acks, not one: waiting on the type alone would match the first again.
    const deadline = Date.now() + 2_000;
    while (phone.drain().filter((m) => m.type === 'tunnel/subscribed').length < 2 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(backend.streamCloses).toBe(1);
    expect(backend.subscribes).toEqual([
      { token: 't1', after: 0 },
      { token: 't2', after: 5 },
    ]);
  });

  it('answers a tunnel ping inside the sealed channel', async () => {
    await phone.establish();
    phone.send({ v: 1, type: 'tunnel/ping', at: 4242 });
    expect((await phone.waitTunnel('tunnel/pong')).at).toBe(4242);
  });

  it('drops the tunnel when a record fails authentication', async () => {
    await phone.establish();
    phone.sendRaw({ n: '0', c: 'dGFtcGVyZWQtY2lwaGVydGV4dA' });
    await new Promise((resolve) => setTimeout(resolve, 100));
    // Fail-closed: a forged record ends the session rather than being skipped.
    expect(connector.stats().tunneled).toBe(false);
    // Checked against the history, not `lastError`: the redial that follows can
    // legitimately report `routing-id-taken` if it beats the relay's cleanup.
    expect(connector.stats().recentErrors.join('|')).toContain('sealed record rejected');
  });

  it('rejects a peer whose static key is not the pinned one', async () => {
    const impostorKeys = generateKeyPairSync('ed25519');
    const impostor = new TestPhone(
      phonePeer,
      `${phoneRoutingId}:${bridgeRoutingId}`,
      rawPublic(impostorKeys.publicKey),
      impostorKeys.privateKey,
      bridgePublic,
    );
    await expect(impostor.establish()).rejects.toThrow(/bad-signature|handshake/);
    expect(connector.stats().tunneled).toBe(false);
  });

  it('tears the sealed session down when the phone disappears', async () => {
    await phone.establish();
    expect(connector.getState()).toBe('tunneled');
    phonePeer.close();
    const deadline = Date.now() + 2_000;
    while (connector.getState() !== 'registered' && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    // Keys must not outlive the peer: a returning phone renegotiates.
    expect(connector.getState()).toBe('registered');
    expect(connector.stats().tunneled).toBe(false);
  });

  it('redials after the relay goes away', async () => {
    await phone.establish();
    await relay.close();
    const deadline = Date.now() + 2_000;
    while (connector.getState() === 'tunneled' && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(connector.getState()).not.toBe('tunneled');
    expect(connector.stats().attempt).toBeGreaterThan(0);
  });

  it('refuses to construct with an invalid or self-referential routing id', () => {
    const base = {
      relayUrl: `ws://127.0.0.1:${port}${RELAY_PATH}`,
      ownStaticPublicKey: bridgePublic,
      ownStaticPrivateKey: bridgeKeys.privateKey,
      peerStaticPublicKey: phonePublic,
      backend,
    };
    expect(() => new RelayConnector({ ...base, routingId: 'too-short', peerRoutingId: newRoutingId() })).toThrow();
    const same = newRoutingId();
    expect(() => new RelayConnector({ ...base, routingId: same, peerRoutingId: same })).toThrow(/must differ/);
  });
});

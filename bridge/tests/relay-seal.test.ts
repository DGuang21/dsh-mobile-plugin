/**
 * The sealed tunnel is what makes a hostile relay tolerable, so these tests are
 * adversarial: every check asserts a *refusal*, not just that the happy path
 * works.
 */

import { describe, expect, it } from 'vitest';
import {
  SealedChannel,
  beginHandshake,
  completeHandshake,
  newRoutingId,
  signHandshake,
  type SealHandshake,
} from '../src/relay/seal.ts';
import { generateEd25519KeyPair } from '../src/identity/crypto.ts';

/** Drive a full two-sided handshake and return both channels. */
function pair(sessionId = 'session-1') {
  const bridgeKeys = generateEd25519KeyPair();
  const phoneKeys = generateEd25519KeyPair();

  const bridge = beginHandshake({
    role: 'responder',
    sessionId,
    ownStaticPublicKey: bridgeKeys.publicKeyB64,
    peerStaticPublicKey: phoneKeys.publicKeyB64,
  });
  const phone = beginHandshake({
    role: 'initiator',
    sessionId,
    ownStaticPublicKey: phoneKeys.publicKeyB64,
    peerStaticPublicKey: bridgeKeys.publicKeyB64,
  });

  // Each signs the transcript once it knows the peer's ephemeral.
  const bridgeMessage = { ...bridge.message, sig: signHandshake(bridge, phone.message.eph, bridgeKeys.privateKey) };
  const phoneMessage = { ...phone.message, sig: signHandshake(phone, bridge.message.eph, phoneKeys.privateKey) };

  return { bridge, phone, bridgeKeys, phoneKeys, bridgeMessage, phoneMessage };
}

function established(sessionId = 'session-1') {
  const context = pair(sessionId);
  const bridgeSide = completeHandshake(context.bridge, context.phoneMessage);
  const phoneSide = completeHandshake(context.phone, context.bridgeMessage);
  if (!bridgeSide.ok || !phoneSide.ok) throw new Error('handshake should have succeeded');
  return { ...context, bridgeChannel: bridgeSide.channel, phoneChannel: phoneSide.channel };
}

describe('handshake', () => {
  it('establishes a channel both sides can use', () => {
    const { bridgeChannel, phoneChannel } = established();
    const sealed = phoneChannel.sealJson({ hello: 'bridge' });
    expect(bridgeChannel.openJson(sealed)).toEqual({ ok: true, value: { hello: 'bridge' } });
  });

  it('derives matching keys in both directions', () => {
    const { bridgeChannel, phoneChannel } = established();
    const toBridge = phoneChannel.seal(Buffer.from('up'));
    const toPhone = bridgeChannel.seal(Buffer.from('down'));
    expect(bridgeChannel.open(toBridge)).toEqual({ ok: true, plaintext: Buffer.from('up') });
    expect(phoneChannel.open(toPhone)).toEqual({ ok: true, plaintext: Buffer.from('down') });
  });

  it('rejects a signature from the wrong static key, so a relay cannot substitute its identity', () => {
    const context = pair();
    const impostor = generateEd25519KeyPair();
    // The relay generates its own ephemeral and signs with its own key, then
    // presents the bridge's pinned public key as if it were the signer.
    const forged = beginHandshake({
      role: 'responder',
      sessionId: 'session-1',
      ownStaticPublicKey: impostor.publicKeyB64,
      peerStaticPublicKey: context.phoneKeys.publicKeyB64,
    });
    const forgedMessage = {
      ...forged.message,
      sig: signHandshake(forged, context.phone.message.eph, impostor.privateKey),
    };
    expect(completeHandshake(context.phone, forgedMessage)).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('rejects a swapped ephemeral, because the signature covers the transcript', () => {
    const context = pair();
    const other = beginHandshake({
      role: 'responder',
      sessionId: 'session-1',
      ownStaticPublicKey: context.bridgeKeys.publicKeyB64,
      peerStaticPublicKey: context.phoneKeys.publicKeyB64,
    });
    // Valid signature, but paired with a different ephemeral.
    const tampered = { ...context.bridgeMessage, eph: other.message.eph };
    expect(completeHandshake(context.phone, tampered)).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('rejects a mismatched session id, so a record cannot be moved between tunnels', () => {
    const bridgeKeys = generateEd25519KeyPair();
    const phoneKeys = generateEd25519KeyPair();
    const bridge = beginHandshake({
      role: 'responder',
      sessionId: 'session-A',
      ownStaticPublicKey: bridgeKeys.publicKeyB64,
      peerStaticPublicKey: phoneKeys.publicKeyB64,
    });
    const phone = beginHandshake({
      role: 'initiator',
      sessionId: 'session-B',
      ownStaticPublicKey: phoneKeys.publicKeyB64,
      peerStaticPublicKey: bridgeKeys.publicKeyB64,
    });
    const bridgeMessage = { ...bridge.message, sig: signHandshake(bridge, phone.message.eph, bridgeKeys.privateKey) };
    expect(completeHandshake(phone, bridgeMessage)).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('fails closed on malformed peer messages instead of throwing', () => {
    const context = pair();
    const cases: unknown[] = [
      null,
      undefined,
      42,
      'nope',
      {},
      { v: 2, eph: context.bridgeMessage.eph, sig: context.bridgeMessage.sig },
      { v: 1 },
      { v: 1, eph: 123, sig: 'x' },
      { v: 1, eph: '!!!not-base64url!!!', sig: context.bridgeMessage.sig },
      { v: 1, eph: 'c2hvcnQ', sig: context.bridgeMessage.sig },
      { v: 1, eph: context.bridgeMessage.eph, sig: '' },
      { v: 1, eph: context.bridgeMessage.eph, sig: '!!!' },
    ];
    for (const message of cases) {
      const result = completeHandshake(context.phone, message);
      expect(result.ok, `should refuse ${JSON.stringify(message)}`).toBe(false);
    }
  });

  it('refuses an all-zero ephemeral', () => {
    const context = pair();
    const zero = Buffer.alloc(32).toString('base64url');
    const result = completeHandshake(context.phone, { v: 1, eph: zero, sig: context.bridgeMessage.sig });
    // Caught at signature verification (the transcript changed) or at key
    // agreement. Either is a refusal; what matters is no channel is produced.
    expect(result.ok).toBe(false);
  });

  it('produces a different channel for every session', () => {
    const first = established('s1');
    const second = established('s2');
    const sealed = first.phoneChannel.seal(Buffer.from('secret'));
    // A record from one session must not open in another.
    expect(second.bridgeChannel.open(sealed)).toEqual({ ok: false, reason: 'auth-failed' });
  });
});

describe('record layer', () => {
  it('rejects a replayed record', () => {
    const { bridgeChannel, phoneChannel } = established();
    const sealed = phoneChannel.seal(Buffer.from('once'));
    expect(bridgeChannel.open(sealed).ok).toBe(true);
    expect(bridgeChannel.open(sealed)).toEqual({ ok: false, reason: 'replay' });
  });

  it('rejects an out-of-order record below the high-water mark', () => {
    const { bridgeChannel, phoneChannel } = established();
    const first = phoneChannel.seal(Buffer.from('1'));
    const second = phoneChannel.seal(Buffer.from('2'));
    expect(bridgeChannel.open(second).ok).toBe(true);
    // The relay held the first record back and delivered it late.
    expect(bridgeChannel.open(first)).toEqual({ ok: false, reason: 'replay' });
  });

  it('rejects a renumbered record, because the counter is authenticated', () => {
    const { bridgeChannel, phoneChannel } = established();
    const sealed = phoneChannel.seal(Buffer.from('payload'));
    const renumbered = { n: '999', c: sealed.c };
    expect(bridgeChannel.open(renumbered)).toEqual({ ok: false, reason: 'auth-failed' });
  });

  it('rejects tampered ciphertext', () => {
    const { bridgeChannel, phoneChannel } = established();
    const sealed = phoneChannel.seal(Buffer.from('payload'));
    const bytes = Buffer.from(sealed.c, 'base64url');
    bytes[0] = (bytes[0] as number) ^ 0xff;
    expect(bridgeChannel.open({ n: sealed.n, c: bytes.toString('base64url') })).toEqual({
      ok: false,
      reason: 'auth-failed',
    });
  });

  it('rejects a truncated record', () => {
    const { bridgeChannel, phoneChannel } = established();
    const sealed = phoneChannel.seal(Buffer.from('payload'));
    const bytes = Buffer.from(sealed.c, 'base64url').subarray(0, 8);
    expect(bridgeChannel.open({ n: sealed.n, c: bytes.toString('base64url') })).toEqual({
      ok: false,
      reason: 'bad-frame',
    });
  });

  it('does not let a record be reflected back at its sender', () => {
    const { phoneChannel } = established();
    const sealed = phoneChannel.seal(Buffer.from('payload'));
    // Directional keys: the sender cannot open its own record.
    expect(phoneChannel.open(sealed)).toEqual({ ok: false, reason: 'auth-failed' });
  });

  it('fails closed on malformed records', () => {
    const { bridgeChannel } = established();
    const cases: unknown[] = [
      null,
      42,
      'nope',
      {},
      { n: 'abc', c: 'AAAA' },
      { n: '-1', c: 'AAAA' },
      { n: 1, c: 'AAAA' },
      { n: '0', c: '!!!' },
      { n: '0', c: '' },
      { n: '99999999999999999999999', c: 'AAAA' },
    ];
    for (const record of cases) {
      expect(bridgeChannel.open(record).ok, `should refuse ${JSON.stringify(record)}`).toBe(false);
    }
  });

  it('carries frames larger than one AES block', () => {
    const { bridgeChannel, phoneChannel } = established();
    const payload = Buffer.alloc(200_000, 0x41);
    const opened = bridgeChannel.open(phoneChannel.seal(payload));
    expect(opened.ok && opened.plaintext.equals(payload)).toBe(true);
  });

  it('preserves ordering across many records', () => {
    const { bridgeChannel, phoneChannel } = established();
    for (let index = 0; index < 200; index += 1) {
      const opened = bridgeChannel.open(phoneChannel.seal(Buffer.from(`frame-${index}`)));
      expect(opened.ok && opened.plaintext.toString('utf8')).toBe(`frame-${index}`);
    }
    expect(bridgeChannel.stats().receivedThrough).toBe('199');
  });

  it('reports a decrypted non-JSON payload as a bad frame', () => {
    const { bridgeChannel, phoneChannel } = established();
    const sealed = phoneChannel.seal(Buffer.from('not json'));
    expect(bridgeChannel.openJson(sealed)).toEqual({ ok: false, reason: 'bad-frame' });
  });

  it('zeroes keys on close and refuses further use', () => {
    const { bridgeChannel, phoneChannel } = established();
    const sealed = phoneChannel.seal(Buffer.from('payload'));
    bridgeChannel.close();
    expect(bridgeChannel.isClosed()).toBe(true);
    expect(bridgeChannel.open(sealed)).toEqual({ ok: false, reason: 'bad-frame' });
    expect(() => phoneChannel.seal(Buffer.from('x'))).not.toThrow();
    phoneChannel.close();
    expect(() => phoneChannel.seal(Buffer.from('x'))).toThrow(/closed/);
  });

  it('never reuses a nonce, which is what would break GCM', () => {
    const { phoneChannel } = established();
    const counters = new Set<string>();
    for (let index = 0; index < 500; index += 1) counters.add(phoneChannel.seal(Buffer.from('x')).n);
    expect(counters.size).toBe(500);
  });
});

describe('routing ids', () => {
  it('are unguessable and unique', () => {
    const ids = new Set<string>();
    for (let index = 0; index < 500; index += 1) ids.add(newRoutingId());
    expect(ids.size).toBe(500);
    // 16 bytes base64url, no padding.
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});

describe('channel construction', () => {
  it('is usable directly with symmetric keys, for relay-side tests', () => {
    const keyA = Buffer.alloc(32, 1);
    const keyB = Buffer.alloc(32, 2);
    const left = new SealedChannel({ sendKey: Buffer.from(keyA), receiveKey: Buffer.from(keyB), sessionId: 's' });
    const right = new SealedChannel({ sendKey: Buffer.from(keyB), receiveKey: Buffer.from(keyA), sessionId: 's' });
    const opened = right.open(left.seal(Buffer.from('ping')));
    expect(opened.ok && opened.plaintext.toString('utf8')).toBe('ping');
  });

  it('exposes counters without leaking key material', () => {
    const { phoneChannel } = established();
    phoneChannel.seal(Buffer.from('a'));
    const stats: Record<string, unknown> = phoneChannel.stats();
    expect(stats.sent).toBe('1');
    expect(JSON.stringify(stats)).not.toMatch(/[A-Za-z0-9+/]{40,}/);
  });
});

// Referenced so the type import is load-bearing for readers, not just tests.
export type { SealHandshake };

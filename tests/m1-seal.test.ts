/**
 * The RN seal must agree with `bridge/src/relay/seal.ts` byte for byte, or a
 * phone and a bridge derive different keys and every record fails to open. The
 * bridge is Node-only, so rather than import it, these tests recompute the same
 * values with `node:crypto` directly — the primitives the bridge is built from.
 * If `@noble/*` and `node:crypto` ever diverge, this is where it surfaces.
 */

import { describe, expect, it } from 'vitest';
import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import { fromBase64Url, toBase64Url, utf8 } from '../src/m1/bytes';
import {
  aesGcmOpen,
  aesGcmSeal,
  domainMessage,
  ed25519PublicKeyFromSeed,
  generateX25519KeyPair,
  hkdfSha256,
  randomBytes,
  signBytes,
  verifyBytes,
  x25519SharedSecret,
} from '../src/m1/crypto';
import {
  SealedChannel,
  beginHandshake,
  beginPairingHandshake,
  completeHandshake,
  completePairingHandshakeAsPhone,
  handshakeTranscript,
  isValidRoutingId,
  newRoutingId,
  pairingTokenBinder,
  signHandshake,
} from '../src/m1/seal';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Import a raw 32-byte X25519 public key the way the bridge does. */
function nodeX25519Public(raw: Uint8Array) {
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });
}

function nodeX25519Private(raw: Uint8Array) {
  const prefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
  return createPrivateKey({ key: Buffer.concat([prefix, Buffer.from(raw)]), format: 'der', type: 'pkcs8' });
}

function nodeEd25519Private(seed: Uint8Array) {
  return createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
}

function nodeEd25519Public(raw: Uint8Array) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return createPublicKey({ key: Buffer.concat([prefix, Buffer.from(raw)]), format: 'der', type: 'spki' });
}

describe('primitive agreement with node:crypto', () => {
  it('derives the same X25519 shared secret', () => {
    const phone = generateX25519KeyPair();
    const nodePair = generateKeyPairSync('x25519');
    const nodeRaw = new Uint8Array(
      nodePair.publicKey.export({ type: 'spki', format: 'der' }).subarray(X25519_SPKI_PREFIX.byteLength),
    );

    const ours = x25519SharedSecret(phone.privateKey, nodeRaw);
    const theirs = diffieHellman({ privateKey: nodePair.privateKey, publicKey: nodeX25519Public(phone.publicKey) });

    expect(ours).toBeDefined();
    expect(Buffer.from(ours!).equals(theirs)).toBe(true);
  });

  it('derives the same HKDF-SHA256 output', () => {
    const ikm = randomBytes(32);
    const salt = randomBytes(64);
    const info = utf8('dshm relay i2r');
    const ours = hkdfSha256(ikm, salt, info, 32);
    const theirs = Buffer.from(hkdfSync('sha256', ikm, salt, info, 32));
    expect(Buffer.from(ours).equals(theirs)).toBe(true);
  });

  it('produces AES-256-GCM ciphertext node can open, and vice versa', () => {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const aad = randomBytes(8);
    const plaintext = utf8('sealed tunnel frame');

    const ours = aesGcmSeal(key, nonce, aad, plaintext);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(ours.subarray(ours.byteLength - 16)));
    const nodeOpened = Buffer.concat([
      decipher.update(Buffer.from(ours.subarray(0, ours.byteLength - 16))),
      decipher.final(),
    ]);
    expect(nodeOpened.toString('utf8')).toBe('sealed tunnel frame');

    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(aad);
    const nodeSealed = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]);
    const oursOpened = aesGcmOpen(key, nonce, aad, new Uint8Array(nodeSealed));
    expect(oursOpened).toBeDefined();
    expect(Buffer.from(oursOpened!).toString('utf8')).toBe('sealed tunnel frame');
  });

  it('signs and verifies Ed25519 interoperably in both directions', () => {
    const seed = randomBytes(32);
    const publicKey = ed25519PublicKeyFromSeed(seed);
    const message = domainMessage('relay-seal', 'session', 'a', 'b', 'c', 'd');

    // Ours signs, node verifies.
    const ourSig = signBytes(message, seed);
    expect(nodeVerify(null, Buffer.from(message), nodeEd25519Public(publicKey), Buffer.from(ourSig))).toBe(true);

    // Node signs, ours verifies. This is the direction that matters most: the
    // phone verifying the bridge's pinned static key.
    const nodeSig = nodeSign(null, Buffer.from(message), nodeEd25519Private(seed));
    expect(verifyBytes(publicKey, message, new Uint8Array(nodeSig))).toBe(true);

    // And node's public key export matches our derivation from the same seed.
    const nodeRawPublic = nodeEd25519Public(publicKey).export({ type: 'spki', format: 'der' }).subarray(12);
    expect(Buffer.from(publicKey).equals(nodeRawPublic)).toBe(true);
  });
});

describe('transcript and binder agreement', () => {
  it('builds the same domain-separated transcript bytes as the bridge formula', () => {
    // Recomputed here from the spec rather than imported, so a change to either
    // side's layout breaks this test.
    const parts = ['sess:id', 'initStatic', 'respStatic', 'initEph', 'respEph'];
    const ours = domainMessage('relay-seal', ...parts);

    const chunks: Buffer[] = [Buffer.from('dshm/relay-seal', 'utf8')];
    for (const part of parts) {
      const bytes = Buffer.from(part, 'utf8');
      const length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.byteLength, 0);
      chunks.push(length, bytes);
    }
    expect(Buffer.from(ours).equals(Buffer.concat(chunks))).toBe(true);
  });

  it('derives the same pairing token binder as the bridge formula', () => {
    const token = toBase64Url(randomBytes(32));
    const bridgeId = 'bridge-abc';
    const ours = pairingTokenBinder(token, bridgeId);
    const theirs = toBase64Url(
      new Uint8Array(
        hkdfSync('sha256', Buffer.from(token, 'utf8'), Buffer.from(bridgeId, 'utf8'), Buffer.from('dshm pair binder', 'utf8'), 32),
      ),
    );
    expect(ours).toBe(theirs);
    expect(fromBase64Url(ours)?.byteLength).toBe(32);
  });

  it('orders transcript fields canonically regardless of role', () => {
    const phone = beginHandshake({
      role: 'initiator',
      sessionId: 'P:B',
      ownStaticPublicKey: 'phone-static',
      peerStaticPublicKey: 'bridge-static',
    });
    const bridge = beginHandshake({
      role: 'responder',
      sessionId: 'P:B',
      ownStaticPublicKey: 'bridge-static',
      peerStaticPublicKey: 'phone-static',
    });

    const fromPhone = handshakeTranscript(phone, bridge.message.eph);
    const fromBridge = handshakeTranscript(bridge, phone.message.eph);
    expect(Buffer.from(fromPhone).equals(Buffer.from(fromBridge))).toBe(true);
  });
});

/**
 * A minimal responder built the way `bridge/src/relay/seal.ts` builds one, from
 * `node:crypto` directly. Not a mock of the RN code — an independent
 * implementation of the same spec, so agreement means the wire format is right
 * rather than that two copies of one bug match.
 */
function nodeResponder(input: { sessionId: string; initiatorStatic: string; responderSeed: Uint8Array }) {
  const pair = generateKeyPairSync('x25519');
  const rawPublic = pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(X25519_SPKI_PREFIX.byteLength);
  const ephB64 = toBase64Url(new Uint8Array(rawPublic));
  const responderStatic = toBase64Url(ed25519PublicKeyFromSeed(input.responderSeed));

  function transcriptFor(initiatorEph: string): Buffer {
    return Buffer.from(
      domainMessage('relay-seal', input.sessionId, input.initiatorStatic, responderStatic, initiatorEph, ephB64),
    );
  }

  return {
    responderStatic,
    ephB64,
    /** Round one answer: our ephemeral plus a signature over the transcript. */
    reply(initiatorEph: string) {
      const sig = nodeSign(null, transcriptFor(initiatorEph), nodeEd25519Private(input.responderSeed));
      return { v: 1 as const, eph: ephB64, sig: toBase64Url(new Uint8Array(sig)) };
    },
    /** Derive the same two directional keys the phone derives. */
    keys(initiatorEph: string, initiatorEphRaw: Uint8Array) {
      const shared = diffieHellman({ privateKey: pair.privateKey, publicKey: nodeX25519Public(initiatorEphRaw) });
      const salt = transcriptFor(initiatorEph);
      return {
        i2r: Buffer.from(hkdfSync('sha256', shared, salt, Buffer.from('dshm relay i2r', 'utf8'), 32)),
        r2i: Buffer.from(hkdfSync('sha256', shared, salt, Buffer.from('dshm relay r2i', 'utf8'), 32)),
        transcript: salt,
      };
    },
  };
}

describe('handshake interop against a node:crypto responder', () => {
  it('completes, and both sides derive identical directional keys', () => {
    const bridgeSeed = randomBytes(32);
    const bridgeStatic = toBase64Url(ed25519PublicKeyFromSeed(bridgeSeed));
    const phoneSeed = randomBytes(32);
    const phoneStatic = toBase64Url(ed25519PublicKeyFromSeed(phoneSeed));

    const phone = beginHandshake({
      role: 'initiator',
      sessionId: 'PPPPPPPPPPPPPPPPPPPPPP:BBBBBBBBBBBBBBBBBBBBBB',
      ownStaticPublicKey: phoneStatic,
      peerStaticPublicKey: bridgeStatic,
    });
    const bridge = nodeResponder({
      sessionId: 'PPPPPPPPPPPPPPPPPPPPPP:BBBBBBBBBBBBBBBBBBBBBB',
      initiatorStatic: phoneStatic,
      responderSeed: bridgeSeed,
    });

    const completed = completeHandshake(phone, bridge.reply(phone.message.eph));
    expect(completed.ok).toBe(true);
    if (!completed.ok) return;

    // The phone's own round-two signature must verify against its static key on
    // the bridge side — this is what the bridge defers during pairing.
    const phoneSig = signHandshake(phone, bridge.ephB64, phoneSeed);
    const derived = bridge.keys(phone.message.eph, fromBase64Url(phone.message.eph)!);
    expect(nodeVerify(null, derived.transcript, nodeEd25519Public(fromBase64Url(phoneStatic)!), Buffer.from(fromBase64Url(phoneSig)!))).toBe(true);

    // A frame the phone seals opens with the bridge's i2r key, at the same nonce
    // and AAD. This is the whole wire format in one assertion.
    const record = completed.channel.sealJson({ hello: 'bridge' });
    expect(record.n).toBe('0');
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(0n, 4);
    const aad = Buffer.alloc(8);
    aad.writeBigUInt64BE(0n, 0);
    const sealed = fromBase64Url(record.c)!;
    const decipher = createDecipheriv('aes-256-gcm', derived.i2r, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(sealed.subarray(sealed.byteLength - 16)));
    const opened = Buffer.concat([
      decipher.update(Buffer.from(sealed.subarray(0, sealed.byteLength - 16))),
      decipher.final(),
    ]);
    expect(JSON.parse(opened.toString('utf8'))).toEqual({ hello: 'bridge' });

    // And the reverse direction: a frame the bridge seals with r2i opens on the phone.
    const replyNonce = Buffer.alloc(12);
    replyNonce.writeBigUInt64BE(0n, 4);
    const cipher = createCipheriv('aes-256-gcm', derived.r2i, replyNonce);
    cipher.setAAD(aad);
    const bridgeSealed = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify({ hello: 'phone' }), 'utf8')),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    const back = completed.channel.openJson({ n: '0', c: toBase64Url(new Uint8Array(bridgeSealed)) });
    expect(back).toEqual({ ok: true, value: { hello: 'phone' } });
  });

  it('refuses a responder that signs with the wrong static key', () => {
    const pinnedSeed = randomBytes(32);
    const pinned = toBase64Url(ed25519PublicKeyFromSeed(pinnedSeed));
    const impostorSeed = randomBytes(32);

    const phone = beginHandshake({
      role: 'initiator',
      sessionId: 'session',
      ownStaticPublicKey: 'binder',
      peerStaticPublicKey: pinned,
    });

    // The impostor signs the EXACT transcript the phone will compute — one that
    // names the pinned key — but with its own private key. So the failure can
    // only come from the key check, not from a transcript mismatch, which is the
    // property that stops a relay from substituting itself.
    const impostorEph = toBase64Url(generateX25519KeyPair().publicKey);
    const exact = handshakeTranscript(phone, impostorEph);
    const forgedSig = nodeSign(null, Buffer.from(exact), nodeEd25519Private(impostorSeed));
    const forged = { v: 1 as const, eph: impostorEph, sig: toBase64Url(new Uint8Array(forgedSig)) };

    expect(completeHandshake(phone, forged)).toEqual({ ok: false, reason: 'bad-signature' });

    // Sanity: the same transcript signed by the pinned key IS accepted, so the
    // test above failed for the right reason.
    const goodSig = nodeSign(null, Buffer.from(exact), nodeEd25519Private(pinnedSeed));
    const good = { v: 1 as const, eph: impostorEph, sig: toBase64Url(new Uint8Array(goodSig)) };
    expect(completeHandshake(phone, good).ok).toBe(true);
  });
});

describe('record layer', () => {
  function pair(): { a: SealedChannel; b: SealedChannel } {
    const i2r = randomBytes(32);
    const r2i = randomBytes(32);
    return {
      a: new SealedChannel({ sendKey: Uint8Array.from(i2r), receiveKey: Uint8Array.from(r2i), sessionId: 's' }),
      b: new SealedChannel({ sendKey: Uint8Array.from(r2i), receiveKey: Uint8Array.from(i2r), sessionId: 's' }),
    };
  }

  it('numbers records from zero and round-trips them in order', () => {
    const { a, b } = pair();
    for (let index = 0; index < 4; index += 1) {
      const record = a.sealJson({ index });
      expect(record.n).toBe(String(index));
      expect(b.openJson(record)).toEqual({ ok: true, value: { index } });
    }
    expect(a.stats()).toEqual({ sent: '4', receivedThrough: '-1' });
    expect(b.stats()).toEqual({ sent: '0', receivedThrough: '3' });
  });

  it('rejects a replayed record', () => {
    const { a, b } = pair();
    const record = a.sealJson({ n: 1 });
    expect(b.openJson(record).ok).toBe(true);
    expect(b.openJson(record)).toEqual({ ok: false, reason: 'replay' });
  });

  it('rejects a record renumbered below the high-water mark', () => {
    const { a, b } = pair();
    const first = a.sealJson({ n: 1 });
    const second = a.sealJson({ n: 2 });
    expect(b.openJson(second).ok).toBe(true);
    // The relay reordering frames looks exactly like this. `first` is genuine but
    // stale, and accepting it would mean accepting a replay.
    expect(b.openJson(first)).toEqual({ ok: false, reason: 'replay' });
  });

  it('tolerates a gap, since the counter is a high-water mark and not a sequence', () => {
    const { a, b } = pair();
    a.sealJson({ dropped: true });
    const second = a.sealJson({ delivered: true });
    expect(b.openJson(second)).toEqual({ ok: true, value: { delivered: true } });
  });

  it('does not advance the high-water mark on a forged record', () => {
    const { a, b } = pair();
    const genuine = a.sealJson({ real: true });
    // Same counter, garbage ciphertext. If this advanced the mark, the genuine
    // record behind it would be locked out — a one-frame denial of service.
    expect(b.openJson({ n: genuine.n, c: toBase64Url(randomBytes(32)) })).toEqual({ ok: false, reason: 'auth-failed' });
    expect(b.openJson(genuine)).toEqual({ ok: true, value: { real: true } });
  });

  it('rejects a renumbered counter, because the counter is authenticated as AAD', () => {
    const { a, b } = pair();
    const record = a.sealJson({ real: true });
    expect(b.openJson({ n: '7', c: record.c })).toEqual({ ok: false, reason: 'auth-failed' });
  });

  it('refuses malformed frames without throwing', () => {
    const { a, b } = pair();
    a.sealJson({ warm: true });
    for (const bad of [
      null,
      undefined,
      'string',
      42,
      {},
      { n: '0' },
      { c: 'AAAA' },
      { n: 0, c: 'AAAA' },
      { n: '', c: 'AAAA' },
      { n: ' 1', c: 'AAAA' },
      { n: '+1', c: 'AAAA' },
      { n: '-1', c: 'AAAA' },
      { n: '01', c: 'AAAA' },
      { n: '0x10', c: 'AAAA' },
      { n: '1e3', c: 'AAAA' },
      { n: '18446744073709551616', c: 'AAAA' },
      { n: '5', c: 'not base64url!!' },
      { n: '5', c: '' },
      { n: '5', c: toBase64Url(randomBytes(15)) },
    ]) {
      const result = b.open(bad);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(['bad-frame', 'auth-failed']).toContain(result.reason);
    }
  });

  it('accepts the maximum counter as a well-formed frame, refusing on the tag', () => {
    const { b } = pair();
    // 2^64-1 is in range; it must fail on authentication, not be silently treated
    // as a bad frame, and must not poison the high-water mark.
    expect(b.open({ n: '18446744073709551615', c: toBase64Url(randomBytes(32)) })).toEqual({
      ok: false,
      reason: 'auth-failed',
    });
    expect(b.stats().receivedThrough).toBe('-1');
  });

  it('refuses a record that decrypts but is not JSON', () => {
    const { a, b } = pair();
    const record = a.seal(utf8('not json'));
    expect(b.open(record).ok).toBe(true);
    const next = a.seal(utf8('{ broken'));
    expect(b.openJson(next)).toEqual({ ok: false, reason: 'bad-frame' });
  });

  it('wipes keys on close and refuses further use', () => {
    const { a, b } = pair();
    const record = a.sealJson({ before: true });
    b.close();
    expect(b.isClosed()).toBe(true);
    expect(b.open(record)).toEqual({ ok: false, reason: 'bad-frame' });
    a.close();
    expect(() => a.sealJson({ after: true })).toThrow(/closed/);
  });

  it('gives each direction a distinct key, so a record cannot be reflected', () => {
    const bridgeSeed = randomBytes(32);
    const bridgeStatic = toBase64Url(ed25519PublicKeyFromSeed(bridgeSeed));
    const phone = beginHandshake({
      role: 'initiator',
      sessionId: 'reflect',
      ownStaticPublicKey: 'binder',
      peerStaticPublicKey: bridgeStatic,
    });
    const bridge = nodeResponder({ sessionId: 'reflect', initiatorStatic: 'binder', responderSeed: bridgeSeed });
    const completed = completeHandshake(phone, bridge.reply(phone.message.eph));
    expect(completed.ok).toBe(true);
    if (!completed.ok) return;

    const outbound = completed.channel.sealJson({ request: 1 });
    // Feeding our own record back to us must fail: the receive key is the other
    // direction's key. (Counter 0 is also below no high-water mark yet, so this
    // reaches the crypto and fails there.)
    expect(completed.channel.open(outbound)).toEqual({ ok: false, reason: 'auth-failed' });
  });
});

describe('pairing handshake', () => {
  it('agrees with a bridge that fills the initiator slot with the binder', () => {
    const token = toBase64Url(randomBytes(32));
    const bridgeId = 'bridge-xyz';
    const binder = pairingTokenBinder(token, bridgeId);
    const bridgeSeed = randomBytes(32);
    const bridgeStatic = toBase64Url(ed25519PublicKeyFromSeed(bridgeSeed));
    const sessionId = 'PPPPPPPPPPPPPPPPPPPPPP:RRRRRRRRRRRRRRRRRRRRRR';

    const phone = beginPairingHandshake({
      role: 'initiator',
      sessionId,
      bridgeStaticPublicKey: bridgeStatic,
      tokenBinder: binder,
    });
    // The bridge's own `beginPairingHandshake` puts the binder in the peer slot;
    // from the transcript's point of view that is the initiator static.
    const bridge = nodeResponder({ sessionId, initiatorStatic: binder, responderSeed: bridgeSeed });

    const completed = completePairingHandshakeAsPhone({ handshake: phone, peerMessage: bridge.reply(phone.message.eph) });
    expect(completed.ok).toBe(true);
  });

  it('fails without the token, so a relay that never saw the QR cannot pair', () => {
    const bridgeSeed = randomBytes(32);
    const bridgeStatic = toBase64Url(ed25519PublicKeyFromSeed(bridgeSeed));
    const sessionId = 'session';

    const phone = beginPairingHandshake({
      role: 'initiator',
      sessionId,
      bridgeStaticPublicKey: bridgeStatic,
      tokenBinder: pairingTokenBinder('the-real-token', 'bridge-xyz'),
    });
    // The bridge computed a different binder, so it signed different bytes.
    const bridge = nodeResponder({
      sessionId,
      initiatorStatic: pairingTokenBinder('a-guessed-token', 'bridge-xyz'),
      responderSeed: bridgeSeed,
    });

    expect(
      completePairingHandshakeAsPhone({ handshake: phone, peerMessage: bridge.reply(phone.message.eph) }),
    ).toEqual({ ok: false, reason: 'bad-signature' });
  });
});

describe('handshake input validation', () => {
  const bridgeStatic = toBase64Url(ed25519PublicKeyFromSeed(randomBytes(32)));

  function fresh() {
    return beginHandshake({
      role: 'initiator',
      sessionId: 's',
      ownStaticPublicKey: 'binder',
      peerStaticPublicKey: bridgeStatic,
    });
  }

  it('starts unsigned, since the transcript needs the peer ephemeral', () => {
    const handshake = fresh();
    expect(handshake.message).toEqual({ v: 1, eph: handshake.ephemeralPublicB64, sig: '' });
    expect(fromBase64Url(handshake.message.eph)?.byteLength).toBe(32);
  });

  it('refuses malformed peer messages with a specific reason and no throw', () => {
    expect(completeHandshake(fresh(), null).ok).toBe(false);
    expect(completeHandshake(fresh(), {})).toEqual({ ok: false, reason: 'bad-version' });
    expect(completeHandshake(fresh(), { v: 2, eph: 'a', sig: 'b' })).toEqual({ ok: false, reason: 'bad-version' });
    expect(completeHandshake(fresh(), { v: 1, eph: 42, sig: 'b' })).toEqual({ ok: false, reason: 'bad-ephemeral' });
    expect(completeHandshake(fresh(), { v: 1, eph: 'a', sig: 42 })).toEqual({ ok: false, reason: 'bad-ephemeral' });
    expect(completeHandshake(fresh(), { v: 1, eph: 'not-base64!', sig: 'b' })).toEqual({ ok: false, reason: 'bad-ephemeral' });
    expect(completeHandshake(fresh(), { v: 1, eph: toBase64Url(randomBytes(31)), sig: 'b' })).toEqual({
      ok: false,
      reason: 'bad-ephemeral',
    });
    // Well-formed ephemeral, unverifiable signature.
    expect(completeHandshake(fresh(), { v: 1, eph: toBase64Url(randomBytes(32)), sig: '' })).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('reports a corrupt pinned key as bad-static-key rather than a signature failure', () => {
    const shortPin = beginHandshake({
      role: 'initiator',
      sessionId: 's',
      ownStaticPublicKey: 'binder',
      peerStaticPublicKey: toBase64Url(randomBytes(31)),
    });
    expect(completeHandshake(shortPin, { v: 1, eph: toBase64Url(randomBytes(32)), sig: 'AAAA' })).toEqual({
      ok: false,
      reason: 'bad-static-key',
    });

    const unparseablePin = beginHandshake({
      role: 'initiator',
      sessionId: 's',
      ownStaticPublicKey: 'binder',
      peerStaticPublicKey: 'not base64url',
    });
    expect(completeHandshake(unparseablePin, { v: 1, eph: toBase64Url(randomBytes(32)), sig: 'AAAA' })).toEqual({
      ok: false,
      reason: 'bad-static-key',
    });
  });

  it('is single-use, so a replayed handshake frame cannot re-derive a key', () => {
    const bridgeSeed = randomBytes(32);
    const pinned = toBase64Url(ed25519PublicKeyFromSeed(bridgeSeed));
    const handshake = beginHandshake({
      role: 'initiator',
      sessionId: 's',
      ownStaticPublicKey: 'binder',
      peerStaticPublicKey: pinned,
    });
    const bridge = nodeResponder({ sessionId: 's', initiatorStatic: 'binder', responderSeed: bridgeSeed });
    const reply = bridge.reply(handshake.message.eph);

    const first = completeHandshake(handshake, reply);
    expect(first.ok).toBe(true);
    // The ephemeral private key is wiped by the first completion. A wiped X25519
    // scalar still agrees on *something*, so without the guard this would hand
    // back a second channel with a silently different key.
    expect(completeHandshake(handshake, reply)).toEqual({ ok: false, reason: 'handshake-consumed' });
  });

  it('rejects an all-zero peer ephemeral, which would force a known shared secret', () => {
    // Signature is checked before key agreement, so this needs a real signature
    // over the zero-ephemeral transcript to reach the agreement step.
    const bridgeSeed = randomBytes(32);
    const pinned = toBase64Url(ed25519PublicKeyFromSeed(bridgeSeed));
    const handshake = beginHandshake({
      role: 'initiator',
      sessionId: 's',
      ownStaticPublicKey: 'binder',
      peerStaticPublicKey: pinned,
    });
    const zeroEph = toBase64Url(new Uint8Array(32));
    const sig = nodeSign(null, Buffer.from(handshakeTranscript(handshake, zeroEph)), nodeEd25519Private(bridgeSeed));
    expect(completeHandshake(handshake, { v: 1, eph: zeroEph, sig: toBase64Url(new Uint8Array(sig)) })).toEqual({
      ok: false,
      reason: 'key-agreement-failed',
    });
  });
});

describe('routing ids', () => {
  it('mints 22-character base64url ids that the relay would accept', () => {
    for (let index = 0; index < 32; index += 1) {
      const id = newRoutingId();
      expect(id).toHaveLength(22);
      expect(isValidRoutingId(id)).toBe(true);
      expect(fromBase64Url(id)?.byteLength).toBe(16);
    }
  });

  it('does not repeat', () => {
    const seen = new Set<string>();
    for (let index = 0; index < 256; index += 1) seen.add(newRoutingId());
    expect(seen.size).toBe(256);
  });

  it('rejects ids the relay would reject', () => {
    for (const bad of [undefined, null, 42, '', 'short', 'A'.repeat(21), 'A'.repeat(23), 'A'.repeat(21) + '=', 'A'.repeat(21) + '+']) {
      expect(isValidRoutingId(bad)).toBe(false);
    }
  });
});

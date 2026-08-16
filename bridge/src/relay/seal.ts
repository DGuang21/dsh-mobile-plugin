/**
 * [OUR DESIGN] End-to-end sealing for Mode B (relay) transport.
 *
 * The relay is treated as a hostile network. TLS to the relay is transport
 * hygiene, not the security boundary — the relay terminates it and would
 * otherwise see every prompt, every approval and every token. So application
 * frames are sealed again inside the tunnel, and the relay sees only ciphertext,
 * frame lengths and timing.
 *
 * Handshake (Noise-IK-shaped, built from node:crypto primitives):
 *   1. Both sides hold a pinned Ed25519 static key. The phone pinned the bridge's
 *      key from the pairing QR; the bridge holds the phone's from its registry.
 *      Neither is learned from the relay, which is what stops the relay from
 *      substituting its own identity.
 *   2. Each side sends a fresh X25519 ephemeral public key plus an Ed25519
 *      signature over a transcript that commits to BOTH statics, BOTH ephemerals,
 *      the session id and the direction.
 *   3. The shared secret is X25519(own ephemeral, peer ephemeral), run through
 *      HKDF-SHA256 with the transcript as salt/info, yielding two directional
 *      AES-256-GCM keys.
 *
 * Properties this buys, and why each matters here:
 *   - Relay tampering with any handshake field changes the transcript, so every
 *     derived key changes and the first record fails to decrypt. Fail-closed.
 *   - Signing the transcript (not just the ephemeral) binds the ephemeral exchange
 *     to the pinned static key, so a relay cannot splice its own ephemeral in.
 *   - Directional keys mean a record cannot be reflected back at its sender.
 *   - A strictly increasing 64-bit counter as the GCM nonce makes replay and
 *     nonce reuse structurally impossible rather than merely unlikely.
 *
 * Forward secrecy is per session: ephemerals are discarded on close, so a later
 * static-key compromise does not decrypt captured traffic.
 *
 * Every function here fails closed — it returns a result object and never throws
 * on malformed peer input. A relay feeding us garbage must produce a clean
 * refusal, not an exception that unwinds a connection handler.
 */

import { createCipheriv, createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, type KeyObject } from 'node:crypto';
import {
  ED25519_PUBLIC_KEY_BYTES,
  domainMessage,
  fromBase64Url,
  publicKeyFromRaw,
  signMessage,
  toBase64Url,
  verifySignature,
} from '../identity/crypto.ts';

/** X25519 raw public keys are 32 bytes, same as Ed25519. */
export const X25519_PUBLIC_KEY_BYTES = 32;
/** AES-256-GCM. */
export const SEAL_KEY_BYTES = 32;
export const GCM_NONCE_BYTES = 12;
export const GCM_TAG_BYTES = 16;

/** DER prefix for a raw X25519 public key wrapped as SPKI (RFC 8410). */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export type SealRole = 'initiator' | 'responder';

export interface SealHandshakeMessage {
  v: 1;
  /** base64url raw X25519 ephemeral public key. */
  eph: string;
  /** base64url Ed25519 signature over the handshake transcript. */
  sig: string;
}

export type HandshakeFailure =
  | 'bad-version'
  | 'bad-ephemeral'
  | 'bad-signature'
  | 'bad-static-key'
  | 'key-agreement-failed';

export type CompleteResult =
  | { ok: true; channel: SealedChannel }
  | { ok: false; reason: HandshakeFailure };

/** Wrap a raw 32-byte X25519 public key so node:crypto will import it. */
function x25519PublicFromRaw(raw: Buffer): KeyObject | undefined {
  if (raw.byteLength !== X25519_PUBLIC_KEY_BYTES) return undefined;
  try {
    return createPublicKey({
      key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return undefined;
  }
}

/**
 * The bytes both sides sign and derive from.
 *
 * Ordering is canonical (initiator fields always first) rather than
 * sender-relative, so both sides compute an identical transcript. Every field is
 * length-prefixed by `domainMessage`, so no combination of values can be
 * reinterpreted as a different combination.
 */
function transcript(input: {
  sessionId: string;
  initiatorStatic: string;
  responderStatic: string;
  initiatorEphemeral: string;
  responderEphemeral: string;
}): Buffer {
  return domainMessage(
    'relay-seal',
    input.sessionId,
    input.initiatorStatic,
    input.responderStatic,
    input.initiatorEphemeral,
    input.responderEphemeral,
  );
}

/** One side's in-progress handshake. */
export interface SealHandshake {
  readonly role: SealRole;
  readonly sessionId: string;
  readonly message: SealHandshakeMessage;
  /** Kept only until the handshake completes, then discarded. */
  readonly ephemeralPublicB64: string;
  readonly ephemeralPrivate: KeyObject;
  readonly ownStaticB64: string;
  readonly peerStaticB64: string;
}

/**
 * Begin a handshake.
 *
 * The signature cannot be produced yet — the transcript commits to the peer's
 * ephemeral, which is not known. So `message.sig` is filled in by
 * {@link completeHandshake}, which is also where the peer's message arrives. The
 * two-message exchange is therefore: both sides send ephemerals, both sides then
 * send signatures. Callers send `message` first and the signature second.
 */
export function beginHandshake(input: {
  role: SealRole;
  sessionId: string;
  /** base64url raw Ed25519 public key of this side. */
  ownStaticPublicKey: string;
  /** base64url raw Ed25519 public key of the peer, pinned out of band. */
  peerStaticPublicKey: string;
}): SealHandshake {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const rawPublic = publicKey.export({ type: 'spki', format: 'der' }).subarray(X25519_SPKI_PREFIX.byteLength);
  const ephemeralPublicB64 = toBase64Url(rawPublic);
  return {
    role: input.role,
    sessionId: input.sessionId,
    message: { v: 1, eph: ephemeralPublicB64, sig: '' },
    ephemeralPublicB64,
    ephemeralPrivate: privateKey,
    ownStaticB64: input.ownStaticPublicKey,
    peerStaticB64: input.peerStaticPublicKey,
  };
}

/** The transcript this side must sign, once the peer's ephemeral is known. */
export function handshakeTranscript(handshake: SealHandshake, peerEphemeralB64: string): Buffer {
  const isInitiator = handshake.role === 'initiator';
  return transcript({
    sessionId: handshake.sessionId,
    initiatorStatic: isInitiator ? handshake.ownStaticB64 : handshake.peerStaticB64,
    responderStatic: isInitiator ? handshake.peerStaticB64 : handshake.ownStaticB64,
    initiatorEphemeral: isInitiator ? handshake.ephemeralPublicB64 : peerEphemeralB64,
    responderEphemeral: isInitiator ? peerEphemeralB64 : handshake.ephemeralPublicB64,
  });
}

/** Sign the transcript with this side's Ed25519 static private key. */
export function signHandshake(
  handshake: SealHandshake,
  peerEphemeralB64: string,
  ownStaticPrivateKey: KeyObject,
): string {
  return toBase64Url(signMessage(ownStaticPrivateKey, handshakeTranscript(handshake, peerEphemeralB64)));
}

/**
 * Verify the peer's handshake message and derive the record keys.
 *
 * Order of checks is deliberate: shape, then ephemeral validity, then signature,
 * then key agreement. Nothing derives a key from unauthenticated material.
 */
export function completeHandshake(handshake: SealHandshake, peerMessage: unknown): CompleteResult {
  const message = peerMessage as Partial<SealHandshakeMessage> | null;
  if (typeof message !== 'object' || message === null || message.v !== 1) {
    return { ok: false, reason: 'bad-version' };
  }
  if (typeof message.eph !== 'string' || typeof message.sig !== 'string') {
    return { ok: false, reason: 'bad-ephemeral' };
  }

  const peerEphemeralRaw = fromBase64Url(message.eph);
  if (peerEphemeralRaw === undefined || peerEphemeralRaw.byteLength !== X25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: 'bad-ephemeral' };
  }
  const peerEphemeral = x25519PublicFromRaw(peerEphemeralRaw);
  if (peerEphemeral === undefined) return { ok: false, reason: 'bad-ephemeral' };

  const peerStaticRaw = fromBase64Url(handshake.peerStaticB64);
  if (peerStaticRaw === undefined || peerStaticRaw.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: 'bad-static-key' };
  }
  // Confirm the pinned key imports before using it, so a corrupt registry entry
  // is reported as `bad-static-key` rather than a confusing signature failure.
  if (publicKeyFromRaw(peerStaticRaw) === undefined) return { ok: false, reason: 'bad-static-key' };

  // The transcript the PEER signed: same canonical field order, so both sides
  // sign identical bytes.
  const expected = handshakeTranscript(handshake, message.eph);
  const signature = fromBase64Url(message.sig);
  if (signature === undefined || !verifySignature(peerStaticRaw, expected, signature)) {
    return { ok: false, reason: 'bad-signature' };
  }

  let shared: Buffer;
  try {
    shared = diffieHellman({ privateKey: handshake.ephemeralPrivate, publicKey: peerEphemeral });
  } catch {
    // Includes an all-zero / low-order peer point, which X25519 rejects.
    return { ok: false, reason: 'key-agreement-failed' };
  }
  // A zero shared secret means a contributory-behaviour failure; refuse rather
  // than deriving keys an attacker also knows.
  if (shared.every((byte) => byte === 0)) return { ok: false, reason: 'key-agreement-failed' };

  // Two independent keys from one secret. Labels are distinct, so the
  // initiator→responder key can never equal the reverse key.
  const i2r = Buffer.from(hkdfSync('sha256', shared, expected, Buffer.from('dshm relay i2r', 'utf8'), SEAL_KEY_BYTES));
  const r2i = Buffer.from(hkdfSync('sha256', shared, expected, Buffer.from('dshm relay r2i', 'utf8'), SEAL_KEY_BYTES));
  shared.fill(0);

  const isInitiator = handshake.role === 'initiator';
  return {
    ok: true,
    channel: new SealedChannel({
      sendKey: isInitiator ? i2r : r2i,
      receiveKey: isInitiator ? r2i : i2r,
      sessionId: handshake.sessionId,
    }),
  };
}

export type OpenFailure = 'bad-frame' | 'replay' | 'auth-failed';

export type OpenResult = { ok: true; plaintext: Buffer } | { ok: false; reason: OpenFailure };

/**
 * A sealed record: `{ n: <counter>, c: <base64url ciphertext||tag> }`.
 *
 * The counter is on the wire because the receiver needs it to build the nonce,
 * and it is authenticated as AAD so a relay cannot renumber records to induce a
 * gap or a replay.
 */
export interface SealedRecord {
  n: string;
  c: string;
}

/**
 * The record layer.
 *
 * Nonces are the 64-bit send counter, big-endian, left-padded to 12 bytes. Since
 * the counter never repeats for a given key and each direction has its own key,
 * a nonce is never reused — the failure mode that breaks GCM catastrophically.
 */
export class SealedChannel {
  private readonly sendKey: Buffer;
  private readonly receiveKey: Buffer;
  readonly sessionId: string;
  private sendCounter = 0n;
  /** Highest counter accepted so far; anything at or below it is a replay. */
  private receiveHighWater = -1n;
  private closed = false;

  constructor(input: { sendKey: Buffer; receiveKey: Buffer; sessionId: string }) {
    this.sendKey = input.sendKey;
    this.receiveKey = input.receiveKey;
    this.sessionId = input.sessionId;
  }

  /** Seal a plaintext frame. */
  seal(plaintext: Buffer): SealedRecord {
    if (this.closed) throw new Error('sealed channel is closed');
    const counter = this.sendCounter;
    // 2^64 records is unreachable in practice; refusing is still cheaper than
    // reasoning about what wrapping would do to nonce uniqueness.
    if (counter === 0xffff_ffff_ffff_ffffn) throw new Error('send counter exhausted');
    this.sendCounter += 1n;
    const nonce = nonceFor(counter);
    const cipher = createCipheriv('aes-256-gcm', this.sendKey, nonce);
    cipher.setAAD(aadFor(counter));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { n: counter.toString(10), c: toBase64Url(Buffer.concat([body, cipher.getAuthTag()])) };
  }

  sealJson(value: unknown): SealedRecord {
    return this.seal(Buffer.from(JSON.stringify(value), 'utf8'));
  }

  /**
   * Open a sealed record.
   *
   * Rejects a counter at or below the high-water mark before doing any crypto, so
   * a replayed record is cheap to refuse. The high-water mark advances only after
   * successful authentication, so a forged record cannot poison it and lock out
   * legitimate traffic.
   */
  open(record: unknown): OpenResult {
    if (this.closed) return { ok: false, reason: 'bad-frame' };
    const candidate = record as Partial<SealedRecord> | null;
    if (typeof candidate !== 'object' || candidate === null) return { ok: false, reason: 'bad-frame' };
    if (typeof candidate.n !== 'string' || typeof candidate.c !== 'string') return { ok: false, reason: 'bad-frame' };

    let counter: bigint;
    try {
      counter = BigInt(candidate.n);
    } catch {
      return { ok: false, reason: 'bad-frame' };
    }
    if (counter < 0n || counter > 0xffff_ffff_ffff_ffffn) return { ok: false, reason: 'bad-frame' };
    if (counter <= this.receiveHighWater) return { ok: false, reason: 'replay' };

    const sealed = fromBase64Url(candidate.c);
    if (sealed === undefined || sealed.byteLength < GCM_TAG_BYTES) return { ok: false, reason: 'bad-frame' };

    const body = sealed.subarray(0, sealed.byteLength - GCM_TAG_BYTES);
    const tag = sealed.subarray(sealed.byteLength - GCM_TAG_BYTES);
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.receiveKey, nonceFor(counter));
      decipher.setAAD(aadFor(counter));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
      // Only now is the counter trusted.
      this.receiveHighWater = counter;
      return { ok: true, plaintext };
    } catch {
      // Tag mismatch: wrong key, tampered ciphertext, or renumbered counter.
      return { ok: false, reason: 'auth-failed' };
    }
  }

  /** Open and JSON-parse. A record that decrypts but is not JSON is a bad frame. */
  openJson(record: unknown): { ok: true; value: unknown } | { ok: false; reason: OpenFailure } {
    const opened = this.open(record);
    if (!opened.ok) return opened;
    try {
      return { ok: true, value: JSON.parse(opened.plaintext.toString('utf8')) };
    } catch {
      return { ok: false, reason: 'bad-frame' };
    }
  }

  /** Zero the keys. Called when the tunnel drops. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.sendKey.fill(0);
    this.receiveKey.fill(0);
  }

  isClosed(): boolean {
    return this.closed;
  }

  /** Counters as strings, for diagnostics. Never exposes key material. */
  stats(): { sent: string; receivedThrough: string } {
    return { sent: this.sendCounter.toString(10), receivedThrough: this.receiveHighWater.toString(10) };
  }
}

/** 64-bit counter, big-endian, left-padded into a 12-byte GCM nonce. */
function nonceFor(counter: bigint): Buffer {
  const nonce = Buffer.alloc(GCM_NONCE_BYTES);
  nonce.writeBigUInt64BE(counter, GCM_NONCE_BYTES - 8);
  return nonce;
}

/** The counter, authenticated so a relay cannot renumber a record. */
function aadFor(counter: bigint): Buffer {
  const aad = Buffer.alloc(8);
  aad.writeBigUInt64BE(counter, 0);
  return aad;
}

/** Opaque routing id for the relay. 16 bytes: unguessable, not a device secret. */
export function newRoutingId(): string {
  return toBase64Url(randomBytes(16));
}

// ── pairing handshake (Mode B, first pair) ──────────────────────────────────

/**
 * [OUR DESIGN] The seal variant used before a device is paired.
 *
 * The steady-state handshake above cannot be used for a first pairing: its
 * transcript commits to BOTH pinned Ed25519 statics, and at first contact the
 * bridge does not yet know the phone's key — that key arrives inside the claim, so
 * requiring it to build the channel that carries the claim is circular.
 *
 * The substitution is deliberate and narrow: the phone's static is replaced in the
 * transcript by a **token binder**, `HKDF(pairing token)`. What each side proves:
 *
 *   - The **bridge** still signs the transcript with its static key, exactly as in
 *     steady state. The phone pinned that key from the QR, so a relay — or anyone
 *     else in the path — still cannot impersonate the bridge. This is the property
 *     that matters most, because it is what stops a hostile relay from running a
 *     man in the middle over the pairing exchange.
 *   - The **phone** proves it saw the QR, because the binder cannot be computed
 *     without the 32-byte token. It also signs the transcript with its device key;
 *     the bridge cannot verify that yet, so it retains the transcript and checks
 *     the signature the moment the claim reveals the device public key. That check
 *     is what binds this sealed channel to the key being registered, so a relay
 *     cannot splice one device's channel onto another device's claim.
 *
 * Confidentiality is unconditional against the relay: the token, the device public
 * key, the label, the proof and the SAS-bearing response are all inside AES-GCM.
 *
 * What this does NOT defend against, stated plainly: someone who reads the QR
 * (shoulder-surfs it, or photographs the screen) can compute the binder and open a
 * pairing channel of their own. That is the same exposure Mode A has, and it is
 * why the operator-confirmed SAS is mandatory in both modes — the SAS commits to
 * the device public key, so an attacker's channel produces a code that does not
 * match the phone in the user's hand. The token is also single-use and consumed
 * atomically, so only one claim can ever reach the SAS step.
 */
export const PAIRING_BINDER_BYTES = 32;

/**
 * Derive the token binder that stands in for the phone's static key.
 *
 * A hash rather than the token itself so the transcript — which is signed and
 * could be retained — never contains the live token.
 */
export function pairingTokenBinder(token: string, bridgeId: string): string {
  return toBase64Url(
    Buffer.from(hkdfSync('sha256', Buffer.from(token, 'utf8'), Buffer.from(bridgeId, 'utf8'), Buffer.from('dshm pair binder', 'utf8'), PAIRING_BINDER_BYTES)),
  );
}

/**
 * Begin a pairing handshake.
 *
 * Both sides must produce IDENTICAL transcript bytes or no signature can verify, so
 * the two static slots are pinned by meaning rather than by whose key it is:
 * the initiator slot always holds the token binder (standing in for the phone's
 * not-yet-known device key) and the responder slot always holds the bridge's real
 * static. This function assigns them from `role` so a caller cannot get the
 * orientation wrong — the phone passes the same two values the bridge does.
 *
 * Everything downstream — transcript ordering, signing, key derivation, the record
 * layer — is the same code as steady state, so there is no second crypto path to
 * keep correct.
 */
export function beginPairingHandshake(input: {
  /** `initiator` is the phone; `responder` is the bridge. */
  role: SealRole;
  sessionId: string;
  /** The bridge's real Ed25519 static: its own, or the phone's pinned copy from the QR. */
  bridgeStaticPublicKey: string;
  /** The binder from {@link pairingTokenBinder}. */
  tokenBinder: string;
}): SealHandshake {
  const isPhone = input.role === 'initiator';
  return beginHandshake({
    role: input.role,
    sessionId: input.sessionId,
    ownStaticPublicKey: isPhone ? input.tokenBinder : input.bridgeStaticPublicKey,
    peerStaticPublicKey: isPhone ? input.bridgeStaticPublicKey : input.tokenBinder,
  });
}

/**
 * Complete a pairing handshake on the side that CAN verify its peer.
 *
 * Used by the phone: it holds the bridge's pinned static key in `peerStaticB64`
 * already, so the bridge's signature is verified in full by the normal
 * {@link completeHandshake} path. A bridge that cannot produce that signature — a
 * relay attempting a man in the middle, say — fails here, before any key is derived.
 */
export function completePairingHandshakeAsPhone(input: {
  handshake: SealHandshake;
  peerMessage: unknown;
}): CompleteResult {
  return completeHandshake(input.handshake, input.peerMessage);
}

/**
 * The transcript a bridge must retain to verify a device key later.
 *
 * Returned alongside the channel because the bridge completes the handshake before
 * it knows whose key to check the peer signature against.
 */
export interface DeferredPeerProof {
  /** Bytes the peer signed. */
  transcript: Buffer;
  /** base64url Ed25519 signature the peer sent. */
  signature: string;
}

export type CompletePairingAsBridgeResult =
  | { ok: true; channel: SealedChannel; deferred: DeferredPeerProof }
  | { ok: false; reason: HandshakeFailure };

/**
 * Complete a pairing handshake on the bridge side.
 *
 * The peer's signature cannot be verified here — the device key is unknown until
 * the claim arrives — so it is captured for {@link verifyDeferredPeerProof}. The
 * channel is derived from the X25519 exchange, which is unaffected: an attacker
 * without the binder cannot produce a transcript both sides agree on, and the first
 * record therefore fails to open.
 */
export function completePairingHandshakeAsBridge(
  handshake: SealHandshake,
  peerMessage: unknown,
): CompletePairingAsBridgeResult {
  const message = peerMessage as { v?: unknown; eph?: unknown; sig?: unknown } | null;
  if (typeof message !== 'object' || message === null || message.v !== 1) {
    return { ok: false, reason: 'bad-version' };
  }
  if (typeof message.eph !== 'string' || typeof message.sig !== 'string') {
    return { ok: false, reason: 'bad-ephemeral' };
  }

  const peerEphemeralRaw = fromBase64Url(message.eph);
  if (peerEphemeralRaw === undefined || peerEphemeralRaw.byteLength !== X25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: 'bad-ephemeral' };
  }
  const peerEphemeral = x25519PublicFromRaw(peerEphemeralRaw);
  if (peerEphemeral === undefined) return { ok: false, reason: 'bad-ephemeral' };

  const expected = handshakeTranscript(handshake, message.eph);

  let shared: Buffer;
  try {
    shared = diffieHellman({ privateKey: handshake.ephemeralPrivate, publicKey: peerEphemeral });
  } catch {
    return { ok: false, reason: 'key-agreement-failed' };
  }
  if (shared.every((byte) => byte === 0)) return { ok: false, reason: 'key-agreement-failed' };

  const i2r = Buffer.from(hkdfSync('sha256', shared, expected, Buffer.from('dshm relay i2r', 'utf8'), SEAL_KEY_BYTES));
  const r2i = Buffer.from(hkdfSync('sha256', shared, expected, Buffer.from('dshm relay r2i', 'utf8'), SEAL_KEY_BYTES));
  shared.fill(0);

  const isInitiator = handshake.role === 'initiator';
  return {
    ok: true,
    channel: new SealedChannel({
      sendKey: isInitiator ? i2r : r2i,
      receiveKey: isInitiator ? r2i : i2r,
      sessionId: handshake.sessionId,
    }),
    deferred: { transcript: expected, signature: message.sig },
  };
}

/**
 * Check a retained pairing transcript against the device key from the claim.
 *
 * Fails closed. A claim whose key did not establish the channel it arrived on is
 * refused, which is what makes the sealed channel and the registered device the
 * same principal.
 */
export function verifyDeferredPeerProof(deferred: DeferredPeerProof, devicePublicKeyB64: string): boolean {
  const key = fromBase64Url(devicePublicKeyB64);
  if (key === undefined || key.byteLength !== ED25519_PUBLIC_KEY_BYTES) return false;
  const signature = fromBase64Url(deferred.signature);
  if (signature === undefined) return false;
  return verifySignature(key, deferred.transcript, signature);
}

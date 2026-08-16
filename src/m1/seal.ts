/**
 * [OUR DESIGN] Phone-side end-to-end sealing for Mode B (relay) transport.
 *
 * This is the RN counterpart of `bridge/src/relay/seal.ts` and must agree with it
 * byte for byte: same transcript layout, same HKDF labels, same nonce and AAD
 * construction, same wire record. Read that file for the full rationale of the
 * handshake; the short version is that the relay is treated as a hostile network,
 * so every application frame is sealed again inside the tunnel and the relay sees
 * only ciphertext, lengths and timing.
 *
 * Differences from the bridge version, all of them mechanical:
 *   - `@noble/*` instead of `node:crypto`, since Hermes has neither. Byte
 *     compatibility of X25519, HKDF-SHA256 and AES-256-GCM between the two was
 *     checked directly rather than assumed (`tests/m1-seal.test.ts`).
 *   - `Uint8Array` instead of `Buffer`, and no SPKI wrapping: `@noble/curves`
 *     takes raw 32-byte X25519 keys, so the DER prefix the bridge needs has no
 *     analogue here. The bytes on the wire are identical either way.
 *   - 64-bit counter fields are written with explicit shifts rather than
 *     `DataView.setBigUint64`, because engine BigInt support and typed-array
 *     BigInt accessors are separate features and Hermes has historically shipped
 *     one without the other. BigInt itself is already a hard requirement of
 *     `@noble/curves`, so using it for counters adds no new engine dependency.
 *
 * Every function fails closed: results are returned, never thrown, on any peer
 * input. A hostile relay feeding us garbage must produce a clean refusal, not an
 * exception unwinding a socket handler.
 */

import { bytesEqual, concatBytes, fromBase64Url, fromUtf8, toBase64Url, utf8, wipe } from './bytes';
import {
  ED25519_PUBLIC_KEY_BYTES,
  GCM_NONCE_BYTES,
  GCM_TAG_BYTES,
  SEAL_KEY_BYTES,
  X25519_PUBLIC_KEY_BYTES,
  aesGcmOpen,
  aesGcmSeal,
  domainMessage,
  generateX25519KeyPair,
  hkdfSha256,
  isValidEd25519PublicKey,
  randomBytes,
  signBytes,
  verifyBytes,
  x25519SharedSecret,
} from './crypto';

export { GCM_NONCE_BYTES, GCM_TAG_BYTES, SEAL_KEY_BYTES, X25519_PUBLIC_KEY_BYTES };

/** Routing ids are 16 random bytes, base64url, so exactly 22 characters. */
export const ROUTING_ID_BYTES = 16;
const ROUTING_ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;

const MAX_COUNTER = 0xffff_ffff_ffff_ffffn;

/** Canonical unsigned decimal, no sign, no padding, no whitespace. */
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;

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
  | 'key-agreement-failed'
  /** A second completion was attempted on a handshake that already produced a channel. */
  | 'handshake-consumed';

export type CompleteResult = { ok: true; channel: SealedChannel } | { ok: false; reason: HandshakeFailure };

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
}): Uint8Array {
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
  readonly ephemeralPrivate: Uint8Array;
  readonly ownStaticB64: string;
  readonly peerStaticB64: string;
  /**
   * Set once a channel has been derived from this handshake.
   *
   * The ephemeral private key is wiped at that point, and a wiped X25519 scalar
   * is not an error — it clamps to a valid one — so a second completion would
   * quietly agree on a different key instead of failing. Callers are supposed to
   * reject a duplicate handshake frame themselves; this makes the wipe safe even
   * if one does not.
   */
  consumed: boolean;
}

/**
 * Begin a handshake.
 *
 * The signature cannot be produced yet — the transcript commits to the peer's
 * ephemeral, which is not known. So `message.sig` is empty and the signature is
 * sent in a second frame once the peer's ephemeral arrives. The phone is always
 * the `initiator`; roles are fixed rather than negotiated because the
 * transcript's field order depends on them, and a negotiable role would be one
 * more thing a hostile relay could try to confuse.
 */
export function beginHandshake(input: {
  role: SealRole;
  sessionId: string;
  /** base64url raw Ed25519 public key of this side. */
  ownStaticPublicKey: string;
  /** base64url raw Ed25519 public key of the peer, pinned out of band. */
  peerStaticPublicKey: string;
}): SealHandshake {
  const pair = generateX25519KeyPair();
  const ephemeralPublicB64 = toBase64Url(pair.publicKey);
  return {
    role: input.role,
    sessionId: input.sessionId,
    message: { v: 1, eph: ephemeralPublicB64, sig: '' },
    ephemeralPublicB64,
    ephemeralPrivate: pair.privateKey,
    ownStaticB64: input.ownStaticPublicKey,
    peerStaticB64: input.peerStaticPublicKey,
    consumed: false,
  };
}

/** The transcript this side must sign, once the peer's ephemeral is known. */
export function handshakeTranscript(handshake: SealHandshake, peerEphemeralB64: string): Uint8Array {
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
  ownStaticPrivateKey: Uint8Array,
): string {
  return toBase64Url(signBytes(handshakeTranscript(handshake, peerEphemeralB64), ownStaticPrivateKey));
}

/**
 * Verify the peer's handshake message and derive the record keys.
 *
 * Order of checks is deliberate: shape, then ephemeral validity, then signature,
 * then key agreement. Nothing derives a key from unauthenticated material.
 *
 * On the phone this is the branch that catches a hostile relay: `peerStaticB64`
 * is the `bk` pinned from the QR, and without the matching private key no relay
 * can produce a transcript signature that verifies.
 */
export function completeHandshake(handshake: SealHandshake, peerMessage: unknown): CompleteResult {
  if (handshake.consumed) return { ok: false, reason: 'handshake-consumed' };

  const message = peerMessage as { v?: unknown; eph?: unknown; sig?: unknown } | null;
  if (typeof message !== 'object' || message === null || message.v !== 1) {
    return { ok: false, reason: 'bad-version' };
  }
  if (typeof message.eph !== 'string' || typeof message.sig !== 'string') {
    return { ok: false, reason: 'bad-ephemeral' };
  }

  const peerEphemeral = fromBase64Url(message.eph);
  if (peerEphemeral === undefined || peerEphemeral.byteLength !== X25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: 'bad-ephemeral' };
  }

  const peerStatic = fromBase64Url(handshake.peerStaticB64);
  if (peerStatic === undefined || peerStatic.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, reason: 'bad-static-key' };
  }
  // Confirm the pinned key is a usable point before using it, so a corrupt stored
  // pin is reported as `bad-static-key` rather than a confusing signature failure.
  if (!isValidEd25519PublicKey(handshake.peerStaticB64)) return { ok: false, reason: 'bad-static-key' };

  // The transcript the PEER signed: same canonical field order, so both sides
  // sign identical bytes.
  const expected = handshakeTranscript(handshake, message.eph);
  const signature = fromBase64Url(message.sig);
  if (signature === undefined || !verifyBytes(peerStatic, expected, signature)) {
    return { ok: false, reason: 'bad-signature' };
  }

  // Returns undefined for a low-order or all-zero result, which is a
  // contributory-behaviour failure: refuse rather than deriving keys an attacker
  // also knows.
  const shared = x25519SharedSecret(handshake.ephemeralPrivate, peerEphemeral);
  if (shared === undefined) return { ok: false, reason: 'key-agreement-failed' };

  const channel = deriveChannel(handshake, shared, expected);
  return { ok: true, channel };
}

/**
 * Two independent keys from one secret, then the secret is wiped.
 *
 * The labels are distinct, so the initiator→responder key can never equal the
 * reverse key and a record cannot be reflected back at its sender.
 */
function deriveChannel(handshake: SealHandshake, shared: Uint8Array, transcriptBytes: Uint8Array): SealedChannel {
  const i2r = hkdfSha256(shared, transcriptBytes, utf8('dshm relay i2r'), SEAL_KEY_BYTES);
  const r2i = hkdfSha256(shared, transcriptBytes, utf8('dshm relay r2i'), SEAL_KEY_BYTES);
  wipe(shared);
  handshake.consumed = true;
  wipe(handshake.ephemeralPrivate);

  const isInitiator = handshake.role === 'initiator';
  return new SealedChannel({
    sendKey: isInitiator ? i2r : r2i,
    receiveKey: isInitiator ? r2i : i2r,
    sessionId: handshake.sessionId,
  });
}

export type OpenFailure = 'bad-frame' | 'replay' | 'auth-failed';

export type OpenResult = { ok: true; plaintext: Uint8Array } | { ok: false; reason: OpenFailure };

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
 * Nonces are the 64-bit send counter, big-endian, left-padded to 12 bytes. The
 * counter never repeats for a given key and each direction has its own key, so a
 * nonce is never reused — the failure mode that breaks GCM catastrophically.
 */
export class SealedChannel {
  private readonly sendKey: Uint8Array;
  private readonly receiveKey: Uint8Array;
  readonly sessionId: string;
  private sendCounter = 0n;
  /** Highest counter accepted so far; anything at or below it is a replay. */
  private receiveHighWater = -1n;
  private closed = false;

  constructor(input: { sendKey: Uint8Array; receiveKey: Uint8Array; sessionId: string }) {
    this.sendKey = input.sendKey;
    this.receiveKey = input.receiveKey;
    this.sessionId = input.sessionId;
  }

  /**
   * Seal a plaintext frame.
   *
   * Throws only on programmer error (using a closed channel) or counter
   * exhaustion, both of which are our own state rather than peer input.
   */
  seal(plaintext: Uint8Array): SealedRecord {
    if (this.closed) throw new Error('sealed channel is closed');
    const counter = this.sendCounter;
    // 2^64 records is unreachable in practice; refusing is still cheaper than
    // reasoning about what wrapping would do to nonce uniqueness.
    if (counter === MAX_COUNTER) throw new Error('send counter exhausted');
    this.sendCounter += 1n;
    const sealed = aesGcmSeal(this.sendKey, nonceFor(counter), aadFor(counter), plaintext);
    return { n: counter.toString(10), c: toBase64Url(sealed) };
  }

  sealJson(value: unknown): SealedRecord {
    return this.seal(utf8(JSON.stringify(value)));
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
    const candidate = record as { n?: unknown; c?: unknown } | null;
    if (typeof candidate !== 'object' || candidate === null) return { ok: false, reason: 'bad-frame' };
    if (typeof candidate.n !== 'string' || typeof candidate.c !== 'string') return { ok: false, reason: 'bad-frame' };

    // Stricter than `BigInt(...)` alone, which accepts whitespace, a sign, hex
    // prefixes and the empty string. A peer that sends anything but a canonical
    // decimal is not something we want to interpret.
    if (!DECIMAL_PATTERN.test(candidate.n)) return { ok: false, reason: 'bad-frame' };
    const counter = BigInt(candidate.n);
    if (counter > MAX_COUNTER) return { ok: false, reason: 'bad-frame' };
    if (counter <= this.receiveHighWater) return { ok: false, reason: 'replay' };

    const sealed = fromBase64Url(candidate.c);
    if (sealed === undefined || sealed.byteLength < GCM_TAG_BYTES) return { ok: false, reason: 'bad-frame' };

    const plaintext = aesGcmOpen(this.receiveKey, nonceFor(counter), aadFor(counter), sealed);
    // Tag mismatch: wrong key, tampered ciphertext, or renumbered counter.
    if (plaintext === undefined) return { ok: false, reason: 'auth-failed' };

    // Only now is the counter trusted.
    this.receiveHighWater = counter;
    return { ok: true, plaintext };
  }

  /** Open and JSON-parse. A record that decrypts but is not JSON is a bad frame. */
  openJson(record: unknown): { ok: true; value: unknown } | { ok: false; reason: OpenFailure } {
    const opened = this.open(record);
    if (!opened.ok) return opened;
    try {
      return { ok: true, value: JSON.parse(fromUtf8(opened.plaintext)) as unknown };
    } catch {
      return { ok: false, reason: 'bad-frame' };
    }
  }

  /** Zero the keys. Called when the tunnel drops. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    wipe(this.sendKey);
    wipe(this.receiveKey);
  }

  isClosed(): boolean {
    return this.closed;
  }

  /** Counters as strings, for diagnostics. Never exposes key material. */
  stats(): { sent: string; receivedThrough: string } {
    return { sent: this.sendCounter.toString(10), receivedThrough: this.receiveHighWater.toString(10) };
  }
}

/**
 * 64-bit counter, big-endian, left-padded into a 12-byte GCM nonce.
 *
 * Written with shifts rather than `DataView.setBigUint64` so this works on any
 * engine that has BigInt at all, whether or not it also has the typed-array
 * BigInt accessors.
 */
function nonceFor(counter: bigint): Uint8Array {
  const nonce = new Uint8Array(GCM_NONCE_BYTES);
  writeBigUint64BE(nonce, GCM_NONCE_BYTES - 8, counter);
  return nonce;
}

/** The counter, authenticated so a relay cannot renumber a record. */
function aadFor(counter: bigint): Uint8Array {
  const aad = new Uint8Array(8);
  writeBigUint64BE(aad, 0, counter);
  return aad;
}

function writeBigUint64BE(target: Uint8Array, offset: number, value: bigint): void {
  let remaining = value;
  for (let index = 7; index >= 0; index -= 1) {
    target[offset + index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
}

/** Opaque routing id for the relay. 16 bytes: unguessable, not a device secret. */
export function newRoutingId(): string {
  return toBase64Url(randomBytes(ROUTING_ID_BYTES));
}

/**
 * Matches the relay's own check (`bridge/src/relay/protocol.ts`).
 *
 * Used on the durable `bridgeRoutingId` the bridge sends inside the sealed claim
 * response: it is relay-adjacent data arriving over an authenticated channel, but
 * validating the shape before persisting it keeps a malformed value from being
 * stored and failing every future connection.
 */
export function isValidRoutingId(value: unknown): value is string {
  return typeof value === 'string' && ROUTING_ID_PATTERN.test(value);
}

// ── pairing handshake (Mode B, first pair) ──────────────────────────────────

/**
 * [OUR DESIGN] The seal variant used before this device is paired.
 *
 * The steady-state handshake commits to BOTH pinned Ed25519 statics, but at first
 * contact the bridge does not know this phone's key — that key travels inside the
 * claim, so requiring it to build the channel that carries the claim is circular.
 * The phone's static slot is therefore filled by a **token binder**,
 * `HKDF(pairing token)`, which cannot be computed without having read the QR.
 *
 * What the phone still gets, and it is the property that matters here: the bridge
 * signs the transcript with the static key pinned from the QR, so a hostile relay
 * cannot man-in-the-middle the pairing exchange. What the phone gives: its own
 * signature over the same transcript, which the bridge cannot check yet and
 * retains until the claim reveals the device public key. That deferred check is
 * what binds this channel to the key being registered.
 *
 * See `bridge/src/relay/seal.ts` for the full argument, including what this does
 * not defend against (anyone who reads the QR can open a pairing channel of their
 * own — which is why the operator-confirmed SAS is mandatory in both modes).
 */
export const PAIRING_BINDER_BYTES = 32;

/**
 * Derive the token binder that stands in for the phone's static key.
 *
 * A hash rather than the token itself so the transcript — which is signed, and
 * which the bridge retains — never contains the live token.
 */
export function pairingTokenBinder(token: string, bridgeId: string): string {
  return toBase64Url(hkdfSha256(utf8(token), utf8(bridgeId), utf8('dshm pair binder'), PAIRING_BINDER_BYTES));
}

/**
 * Begin a pairing handshake.
 *
 * Both sides must produce IDENTICAL transcript bytes or no signature verifies, so
 * the static slots are pinned by meaning rather than by whose key it is: the
 * initiator slot always holds the token binder, the responder slot always holds
 * the bridge's real static. Assigning them from `role` means the phone passes the
 * same two values the bridge does and cannot get the orientation wrong.
 */
export function beginPairingHandshake(input: {
  /** `initiator` is the phone; `responder` is the bridge. */
  role: SealRole;
  sessionId: string;
  /** The bridge's real Ed25519 static — for the phone, the pinned `bk` from the QR. */
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
 * That is always the phone: it holds the bridge's pinned static key, so the
 * bridge's signature is verified in full by the ordinary {@link completeHandshake}
 * path. There is deliberately no bridge-side variant here — the phone never needs
 * to defer a proof, so the RN core has exactly one handshake completion path and
 * no branch that skips signature verification.
 */
export function completePairingHandshakeAsPhone(input: {
  handshake: SealHandshake;
  peerMessage: unknown;
}): CompleteResult {
  return completeHandshake(input.handshake, input.peerMessage);
}

/**
 * Compare two base64url-encoded keys for equality.
 *
 * Exposed for the pin check in the pairing flow, where a mismatch between the
 * pinned `bk` and the key a response was authenticated with is terminal.
 */
export function sealKeyEquals(a: string, b: string): boolean {
  const left = fromBase64Url(a);
  const right = fromBase64Url(b);
  if (left === undefined || right === undefined) return false;
  return bytesEqual(left, right);
}

/** Re-exported so callers do not need a second import for frame assembly. */
export { concatBytes };

/**
 * [OUR DESIGN] Ed25519 primitives for device identity.
 *
 * Uses Node's built-in `node:crypto` (Node ≥ 18 has Ed25519 and X25519), so the
 * bridge adds no cryptographic dependency. Everything here is fail-closed:
 * verification returns `false` on any malformed input rather than throwing, and
 * no function ever falls back to a weaker check.
 *
 * Wire encoding for keys is base64url of the **raw 32-byte** Ed25519 public key.
 * That is what a phone can produce with @noble/ed25519 or expo-crypto without a
 * DER encoder, so the raw form is the contract and this module handles the SPKI
 * wrapping Node requires internally.
 */

import {
  createHash,
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from 'node:crypto';

/** Base64url with no padding, the encoding used everywhere on our wire. */
export function toBase64Url(data: Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

/** Decode base64url, returning `undefined` rather than throwing on garbage. */
export function fromBase64Url(value: string): Buffer | undefined {
  // Buffer.from is famously lenient, so validate the alphabet ourselves first:
  // silently accepting a truncated key would weaken every check downstream.
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return undefined;
  try {
    const decoded = Buffer.from(value, 'base64url');
    // Round-trip guard against inputs that decode lossily.
    if (decoded.toString('base64url') !== value.replace(/=+$/, '')) return undefined;
    return decoded;
  } catch {
    return undefined;
  }
}

/** DER prefix for an Ed25519 SPKI public key: the 12 bytes before the raw key. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
/** DER prefix for an Ed25519 PKCS#8 private key. */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;

/** Wrap a raw 32-byte Ed25519 public key into a Node KeyObject. */
export function publicKeyFromRaw(raw: Uint8Array): KeyObject | undefined {
  if (raw.length !== ED25519_PUBLIC_KEY_BYTES) return undefined;
  try {
    return createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return undefined;
  }
}

/** Wrap a raw 32-byte Ed25519 seed into a Node private KeyObject. */
export function privateKeyFromRaw(raw: Uint8Array): KeyObject | undefined {
  if (raw.length !== 32) return undefined;
  try {
    return createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(raw)]),
      format: 'der',
      type: 'pkcs8',
    });
  } catch {
    return undefined;
  }
}

/** Raw 32-byte public key from a Node KeyObject. */
export function rawFromPublicKey(key: KeyObject): Buffer {
  const der = key.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - ED25519_PUBLIC_KEY_BYTES);
}

/**
 * Raw 32-byte Ed25519 seed from a Node private KeyObject.
 *
 * The PKCS#8 encoding of an Ed25519 private key is a fixed 48 bytes ending in the
 * 32-byte seed, so the tail is the seed. Used only when persisting the bridge's own
 * identity; a device's private key never reaches this process.
 */
export function rawFromPrivateKey(key: KeyObject): Buffer {
  const der = key.export({ type: 'pkcs8', format: 'der' });
  return der.subarray(der.length - 32);
}

export interface Ed25519KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  /** base64url raw public key, the wire form. */
  publicKeyB64: string;
}

/** Generate a fresh Ed25519 identity. */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicKeyB64: toBase64Url(rawFromPublicKey(publicKey)) };
}

/** Sign a message. Ed25519 needs no digest argument. */
export function signMessage(privateKey: KeyObject, message: Uint8Array): Buffer {
  return sign(null, Buffer.from(message), privateKey);
}

/**
 * Verify a signature. Returns `false` for every failure mode — wrong length,
 * unparsable key, bad signature — and never throws. A verification helper that
 * can throw invites a `catch` that accidentally means "allow".
 */
export function verifySignature(
  publicKeyRaw: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  const key = publicKeyFromRaw(publicKeyRaw);
  if (key === undefined) return false;
  try {
    return verify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

/** Verify against a base64url-encoded public key and signature. */
export function verifySignatureB64(publicKeyB64: string, message: Uint8Array, signatureB64: string): boolean {
  const key = fromBase64Url(publicKeyB64);
  const signature = fromBase64Url(signatureB64);
  if (key === undefined || signature === undefined) return false;
  return verifySignature(key, message, signature);
}

export function sha256(data: Uint8Array): Buffer {
  return createHash('sha256').update(Buffer.from(data)).digest();
}

/**
 * Device id: base64url of SHA-256 over the raw public key, truncated to 16
 * bytes. A hash rather than the key itself so logs and QR payloads carry a
 * stable short handle, and 128 bits is far beyond collision risk for the handful
 * of devices one workstation pairs.
 */
export function deviceIdFromPublicKey(publicKeyB64: string): string | undefined {
  const raw = fromBase64Url(publicKeyB64);
  if (raw === undefined || raw.length !== ED25519_PUBLIC_KEY_BYTES) return undefined;
  return toBase64Url(sha256(raw).subarray(0, 16));
}

/** Cryptographically random bytes. */
export function randomToken(bytes = 32): Buffer {
  return randomBytes(bytes);
}

/**
 * Constant-time comparison of two secrets. Length mismatch returns `false`
 * without consulting the contents, which is the one leak we accept (and which
 * `timingSafeEqual` would throw on).
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Constant-time comparison of two base64url strings. */
export function constantTimeEqualB64(a: string, b: string): boolean {
  const left = fromBase64Url(a);
  const right = fromBase64Url(b);
  if (left === undefined || right === undefined) return false;
  return constantTimeEqual(left, right);
}

/**
 * Domain-separated message builder. Every signature in this protocol commits to
 * a purpose string, so a signature harvested from one step can never be replayed
 * into another (a pairing proof must not be usable as an auth response).
 */
export function domainMessage(purpose: string, ...parts: string[]): Buffer {
  // Length-prefixed to make the encoding injective: "a" + "bc" must not collide
  // with "ab" + "c".
  const chunks: Buffer[] = [Buffer.from(`dshm/${purpose}`, 'utf8')];
  for (const part of parts) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    chunks.push(length, bytes);
  }
  return Buffer.concat(chunks);
}

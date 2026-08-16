/**
 * [OUR DESIGN] Pure crypto for the RN core.
 *
 * Node-free AND expo-free on purpose. `expo-secure-store` cannot even be imported
 * under Node, so anything that touches it would make this module untestable and
 * unusable from the cross-tree integration test. Key storage lives in
 * `src/m1/identity.ts`; everything here is a pure function over bytes.
 *
 * Every primitive is chosen to match `bridge/src/identity/crypto.ts` and
 * `bridge/src/relay/seal.ts` byte-for-byte:
 *
 *   | this module              | bridge equivalent            |
 *   |-------------------------|------------------------------|
 *   | `@noble/hashes` sha256   | `node:crypto` createHash     |
 *   | `@noble/hashes` hkdf     | `node:crypto` hkdfSync       |
 *   | `@noble/curves` ed25519  | `node:crypto` sign/verify    |
 *   | `@noble/curves` x25519   | `node:crypto` diffieHellman  |
 *   | `@noble/ciphers` gcm     | `node:crypto` aes-256-gcm    |
 *
 * `tests/m1-seal.test.ts` asserts that agreement against `node:crypto` directly, so
 * a dependency bump that changed any encoding would fail rather than silently
 * produce a phone that cannot pair.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { gcm } from '@noble/ciphers/aes';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes, fromBase64Url, toBase64Url, utf8 } from './bytes';

export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_PRIVATE_KEY_BYTES = 32;
export const X25519_PUBLIC_KEY_BYTES = 32;
export const SEAL_KEY_BYTES = 32;
export const GCM_NONCE_BYTES = 12;
export const GCM_TAG_BYTES = 16;

// ── randomness ──────────────────────────────────────────────────────────────

export type RandomSource = (length: number) => Uint8Array;

/**
 * WebCrypto if the platform has it, else nothing.
 *
 * Node ≥18 and every browser satisfy this, so tests and web builds need no setup.
 * React Native does NOT: Hermes has no `crypto.getRandomValues`. `identity.ts`
 * installs an `expo-crypto`-backed source at import time, which is why the app
 * always has one before any protocol code runs.
 */
function webCryptoRandom(length: number): Uint8Array {
  const source = (globalThis as { crypto?: { getRandomValues?: (array: Uint8Array) => Uint8Array } }).crypto;
  if (source?.getRandomValues === undefined) {
    // Refusing beats returning something predictable. A silent weak RNG here
    // would compromise every ephemeral and every routing id.
    throw new Error('no cryptographic random source is available; call setRandomSource() first');
  }
  const out = new Uint8Array(length);
  source.getRandomValues(out);
  return out;
}

let randomSource: RandomSource = webCryptoRandom;

/** Install a platform CSPRNG. Called by `identity.ts` for React Native. */
export function setRandomSource(source: RandomSource): void {
  randomSource = source;
}

/**
 * CSPRNG bytes.
 *
 * The previous implementation called `ed25519.utils.randomSecretKey().slice(...)`,
 * which is a keygen helper rather than a general RNG: it is defined to return
 * exactly 32 bytes, so it silently could not serve a longer request, and it ties
 * general randomness to a curve implementation detail.
 */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 1 || length > 1024) {
    throw new Error('randomBytes length must be an integer in 1..1024');
  }
  const bytes = randomSource(length);
  if (bytes.byteLength !== length) throw new Error('random source returned the wrong length');
  return bytes;
}

// ── hashing and domain separation ───────────────────────────────────────────

export { sha256 };

/**
 * Domain-separated, length-prefixed message framing.
 *
 * Must match `bridge/src/identity/crypto.ts#domainMessage` exactly: the literal
 * `dshm/<purpose>`, then each part as a 4-byte big-endian length followed by its
 * UTF-8 bytes. The length prefixes are what make the encoding injective, so
 * `('a','bc')` and `('ab','c')` cannot collide.
 */
export function domainMessage(purpose: string, ...parts: readonly string[]): Uint8Array {
  const chunks: Uint8Array[] = [utf8(`dshm/${purpose}`)];
  for (const part of parts) {
    const bytes = utf8(part);
    const length = new Uint8Array(4);
    // Explicit big-endian: DataView defaults to BE but saying so keeps this
    // readable next to the bridge's `writeUInt32BE`.
    new DataView(length.buffer).setUint32(0, bytes.byteLength, false);
    chunks.push(length, bytes);
  }
  return concatBytes(...chunks);
}

/** HKDF-SHA256. Argument order mirrors `hkdfSync('sha256', ikm, salt, info, len)`. */
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

/** base64url of the first 16 bytes of SHA-256 over the raw public key. */
export function deviceIdFromPublicKey(publicKeyB64: string): string | undefined {
  const raw = fromBase64Url(publicKeyB64);
  if (raw === undefined || raw.byteLength !== ED25519_PUBLIC_KEY_BYTES) return undefined;
  return toBase64Url(sha256(raw).subarray(0, 16));
}

// ── Ed25519 ─────────────────────────────────────────────────────────────────

export type DeviceIdentity = {
  /** base64url raw 32-byte Ed25519 public key. */
  publicKey: string;
  /** Raw 32-byte Ed25519 seed. Never leaves the device. */
  privateKey: Uint8Array;
  /** Derived from `publicKey`; not a secret. */
  deviceId: string;
};

export function ed25519PublicKeyFromSeed(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

export function signBytes(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/**
 * Verify an Ed25519 signature. Fails closed.
 *
 * `@noble` THROWS on a wrong-length key or signature rather than returning false,
 * so every call must be wrapped: an exception escaping here would unwind a socket
 * handler on attacker-chosen input, which is exactly the shape of bug the bridge's
 * own crypto module avoids by returning results.
 *
 * `zip215: false` selects strict RFC 8032 verification, matching what
 * `node:crypto`'s `verify` accepts, so the two trees agree on edge-case signatures
 * as well as valid ones.
 */
export function verifyBytes(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (signature.byteLength !== 64) return false;
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/** Verify with base64url inputs. Any malformed field is a refusal, not a throw. */
export function verifySignatureB64(publicKeyB64: string, message: Uint8Array, signatureB64: string): boolean {
  const publicKey = fromBase64Url(publicKeyB64);
  const signature = fromBase64Url(signatureB64);
  if (publicKey === undefined || signature === undefined) return false;
  return verifyBytes(publicKey, message, signature);
}

/** Sign `domainMessage(purpose, ...parts)` with the device key. */
export function signDomain(identity: DeviceIdentity, purpose: string, ...parts: readonly string[]): string {
  return toBase64Url(signBytes(domainMessage(purpose, ...parts), identity.privateKey));
}

/** Whether a base64url string is a well-formed raw Ed25519 public key. */
export function isValidEd25519PublicKey(value: string): boolean {
  const raw = fromBase64Url(value);
  if (raw === undefined || raw.byteLength !== ED25519_PUBLIC_KEY_BYTES) return false;
  try {
    // Rejects a non-canonical or off-curve encoding, so a corrupt pin is caught
    // when it is stored rather than when a handshake mysteriously fails.
    return ed25519.utils.isValidPublicKey(raw);
  } catch {
    return false;
  }
}

// ── X25519 ──────────────────────────────────────────────────────────────────

export type X25519KeyPair = { privateKey: Uint8Array; publicKey: Uint8Array };

/**
 * Fresh X25519 ephemeral.
 *
 * The secret comes from our own `randomBytes` rather than `x25519.utils`, so the
 * whole core has exactly one entropy source — the one the app installs — instead of
 * also depending on whatever global `@noble` happens to find.
 */
export function generateX25519KeyPair(): X25519KeyPair {
  const privateKey = randomBytes(32);
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

/**
 * X25519 shared secret, or `undefined` for a point the curve refuses.
 *
 * `@noble` throws on a low-order or all-zero peer point, matching node's
 * `diffieHellman`, which errors in the same cases. Both are caught here so the
 * caller sees one refusal shape.
 */
export function x25519SharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array | undefined {
  if (peerPublicKey.byteLength !== X25519_PUBLIC_KEY_BYTES) return undefined;
  try {
    const shared = x25519.getSharedSecret(privateKey, peerPublicKey);
    // Contributory-behaviour failure. Refuse rather than deriving keys that an
    // attacker who forced the zero point also knows.
    let allZero = true;
    for (const byte of shared) if (byte !== 0) { allZero = false; break; }
    return allZero ? undefined : shared;
  } catch {
    return undefined;
  }
}

// ── AES-256-GCM ─────────────────────────────────────────────────────────────

/** Ciphertext with the 16-byte tag appended, matching the bridge's layout. */
export function aesGcmSeal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return gcm(key, nonce, aad).encrypt(plaintext);
}

/** Open ciphertext||tag. `undefined` on tag mismatch — never a throw. */
export function aesGcmOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array | undefined {
  if (sealed.byteLength < GCM_TAG_BYTES) return undefined;
  try {
    return gcm(key, nonce, aad).decrypt(sealed);
  } catch {
    return undefined;
  }
}

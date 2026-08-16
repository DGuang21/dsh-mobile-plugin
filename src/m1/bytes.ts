/**
 * [OUR DESIGN] Byte and base64url primitives for the RN core.
 *
 * Deliberately dependency-free: no `Buffer`, no `atob`/`btoa`, no `expo-*`. Hermes
 * does not ship `Buffer`, and the global base64 helpers differ subtly between
 * Hermes, Node and browsers — a hand-rolled codec is a few lines and removes the
 * question entirely. These functions must agree byte-for-byte with
 * `bridge/src/identity/crypto.ts`, which uses Node's `base64url`, because every
 * signature and every HKDF salt in this protocol is computed over their output.
 *
 * `tests/m1-seal.test.ts` cross-checks the codec against Node's own `Buffer`.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Reverse lookup, built once. `-1` marks a character outside the alphabet. */
const DECODE: readonly number[] = (() => {
  const table = new Array<number>(128).fill(-1);
  for (let index = 0; index < ALPHABET.length; index += 1) {
    table[ALPHABET.charCodeAt(index)] = index;
  }
  return table;
})();

export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  let index = 0;
  // Three input bytes become four output characters; the tail is handled below.
  for (; index + 2 < bytes.length; index += 3) {
    const word = (bytes[index]! << 16) | (bytes[index + 1]! << 8) | bytes[index + 2]!;
    out += ALPHABET[(word >>> 18) & 63]! + ALPHABET[(word >>> 12) & 63]! + ALPHABET[(word >>> 6) & 63]! + ALPHABET[word & 63]!;
  }
  const remaining = bytes.length - index;
  if (remaining === 1) {
    const word = bytes[index]! << 16;
    out += ALPHABET[(word >>> 18) & 63]! + ALPHABET[(word >>> 12) & 63]!;
  } else if (remaining === 2) {
    const word = (bytes[index]! << 16) | (bytes[index + 1]! << 8);
    out += ALPHABET[(word >>> 18) & 63]! + ALPHABET[(word >>> 12) & 63]! + ALPHABET[(word >>> 6) & 63]!;
  }
  return out;
}

/**
 * Decode base64url, unpadded, **canonical only**.
 *
 * Returns `undefined` rather than throwing, and rejects anything a canonical
 * encoder would never emit: padding characters, a length ≡ 1 (mod 4), and a final
 * character whose low bits are not zero. Node's `fromBase64Url` in the bridge
 * round-trips to enforce the same thing; rejecting non-canonical input matters
 * because two spellings of one key would be two different pins.
 */
export function fromBase64Url(value: string): Uint8Array | undefined {
  const length = value.length;
  if (length % 4 === 1) return undefined;
  const bytesOut = ((length * 3) / 4) | 0;
  const out = new Uint8Array(bytesOut);
  let accumulator = 0;
  let bits = 0;
  let written = 0;
  for (let index = 0; index < length; index += 1) {
    const code = value.charCodeAt(index);
    const digit = code < 128 ? DECODE[code]! : -1;
    if (digit < 0) return undefined;
    accumulator = (accumulator << 6) | digit;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written] = (accumulator >>> bits) & 0xff;
      written += 1;
    }
  }
  // Leftover bits belong to no byte and must therefore be zero in a canonical
  // encoding. `a` and `b` would otherwise both decode to the same single byte.
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) return undefined;
  return written === bytesOut ? out : out.subarray(0, written);
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

/**
 * Constant-time comparison for equal-length byte strings.
 *
 * Used on pinned-key comparisons. The early length exit is intentional and safe:
 * key lengths are public.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let index = 0; index < a.byteLength; index += 1) diff |= a[index]! ^ b[index]!;
  return diff === 0;
}

/** Constant-time comparison of two base64url strings, by decoded bytes. */
export function base64UrlEqual(a: string, b: string): boolean {
  const left = fromBase64Url(a);
  const right = fromBase64Url(b);
  if (left === undefined || right === undefined) return false;
  return bytesEqual(left, right);
}

/** Overwrite a buffer in place. Best effort — JS gives no guarantee of no copies. */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}

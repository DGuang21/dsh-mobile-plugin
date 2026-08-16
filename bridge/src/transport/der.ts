/**
 * Minimal DER (ASN.1 Distinguished Encoding Rules) writer.
 *
 * Exists because Node's `crypto` can generate keys but cannot issue an X.509
 * certificate, and Mode A needs a self-signed cert at first run. The
 * alternatives were shelling out to `openssl` (absent on Windows, and a silent
 * dependency on whatever version is installed) or pulling in a certificate
 * library. DER is a fully specified encoding and the subset a leaf certificate
 * needs is small, so it is written here where it can be read and tested.
 *
 * Write-only, on purpose. Nothing in this bridge parses attacker-supplied ASN.1,
 * which is where the interesting DER vulnerabilities live.
 */

/** DER identifier octets used by X.509. */
export const TAG = {
  boolean: 0x01,
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  null: 0x05,
  oid: 0x06,
  utf8String: 0x0c,
  sequence: 0x30,
  set: 0x31,
  printableString: 0x13,
  ia5String: 0x16,
  utcTime: 0x17,
  generalizedTime: 0x18,
} as const;

/** Definite-form length octets (X.690 §8.1.3). */
export function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Tag-length-value. */
export function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.byteLength), content]);
}

/**
 * INTEGER from a big-endian magnitude.
 *
 * DER integers are signed, so a leading byte ≥ 0x80 needs a zero pad or it would
 * decode as negative. This is exactly the bug that produces "negative serial
 * number" warnings in real certificates.
 */
export function derInteger(value: Buffer | number): Buffer {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) throw new Error('derInteger expects a non-negative integer');
    if (value === 0) return tlv(TAG.integer, Buffer.from([0]));
    const bytes: number[] = [];
    let remaining = value;
    while (remaining > 0) {
      bytes.unshift(remaining & 0xff);
      remaining = Math.floor(remaining / 256);
    }
    if ((bytes[0] as number) & 0x80) bytes.unshift(0);
    return tlv(TAG.integer, Buffer.from(bytes));
  }
  let content = value;
  // Strip redundant leading zeros (DER requires the minimal encoding).
  let start = 0;
  while (start + 1 < content.byteLength && content[start] === 0 && ((content[start + 1] as number) & 0x80) === 0) {
    start += 1;
  }
  content = content.subarray(start);
  if (content.byteLength === 0) return tlv(TAG.integer, Buffer.from([0]));
  if ((content[0] as number) & 0x80) content = Buffer.concat([Buffer.from([0]), content]);
  return tlv(TAG.integer, content);
}

/** BIT STRING wrapping whole bytes (unused-bits = 0). */
export function derBitString(content: Buffer, unusedBits = 0): Buffer {
  return tlv(TAG.bitString, Buffer.concat([Buffer.from([unusedBits]), content]));
}

export function derOctetString(content: Buffer): Buffer {
  return tlv(TAG.octetString, content);
}

export function derNull(): Buffer {
  return tlv(TAG.null, Buffer.alloc(0));
}

export function derBoolean(value: boolean): Buffer {
  // DER mandates 0xFF for true, not merely non-zero.
  return tlv(TAG.boolean, Buffer.from([value ? 0xff : 0x00]));
}

/**
 * OBJECT IDENTIFIER from dotted notation.
 *
 * The first two arcs are packed into one byte as `40*a + b`; the rest are
 * base-128 varints with the continuation bit set on all but the last octet.
 */
export function derOid(dotted: string): Buffer {
  const arcs = dotted.split('.').map((part) => {
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0) throw new Error(`invalid OID arc: ${part}`);
    return value;
  });
  if (arcs.length < 2) throw new Error('OID needs at least two arcs');
  const first = arcs[0] as number;
  const second = arcs[1] as number;
  if (first > 2) throw new Error('first OID arc must be 0, 1 or 2');
  const bytes: number[] = [first * 40 + second];
  for (const arc of arcs.slice(2)) {
    const chunks: number[] = [arc & 0x7f];
    let remaining = Math.floor(arc / 128);
    while (remaining > 0) {
      chunks.unshift((remaining & 0x7f) | 0x80);
      remaining = Math.floor(remaining / 128);
    }
    bytes.push(...chunks);
  }
  return tlv(TAG.oid, Buffer.from(bytes));
}

export function derSequence(...parts: Buffer[]): Buffer {
  return tlv(TAG.sequence, Buffer.concat(parts));
}

export function derSet(...parts: Buffer[]): Buffer {
  return tlv(TAG.set, Buffer.concat(parts));
}

/** Context-specific constructed tag, e.g. `[0] EXPLICIT`. */
export function derExplicit(tagNumber: number, content: Buffer): Buffer {
  return tlv(0xa0 | tagNumber, content);
}

/** Context-specific primitive tag, used by GeneralName alternatives. */
export function derContextPrimitive(tagNumber: number, content: Buffer): Buffer {
  return tlv(0x80 | tagNumber, content);
}

export function derUtf8String(value: string): Buffer {
  return tlv(TAG.utf8String, Buffer.from(value, 'utf8'));
}

export function derPrintableString(value: string): Buffer {
  return tlv(TAG.printableString, Buffer.from(value, 'ascii'));
}

/**
 * Time, choosing the representation X.509 requires.
 *
 * UTCTime for years 1950–2049, GeneralizedTime outside that range. Getting this
 * wrong produces a certificate that some stacks read as expired in 1926.
 */
export function derTime(date: Date): Buffer {
  const year = date.getUTCFullYear();
  const pad = (value: number, width = 2): string => String(value).padStart(width, '0');
  const month = pad(date.getUTCMonth() + 1);
  const day = pad(date.getUTCDate());
  const hour = pad(date.getUTCHours());
  const minute = pad(date.getUTCMinutes());
  const second = pad(date.getUTCSeconds());
  if (year >= 1950 && year <= 2049) {
    const shortYear = pad(year % 100);
    return tlv(TAG.utcTime, Buffer.from(`${shortYear}${month}${day}${hour}${minute}${second}Z`, 'ascii'));
  }
  return tlv(TAG.generalizedTime, Buffer.from(`${pad(year, 4)}${month}${day}${hour}${minute}${second}Z`, 'ascii'));
}

/** PEM-wrap DER at 64 characters per line. */
export function toPem(der: Buffer, label: string): string {
  const body = der.toString('base64');
  const lines: string[] = [];
  for (let index = 0; index < body.length; index += 64) lines.push(body.slice(index, index + 64));
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

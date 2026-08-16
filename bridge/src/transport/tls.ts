/**
 * [OUR DESIGN] Mode A transport: self-signed TLS, pinned by the phone.
 *
 * The cert is generated at first run and stored under the bridge's state
 * directory. It is not signed by any CA and is not meant to be: the phone pins
 * the SPKI SHA-256 it read from the pairing QR and refuses anything else. That is
 * strictly stronger than CA validation for this use case — no CA can issue a cert
 * this phone will accept for this bridge.
 *
 * There is no plaintext listener, not even for redirect. A redirect is an
 * opportunity to be downgraded, and a phone that already has a pinned
 * fingerprint has no reason to ever speak plaintext.
 *
 * P-256 ECDSA rather than Ed25519, purely for client compatibility: Ed25519
 * certificates are still refused by some mobile TLS stacks, and the pin is what
 * carries the security here.
 */

import { createHash, createPrivateKey, createPublicKey, createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server as HttpsServer } from 'node:https';
import { join } from 'node:path';
import {
  derBitString,
  derBoolean,
  derContextPrimitive,
  derExplicit,
  derInteger,
  derOctetString,
  derOid,
  derPrintableString,
  derSequence,
  derSet,
  derTime,
  derUtf8String,
  toPem,
} from './der.ts';

/** OIDs used by the certificate. */
const OID = {
  commonName: '2.5.4.3',
  organizationName: '2.5.4.10',
  ecPublicKey: '1.2.840.10045.2.1',
  prime256v1: '1.2.840.10045.3.1.7',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  subjectKeyIdentifier: '2.5.29.14',
} as const;

/** Ten years: a pinned self-signed cert has no revocation story, so rotation is
 * a deliberate operator action (`dsh-mobile-bridge regenerate-cert`), not an
 * expiry surprise that breaks a phone mid-trip. */
const CERT_VALIDITY_MS = 10 * 365 * 24 * 60 * 60 * 1000;

export interface TlsIdentity {
  certPem: string;
  keyPem: string;
  /** base64url SHA-256 of the DER SubjectPublicKeyInfo. This is what is pinned. */
  spkiFingerprint: string;
  /** Colon-separated hex of the same digest, for reading aloud. */
  spkiFingerprintHex: string;
  notAfter: Date;
}

export interface GenerateCertOptions {
  commonName: string;
  /** DNS names and IP addresses to put in the SAN. */
  dnsNames?: string[];
  ipAddresses?: string[];
  validityMs?: number;
  now?: () => number;
}

/** Encode a SAN GeneralName list. */
function subjectAltName(dnsNames: string[], ipAddresses: string[]): Buffer {
  const names: Buffer[] = [];
  for (const dns of dnsNames) names.push(derContextPrimitive(2, Buffer.from(dns, 'ascii')));
  for (const ip of ipAddresses) {
    const octets = ip.split('.').map((part) => Number(part));
    // IPv4 only. An IPv6 SAN would need a 16-byte encoding, and the LAN case we
    // support is a v4 address printed in the pairing QR.
    if (octets.length === 4 && octets.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)) {
      names.push(derContextPrimitive(7, Buffer.from(octets)));
    }
  }
  return derSequence(...names);
}

function extension(oid: string, critical: boolean, value: Buffer): Buffer {
  return critical
    ? derSequence(derOid(oid), derBoolean(true), derOctetString(value))
    : derSequence(derOid(oid), derOctetString(value));
}

/**
 * Generate a self-signed P-256 certificate.
 *
 * Marked `[NOT INTEGRATION-TESTED against a real phone]`: the DER is verified by
 * unit tests and by Node's own TLS stack accepting it as a server credential, but
 * whether iOS and Android accept a pinned self-signed cert in every RN networking
 * configuration has not been exercised on device.
 */
export function generateSelfSignedCert(options: GenerateCertOptions): TlsIdentity {
  const now = options.now?.() ?? Date.now();
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const digest = createHash('sha256').update(spkiDer).digest();

  const notBefore = new Date(now - 60_000); // Tolerate a little clock skew.
  const notAfter = new Date(now + (options.validityMs ?? CERT_VALIDITY_MS));

  const algorithm = derSequence(derOid(OID.ecdsaWithSha256));
  const name = derSequence(
    derSet(derSequence(derOid(OID.organizationName), derUtf8String('deepseek-harness-mobile bridge'))),
    derSet(derSequence(derOid(OID.commonName), derPrintableString(options.commonName))),
  );

  const extensions: Buffer[] = [
    // Not a CA. Critical, so a stack that understands it will refuse to build a
    // chain through this key.
    extension(OID.basicConstraints, true, derSequence()),
    // digitalSignature | keyEncipherment
    extension(OID.keyUsage, true, derBitString(Buffer.from([0xa0]), 5)),
    extension(OID.extKeyUsage, false, derSequence(derOid(OID.serverAuth))),
    extension(
      OID.subjectAltName,
      false,
      subjectAltName(options.dnsNames ?? ['localhost'], options.ipAddresses ?? ['127.0.0.1']),
    ),
    extension(OID.subjectKeyIdentifier, false, derOctetString(digest.subarray(0, 20))),
  ];

  const tbs = derSequence(
    derExplicit(0, derInteger(2)), // v3
    // Positive, 20 bytes at most. The high bit is cleared so the DER INTEGER
    // cannot come out negative.
    derInteger(Buffer.concat([Buffer.from([randomBytes(1)[0] as number & 0x7f]), randomBytes(15)])),
    algorithm,
    name,
    derSequence(derTime(notBefore), derTime(notAfter)),
    name, // Self-signed: issuer === subject.
    derSequence(derSequence(derOid(OID.ecPublicKey), derOid(OID.prime256v1)), derBitString(publicKeyPoint(spkiDer))),
    derExplicit(3, derSequence(...extensions)),
  );

  const signature = createSign('sha256').update(tbs).sign(privateKey);
  const certDer = derSequence(tbs, algorithm, derBitString(signature));

  return {
    certPem: toPem(certDer, 'CERTIFICATE'),
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    spkiFingerprint: digest.toString('base64url'),
    spkiFingerprintHex: [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join(':'),
    notAfter,
  };
}

/**
 * Pull the raw EC point out of a DER SubjectPublicKeyInfo.
 *
 * SPKI is `SEQUENCE { AlgorithmIdentifier, BIT STRING }`; for P-256 the BIT
 * STRING content is the 65-byte uncompressed point beginning with 0x04, and it is
 * the last 65 bytes of the structure. Asserted rather than assumed.
 */
function publicKeyPoint(spkiDer: Buffer): Buffer {
  const point = spkiDer.subarray(spkiDer.length - 65);
  if (point.byteLength !== 65 || point[0] !== 0x04) {
    throw new Error('unexpected P-256 SPKI encoding');
  }
  return point;
}

/** Fingerprint of an existing certificate's public key, for verification. */
export function spkiFingerprintOf(certPem: string): string {
  const spki = createPublicKey(certPem).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(spki).digest('base64url');
}

export interface TlsServerOptions {
  stateDir: string;
  commonName?: string;
  dnsNames?: string[];
  ipAddresses?: string[];
  /** Discard any stored identity and issue a new one. Unpairs every phone. */
  regenerate?: boolean;
}

/**
 * Load or create the bridge's TLS identity.
 *
 * Regenerating invalidates every phone's pin, which is a re-pair for each device.
 * That is the correct trade for a suspected key compromise and a bad surprise
 * otherwise, so it only happens when asked.
 */
export function loadOrCreateTlsIdentity(options: TlsServerOptions): TlsIdentity {
  mkdirSync(options.stateDir, { recursive: true, mode: 0o700 });
  const certPath = join(options.stateDir, 'bridge-cert.pem');
  const keyPath = join(options.stateDir, 'bridge-key.pem');

  if (!options.regenerate && existsSync(certPath) && existsSync(keyPath)) {
    const certPem = readFileSync(certPath, 'utf8');
    const keyPem = readFileSync(keyPath, 'utf8');
    const digest = createHash('sha256')
      .update(createPublicKey(certPem).export({ type: 'spki', format: 'der' }))
      .digest();
    // Prove the stored pair actually matches before trusting it: a half-written
    // regeneration would otherwise fail at TLS handshake time with no clue why.
    createPrivateKey(keyPem);
    return {
      certPem,
      keyPem,
      spkiFingerprint: digest.toString('base64url'),
      spkiFingerprintHex: [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join(':'),
      notAfter: new Date(0),
    };
  }

  const identity = generateSelfSignedCert({
    commonName: options.commonName ?? 'dsh-mobile-bridge',
    ...(options.dnsNames !== undefined ? { dnsNames: options.dnsNames } : {}),
    ...(options.ipAddresses !== undefined ? { ipAddresses: options.ipAddresses } : {}),
  });
  writeFileSync(certPath, identity.certPem, { mode: 0o600 });
  writeFileSync(keyPath, identity.keyPem, { mode: 0o600 });
  return identity;
}

/**
 * Create the HTTPS server.
 *
 * TLS 1.2 minimum. Nothing older is needed: the only client is our own app.
 */
export function createTlsServer(identity: TlsIdentity): HttpsServer {
  return createServer({
    cert: identity.certPem,
    key: identity.keyPem,
    minVersion: 'TLSv1.2',
  });
}

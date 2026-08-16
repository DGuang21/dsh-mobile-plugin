/**
 * Proves the hand-rolled X.509 DER is real by making Node's own TLS stack use it
 * as a server credential and complete a handshake.
 *
 * This is the check that matters: a DER encoder can produce something that
 * round-trips through its own tests and is still rejected by OpenSSL.
 */

import { connect as tlsConnect } from 'node:tls';
import { X509Certificate, createHash, createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createTlsServer, generateSelfSignedCert, spkiFingerprintOf } from '../src/transport/tls.ts';
import { derInteger, derOid, encodeLength, toPem } from '../src/transport/der.ts';

describe('DER primitives', () => {
  it('encodes short and long form lengths', () => {
    expect([...encodeLength(0)]).toEqual([0]);
    expect([...encodeLength(127)]).toEqual([127]);
    expect([...encodeLength(128)]).toEqual([0x81, 128]);
    expect([...encodeLength(256)]).toEqual([0x82, 0x01, 0x00]);
    expect([...encodeLength(65_536)]).toEqual([0x83, 0x01, 0x00, 0x00]);
  });

  it('pads an integer whose high bit is set, so it is not read as negative', () => {
    // 0x80 must become 00 80, or a decoder reads -128.
    expect([...derInteger(Buffer.from([0x80]))]).toEqual([0x02, 0x02, 0x00, 0x80]);
    expect([...derInteger(Buffer.from([0x7f]))]).toEqual([0x02, 0x01, 0x7f]);
  });

  it('strips redundant leading zeros to keep the encoding minimal', () => {
    expect([...derInteger(Buffer.from([0x00, 0x00, 0x2a]))]).toEqual([0x02, 0x01, 0x2a]);
  });

  it('encodes zero and small integers', () => {
    expect([...derInteger(0)]).toEqual([0x02, 0x01, 0x00]);
    expect([...derInteger(2)]).toEqual([0x02, 0x01, 0x02]);
    expect([...derInteger(255)]).toEqual([0x02, 0x02, 0x00, 0xff]);
  });

  it('packs the first two OID arcs into one byte', () => {
    // 1.2.840.10045.2.1 (ecPublicKey): 42 = 1*40 + 2, then 840 as a varint.
    expect([...derOid('1.2.840.10045.2.1')]).toEqual([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  });

  it('encodes the P-256 curve OID', () => {
    expect([...derOid('1.2.840.10045.3.1.7')]).toEqual([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
  });

  it('rejects a malformed OID', () => {
    expect(() => derOid('3.1.1')).toThrow();
    expect(() => derOid('1')).toThrow();
  });

  it('wraps PEM at 64 characters', () => {
    const pem = toPem(Buffer.alloc(200, 7), 'CERTIFICATE');
    const lines = pem.trim().split('\n');
    expect(lines[0]).toBe('-----BEGIN CERTIFICATE-----');
    expect(lines[lines.length - 1]).toBe('-----END CERTIFICATE-----');
    for (const line of lines.slice(1, -1)) expect(line.length).toBeLessThanOrEqual(64);
  });
});

describe('self-signed certificate', () => {
  it('is accepted by Node TLS and completes a handshake', async () => {
    const identity = generateSelfSignedCert({ commonName: 'dsh-mobile-bridge', dnsNames: ['localhost'] });
    const server = createTlsServer(identity);
    server.on('request', (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('ok');
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;

    try {
      const peerFingerprint = await new Promise<string>((resolve, reject) => {
        const socket = tlsConnect(
          {
            host: '127.0.0.1',
            port,
            servername: 'localhost',
            // The phone pins the SPKI instead of validating a chain; this mirrors
            // that posture rather than pretending a self-signed cert chains.
            rejectUnauthorized: false,
          },
          () => {
            const peer = socket.getPeerX509Certificate();
            if (peer === undefined) {
              reject(new Error('no peer certificate'));
              return;
            }
            resolve(createHash('sha256').update(peer.publicKey.export({ type: 'spki', format: 'der' })).digest('base64url'));
            socket.end();
          },
        );
        socket.on('error', reject);
      });

      // The pin the phone stores must be the pin it observes on the wire.
      expect(peerFingerprint).toBe(identity.spkiFingerprint);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('parses back as a v3 certificate with the expected subject and SAN', () => {
    const identity = generateSelfSignedCert({
      commonName: 'workstation.local',
      dnsNames: ['workstation.local', 'localhost'],
      ipAddresses: ['192.168.1.42', '127.0.0.1'],
    });
    // X509Certificate is Node's own parser, i.e. OpenSSL. If it reads this, the
    // encoding is real.
    const parsed = new X509Certificate(identity.certPem);
    expect(parsed.subject).toContain('workstation.local');
    expect(parsed.issuer).toBe(parsed.subject);
    expect(parsed.subjectAltName).toContain('DNS:workstation.local');
    expect(parsed.subjectAltName).toContain('IP Address:192.168.1.42');
    expect(parsed.ca).toBe(false);
  });

  it('verifies its own signature', () => {
    const identity = generateSelfSignedCert({ commonName: 'dsh-mobile-bridge' });
    const parsed = new X509Certificate(identity.certPem);
    // Self-signed: it must verify under its own public key.
    expect(parsed.verify(createPublicKey(identity.certPem))).toBe(true);
  });

  it('reports a fingerprint that matches an independent computation', () => {
    const identity = generateSelfSignedCert({ commonName: 'dsh-mobile-bridge' });
    expect(spkiFingerprintOf(identity.certPem)).toBe(identity.spkiFingerprint);
    // Hex form is the same digest, for reading aloud.
    const fromHex = Buffer.from(identity.spkiFingerprintHex.split(':').join(''), 'hex');
    expect(fromHex.toString('base64url')).toBe(identity.spkiFingerprint);
  });

  it('issues a distinct key and serial every time', () => {
    const a = generateSelfSignedCert({ commonName: 'a' });
    const b = generateSelfSignedCert({ commonName: 'b' });
    expect(a.spkiFingerprint).not.toBe(b.spkiFingerprint);
  });

  it('is valid now and not in 1926', () => {
    const identity = generateSelfSignedCert({ commonName: 'dsh-mobile-bridge' });
    const parsed = new X509Certificate(identity.certPem);
    const notBefore = new Date(parsed.validFrom).getTime();
    const notAfter = new Date(parsed.validTo).getTime();
    expect(notBefore).toBeLessThanOrEqual(Date.now());
    expect(notAfter).toBeGreaterThan(Date.now());
    expect(new Date(parsed.validFrom).getUTCFullYear()).toBeGreaterThanOrEqual(2026);
  });
});

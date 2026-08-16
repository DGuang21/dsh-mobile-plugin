import { describe, expect, it } from 'vitest';
import {
  ACCESS_TOKEN_TTL_MS,
  AUTH_NONCE_TTL_MS,
  AuthService,
  authProofMessage,
  bearerFromHeader,
  tokenFromSubprotocols,
} from '../src/auth/tokens.ts';
import { generateEd25519KeyPair, signMessage, toBase64Url } from '../src/identity/crypto.ts';
import { pairingProofMessage } from '../src/identity/pairing.ts';
import { DeviceRegistry } from '../src/identity/registry.ts';

const BRIDGE_ID = 'bridge-abc123';

function setup(options: { now?: () => number } = {}) {
  const registry = DeviceRegistry.inMemory();
  const keys = generateEd25519KeyPair();
  const record = registry.register({ publicKey: keys.publicKeyB64, label: 'Pixel 8' });
  const auth = new AuthService({ registry, bridgeId: BRIDGE_ID, now: options.now });

  const sign = (nonce: string, deviceId = record.deviceId, bridgeId = BRIDGE_ID) =>
    toBase64Url(signMessage(keys.privateKey, authProofMessage(nonce, deviceId, bridgeId)));

  /** Complete a full challenge-response and return the token. */
  const login = () => {
    const challenge = auth.challenge(record.deviceId);
    if (!challenge.ok) throw new Error(`challenge failed: ${challenge.reason}`);
    const result = auth.authenticate({
      deviceId: record.deviceId,
      nonce: challenge.nonce,
      signature: sign(challenge.nonce),
    });
    if (!result.ok) throw new Error(`auth failed: ${result.reason}`);
    return result;
  };

  return { registry, auth, keys, record, sign, login };
}

describe('challenge-response', () => {
  it('issues a token for a correctly signed nonce', () => {
    const { auth, record, sign } = setup();
    const challenge = auth.challenge(record.deviceId);
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;

    const result = auth.authenticate({
      deviceId: record.deviceId,
      nonce: challenge.nonce,
      signature: sign(challenge.nonce),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.deviceId).toBe(record.deviceId);
      expect(auth.verify(result.token)).toEqual({
        ok: true,
        deviceId: record.deviceId,
        expiresAt: result.expiresAt,
      });
    }
  });

  it('refuses a nonce to an unknown device, so challenges cannot be farmed', () => {
    const { auth } = setup();
    expect(auth.challenge('not-a-device')).toEqual({ ok: false, reason: 'unknown-device' });
  });

  it('rejects a bad signature', () => {
    const { auth, record } = setup();
    const other = generateEd25519KeyPair();
    const challenge = auth.challenge(record.deviceId);
    if (!challenge.ok) return;

    const wrongKey = toBase64Url(
      signMessage(other.privateKey, authProofMessage(challenge.nonce, record.deviceId, BRIDGE_ID)),
    );
    expect(auth.authenticate({ deviceId: record.deviceId, nonce: challenge.nonce, signature: wrongKey })).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('consumes the nonce even on failure, so there is exactly one attempt', () => {
    const { auth, record, sign } = setup();
    const challenge = auth.challenge(record.deviceId);
    if (!challenge.ok) return;

    auth.authenticate({ deviceId: record.deviceId, nonce: challenge.nonce, signature: 'AAAA' });
    // The correct signature now fails, because the nonce is gone.
    expect(
      auth.authenticate({ deviceId: record.deviceId, nonce: challenge.nonce, signature: sign(challenge.nonce) }),
    ).toEqual({ ok: false, reason: 'nonce-unknown' });
  });

  it('rejects a replayed challenge-response pair', () => {
    const { auth, record, sign } = setup();
    const challenge = auth.challenge(record.deviceId);
    if (!challenge.ok) return;

    const signature = sign(challenge.nonce);
    expect(auth.authenticate({ deviceId: record.deviceId, nonce: challenge.nonce, signature }).ok).toBe(true);
    // Captured and replayed verbatim.
    expect(auth.authenticate({ deviceId: record.deviceId, nonce: challenge.nonce, signature })).toEqual({
      ok: false,
      reason: 'nonce-unknown',
    });
  });

  it('expires a nonce', () => {
    let now = 1_000;
    const { auth, record, sign } = setup({ now: () => now });
    const challenge = auth.challenge(record.deviceId);
    if (!challenge.ok) return;

    now += AUTH_NONCE_TTL_MS + 1;
    expect(
      auth.authenticate({ deviceId: record.deviceId, nonce: challenge.nonce, signature: sign(challenge.nonce) }),
    ).toEqual({ ok: false, reason: 'nonce-expired' });
  });

  it('will not let one device redeem another device nonce', () => {
    const { auth, registry, record, sign } = setup();
    const otherKeys = generateEd25519KeyPair();
    const other = registry.register({ publicKey: otherKeys.publicKeyB64, label: 'iPad' });

    const challenge = auth.challenge(record.deviceId);
    if (!challenge.ok) return;

    // Signed correctly by the other device, but the nonce was not issued to it.
    const signature = toBase64Url(
      signMessage(otherKeys.privateKey, authProofMessage(challenge.nonce, other.deviceId, BRIDGE_ID)),
    );
    expect(auth.authenticate({ deviceId: other.deviceId, nonce: challenge.nonce, signature })).toEqual({
      ok: false,
      reason: 'nonce-unknown',
    });
    void sign;
  });

  it('domain-separates auth proofs from pairing proofs', () => {
    // A signature over the pairing message must never satisfy auth.
    expect(authProofMessage('n', 'd', 'b').equals(pairingProofMessage('n', 'b'))).toBe(false);
  });
});

describe('access tokens', () => {
  it('expires after 15 minutes', () => {
    let now = 1_000;
    const { auth, login } = setup({ now: () => now });
    const session = login();

    now += ACCESS_TOKEN_TTL_MS - 1;
    expect(auth.verify(session.token).ok).toBe(true);

    now += 2;
    expect(auth.verify(session.token)).toEqual({ ok: false, reason: 'expired' });
    expect(ACCESS_TOKEN_TTL_MS).toBe(15 * 60_000);
  });

  it('rotates, invalidating the previous token', () => {
    const { auth, login } = setup();
    const session = login();

    const rotated = auth.rotate(session.token);
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;

    expect(rotated.token).not.toBe(session.token);
    expect(auth.verify(session.token)).toEqual({ ok: false, reason: 'unknown-token' });
    expect(auth.verify(rotated.token).ok).toBe(true);
  });

  it('binds a token to one device', () => {
    const { auth, login, record } = setup();
    const session = login();
    const check = auth.verify(session.token);
    expect(check.ok && check.deviceId).toBe(record.deviceId);
  });

  it('rejects an unknown token', () => {
    const { auth } = setup();
    expect(auth.verify('made-up')).toEqual({ ok: false, reason: 'unknown-token' });
  });

  it('drops tokens the moment a device is revoked', () => {
    const { auth, registry, login, record } = setup();
    const session = login();
    expect(auth.verify(session.token).ok).toBe(true);

    registry.revoke(record.deviceId);

    // Immediately invalid, without waiting for the next auth attempt.
    expect(auth.verify(session.token)).toEqual({ ok: false, reason: 'unknown-token' });
    expect(auth.stats().activeTokens).toBe(0);
  });

  it('refuses to re-authenticate a revoked device', () => {
    const { auth, registry, record } = setup();
    registry.revoke(record.deviceId);
    expect(auth.challenge(record.deviceId)).toEqual({ ok: false, reason: 'device-revoked' });
  });

  it('flags a token that is close to expiry', () => {
    let now = 1_000;
    const { auth, login } = setup({ now: () => now });
    const session = login();

    expect(auth.isExpiringSoon(session.token)).toBe(false);
    now += ACCESS_TOKEN_TTL_MS - 60_000;
    expect(auth.isExpiringSoon(session.token)).toBe(true);
  });

  it('sweeps expired state so memory stays bounded', () => {
    let now = 1_000;
    const { auth, login, record } = setup({ now: () => now });
    login();
    auth.challenge(record.deviceId);
    expect(auth.stats().activeTokens).toBe(1);

    now += ACCESS_TOKEN_TTL_MS + 1;
    auth.sweep();
    expect(auth.stats()).toEqual({ activeTokens: 0, pendingNonces: 0 });
  });
});

describe('token transport', () => {
  it('reads a bearer token from the Authorization header', () => {
    expect(bearerFromHeader('Bearer abc123')).toBe('abc123');
    expect(bearerFromHeader('  Bearer abc123  ')).toBe('abc123');
    expect(bearerFromHeader('Basic abc123')).toBeUndefined();
    expect(bearerFromHeader('Bearer ')).toBeUndefined();
    expect(bearerFromHeader(undefined)).toBeUndefined();
  });

  it('reads a token from the WebSocket subprotocol, never a query string', () => {
    expect(tokenFromSubprotocols(['dshm.v1', 'dshm.token.abc123'])).toBe('abc123');
    expect(tokenFromSubprotocols(['dshm.v1'])).toBeUndefined();
    expect(tokenFromSubprotocols(['dshm.token.'])).toBeUndefined();
  });
});

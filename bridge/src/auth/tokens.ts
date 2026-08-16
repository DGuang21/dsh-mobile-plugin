/**
 * [OUR DESIGN] Session authentication.
 *
 * Challenge-response against the device's Ed25519 key, yielding a short-lived
 * access token:
 *
 *   1. `POST /m1/auth/session` with `{deviceId}` → the bridge returns a nonce.
 *   2. The phone signs `"dshm/auth" ‖ nonce ‖ deviceId ‖ bridgeId` and posts it.
 *   3. The bridge verifies against the registered public key and issues a token.
 *
 * Design decisions and why:
 *   - Tokens live **only in memory**. A bridge restart invalidates every token,
 *     which is correct: the phone can always silently re-auth with its device
 *     key, so there is no reason to persist a bearer credential to disk.
 *   - TTL is 15 minutes and the token is bound to one `deviceId`. A stolen token
 *     is short-lived and useless without the device key.
 *   - Tokens rotate on stream connect, so a long-lived stream does not imply a
 *     long-lived credential.
 *   - Nonces are single-use and expire, so a captured challenge-response pair
 *     cannot be replayed.
 *   - Revocation kills tokens immediately, not at next use.
 */

import {
  constantTimeEqual,
  domainMessage,
  randomToken,
  toBase64Url,
  verifySignatureB64,
} from '../identity/crypto.ts';
import type { DeviceRegistry } from '../identity/registry.ts';

/** Access token lifetime. Short, because re-auth is cheap and silent. */
export const ACCESS_TOKEN_TTL_MS = 15 * 60_000;
/** Nonce lifetime. Only needs to cover one round trip. */
export const AUTH_NONCE_TTL_MS = 60_000;

/** Warn the client this far before expiry so it can rotate without a 401. */
export const TOKEN_EXPIRY_WARNING_MS = 2 * 60_000;

export interface AccessToken {
  token: string;
  deviceId: string;
  issuedAt: number;
  expiresAt: number;
}

export type AuthFailure =
  | 'unknown-device'
  | 'device-revoked'
  | 'nonce-unknown'
  | 'nonce-expired'
  | 'bad-signature';

export type AuthResult =
  | { ok: true; token: string; expiresAt: number; deviceId: string }
  | { ok: false; reason: AuthFailure };

export type TokenFailure = 'unknown-token' | 'expired' | 'device-revoked';

export type TokenCheck =
  | { ok: true; deviceId: string; expiresAt: number }
  | { ok: false; reason: TokenFailure };

export type RotateResult =
  | { ok: true; token: string; expiresAt: number }
  | { ok: false; reason: TokenFailure };

/** The message a device signs to authenticate. */
export function authProofMessage(nonce: string, deviceId: string, bridgeId: string): Buffer {
  // A distinct purpose string from pairing, so a pairing proof can never be
  // replayed as an auth response or vice versa.
  return domainMessage('auth', nonce, deviceId, bridgeId);
}

interface NonceEntry {
  deviceId: string;
  expiresAt: number;
}

export interface AuthServiceOptions {
  registry: DeviceRegistry;
  bridgeId: string;
  now?: () => number;
  tokenFactory?: () => string;
  nonceFactory?: () => string;
}

export class AuthService {
  private readonly nonces = new Map<string, NonceEntry>();
  private readonly tokens = new Map<string, AccessToken>();
  private readonly registry: DeviceRegistry;
  private readonly bridgeId: string;
  private readonly now: () => number;
  private readonly tokenFactory: () => string;
  private readonly nonceFactory: () => string;

  constructor(options: AuthServiceOptions) {
    this.registry = options.registry;
    this.bridgeId = options.bridgeId;
    this.now = options.now ?? (() => Date.now());
    this.tokenFactory = options.tokenFactory ?? (() => toBase64Url(randomToken(32)));
    this.nonceFactory = options.nonceFactory ?? (() => toBase64Url(randomToken(32)));

    // A revoked device loses its tokens at once. Deferring to the next request
    // would leave an attacker's in-flight session alive.
    this.registry.onRevocation((deviceId) => this.revokeDeviceTokens(deviceId));
  }

  /**
   * Issue a challenge. Requires a known, active device: an unknown device gets
   * no nonce, so the endpoint cannot be used to farm valid challenges.
   */
  challenge(deviceId: string): { ok: true; nonce: string; expiresAt: number } | { ok: false; reason: AuthFailure } {
    const device = this.registry.get(deviceId);
    if (device === undefined) return { ok: false, reason: 'unknown-device' };
    if (device.revokedAt !== undefined) return { ok: false, reason: 'device-revoked' };

    this.sweep();
    const nonce = this.nonceFactory();
    const expiresAt = this.now() + AUTH_NONCE_TTL_MS;
    this.nonces.set(nonce, { deviceId, expiresAt });
    return { ok: true, nonce, expiresAt };
  }

  /** Verify a signed challenge and issue an access token. */
  authenticate(input: { deviceId: string; nonce: string; signature: string }): AuthResult {
    const entry = this.nonces.get(input.nonce);
    // Consume unconditionally: one nonce, one attempt, so a captured pair is
    // never replayable and a wrong signature does not grant a retry.
    this.nonces.delete(input.nonce);

    if (entry === undefined) return { ok: false, reason: 'nonce-unknown' };
    if (this.now() > entry.expiresAt) return { ok: false, reason: 'nonce-expired' };
    // The nonce was issued to one device; it cannot be redeemed by another.
    if (entry.deviceId !== input.deviceId) return { ok: false, reason: 'nonce-unknown' };

    const device = this.registry.get(input.deviceId);
    if (device === undefined) return { ok: false, reason: 'unknown-device' };
    if (device.revokedAt !== undefined) return { ok: false, reason: 'device-revoked' };

    const message = authProofMessage(input.nonce, input.deviceId, this.bridgeId);
    if (!verifySignatureB64(device.publicKey, message, input.signature)) {
      return { ok: false, reason: 'bad-signature' };
    }

    const issued = this.issue(input.deviceId);
    this.registry.touch(input.deviceId);
    return { ok: true, token: issued.token, expiresAt: issued.expiresAt, deviceId: input.deviceId };
  }

  private issue(deviceId: string): AccessToken {
    const issuedAt = this.now();
    const token: AccessToken = {
      token: this.tokenFactory(),
      deviceId,
      issuedAt,
      expiresAt: issuedAt + ACCESS_TOKEN_TTL_MS,
    };
    this.tokens.set(token.token, token);
    return token;
  }

  /**
   * Validate a bearer token. Constant-time lookup is not attempted here: the
   * token is a 256-bit random value used as a map key, so there is no useful
   * timing signal to leak (unlike comparing against a single fixed secret).
   */
  verify(token: string): TokenCheck {
    const entry = this.tokens.get(token);
    if (entry === undefined) return { ok: false, reason: 'unknown-token' };
    if (this.now() > entry.expiresAt) {
      this.tokens.delete(token);
      return { ok: false, reason: 'expired' };
    }
    if (this.registry.getActive(entry.deviceId) === undefined) {
      this.tokens.delete(token);
      return { ok: false, reason: 'device-revoked' };
    }
    return { ok: true, deviceId: entry.deviceId, expiresAt: entry.expiresAt };
  }

  /**
   * Rotate a token, invalidating the old one. Called on stream connect so a
   * long-lived stream does not imply a long-lived credential.
   */
  rotate(token: string): RotateResult {
    const check = this.verify(token);
    if (!check.ok) return { ok: false, reason: check.reason };
    this.tokens.delete(token);
    const issued = this.issue(check.deviceId);
    return { ok: true, token: issued.token, expiresAt: issued.expiresAt };
  }

  /** Whether a token is close enough to expiry to warrant a `token-expiring` frame. */
  isExpiringSoon(token: string): boolean {
    const entry = this.tokens.get(token);
    if (entry === undefined) return false;
    return entry.expiresAt - this.now() <= TOKEN_EXPIRY_WARNING_MS;
  }

  /** Drop every token for a device. Used by revocation. */
  revokeDeviceTokens(deviceId: string): number {
    let dropped = 0;
    for (const [token, entry] of this.tokens) {
      if (entry.deviceId === deviceId) {
        this.tokens.delete(token);
        dropped += 1;
      }
    }
    for (const [nonce, entry] of this.nonces) {
      if (entry.deviceId === deviceId) this.nonces.delete(nonce);
    }
    return dropped;
  }

  /** Explicit sign-out. */
  revokeToken(token: string): boolean {
    return this.tokens.delete(token);
  }

  /**
   * Expiry timestamps of this device's tokens that fall inside `withinMs`.
   *
   * Returns timestamps rather than tokens so a caller building a `token-expiring`
   * frame cannot accidentally put the token itself on the wire.
   */
  expiringTokensFor(deviceId: string, withinMs: number): number[] {
    const now = this.now();
    const expiring: number[] = [];
    for (const entry of this.tokens.values()) {
      if (entry.deviceId !== deviceId) continue;
      const remaining = entry.expiresAt - now;
      if (remaining > 0 && remaining <= withinMs) expiring.push(entry.expiresAt);
    }
    return expiring;
  }

  /** Drop expired nonces and tokens. Cheap, and bounds memory. */
  sweep(): void {
    const now = this.now();
    for (const [nonce, entry] of this.nonces) {
      if (now > entry.expiresAt) this.nonces.delete(nonce);
    }
    for (const [token, entry] of this.tokens) {
      if (now > entry.expiresAt) this.tokens.delete(token);
    }
  }

  /** Diagnostics for `/m1/health` and `status`. */
  stats(): { activeTokens: number; pendingNonces: number } {
    return { activeTokens: this.tokens.size, pendingNonces: this.nonces.size };
  }
}

/**
 * Extract a bearer token from an `Authorization` header.
 *
 * Tokens are never accepted from a query string: query strings land in access
 * logs, shell history, and referrers.
 */
export function bearerFromHeader(header: string | undefined): string | undefined {
  if (header === undefined) return undefined;
  const match = /^Bearer (.+)$/.exec(header.trim());
  const token = match?.[1]?.trim();
  return token !== undefined && token.length > 0 ? token : undefined;
}

/**
 * Extract a token from a WebSocket subprotocol list. The phone sends
 * `dshm.token.<token>` alongside `dshm.v1`, keeping the credential out of the URL.
 */
export function tokenFromSubprotocols(protocols: string[]): string | undefined {
  for (const protocol of protocols) {
    const trimmed = protocol.trim();
    if (trimmed.startsWith('dshm.token.')) {
      const token = trimmed.slice('dshm.token.'.length);
      if (token.length > 0) return token;
    }
  }
  return undefined;
}

/** Constant-time equality for two tokens, where a fixed-secret compare is needed. */
export function tokensEqual(a: string, b: string): boolean {
  return constantTimeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/**
 * [OUR DESIGN] Pairing.
 *
 * Pairing is the only moment trust is established, so it requires physical
 * access to the workstation. The flow, and the reason for each step:
 *
 *   1. The operator runs `pair` on the workstation. A 32-byte token is minted
 *      with a 120-second TTL, single use.
 *   2. The phone scans the QR and POSTs `/m1/pair/claim` with its public key and
 *      `proof = Sign(devicePrivKey, "dshm/pair" ‖ token ‖ bridgeId)`. The
 *      signature binds the claim to that key, so photographing the QR is not
 *      enough — an observer has no private key to sign with.
 *   3. The token is consumed ATOMICALLY. A second claim fails even inside the
 *      TTL, so a race between an attacker and the real phone cannot yield two
 *      paired devices.
 *   4. The bridge shows a short authentication string (SAS) and REQUIRES the
 *      operator to confirm it on the workstation. This is what defeats an
 *      attacker who photographed the QR from across the room: they can complete
 *      a claim, but they cannot make the human at the keyboard confirm a code
 *      that does not match what their own phone shows.
 *   5. Only after confirmation is the device registered.
 *
 * Pairing is refused when the bridge cannot reach dsh, so a user never pairs into
 * a dead bridge and blames the phone.
 */

import {
  constantTimeEqualB64,
  domainMessage,
  ED25519_PUBLIC_KEY_BYTES,
  fromBase64Url,
  randomToken,
  sha256,
  toBase64Url,
  verifySignatureB64,
} from './crypto.ts';
import type { DeviceRecord, DeviceRegistry } from './registry.ts';
import type { ScopeTier } from '../policy/methods.ts';

/** Single-use pairing token TTL. Short enough that a leaked QR ages out fast. */
export const PAIRING_TOKEN_TTL_MS = 120_000;

export type PairingState = 'awaiting-claim' | 'awaiting-confirmation' | 'completed' | 'failed' | 'expired';

export interface PairingSession {
  /** base64url token, carried in the QR. */
  token: string;
  createdAt: number;
  expiresAt: number;
  state: PairingState;
  /** Set once a claim is accepted; the SAS the operator must confirm. */
  sas?: string;
  /** The claiming device, pending confirmation. */
  pending?: { publicKey: string; label: string };
}

export type ClaimFailure =
  | 'token-unknown'
  | 'token-expired'
  | 'token-consumed'
  | 'bad-public-key'
  | 'bad-proof'
  | 'already-paired'
  | 'dsh-unavailable';

export type ClaimResult =
  | { ok: true; sas: string; deviceId: string; bridgeName: string; tier: ScopeTier }
  | { ok: false; reason: ClaimFailure };

export interface PairingManagerOptions {
  registry: DeviceRegistry;
  /** Stable bridge identity, bound into every pairing proof. */
  bridgeId: string;
  bridgeName: string;
  /**
   * Whether dsh is reachable right now. Pairing is refused when it is not: a
   * user who pairs into a dead bridge will blame the phone.
   */
  isDshReachable: () => boolean;
  /** Injectable clock for deterministic expiry tests. */
  now?: () => number;
  /** Injectable token source for deterministic tests. */
  tokenFactory?: () => string;
}

/**
 * Derive the 6-digit SAS both sides display.
 *
 * It commits to the token, the bridge id, and the device public key, so the code
 * the operator compares is a fingerprint of the exact pairing being confirmed.
 * An attacker substituting their own key produces a different SAS.
 */
export function computeSas(token: string, bridgeId: string, devicePublicKey: string): string {
  const digest = sha256(domainMessage('sas', token, bridgeId, devicePublicKey));
  // 6 digits: memorable to read aloud, and the SAS is only useful within the
  // 120-second window against an attacker who must also win the token race.
  const value = digest.readUInt32BE(0) % 1_000_000;
  return value.toString().padStart(6, '0');
}

/** The message a device signs to prove it holds the private key. */
export function pairingProofMessage(token: string, bridgeId: string): Buffer {
  return domainMessage('pair', token, bridgeId);
}

/**
 * [OUR DESIGN] Derive the Mode B rendezvous routing id from the pairing token.
 *
 * This is what removes the first-pair deadlock. Previously `pair --relay` demanded
 * `--peer-routing-id` — the phone's routing id — before the QR existed, which is a
 * value that cannot exist yet: a phone that has never paired has no routing id, and
 * the operator has nothing to type. Deriving a rendezvous id from the token instead
 * gives both sides a meeting point that each computes independently:
 *
 *   - the bridge computes it when it opens the pairing window and registers it at
 *     the relay in `rendezvous` mode;
 *   - the phone computes it from the token it just scanned and dials it.
 *
 * The phone MUST recompute it and compare against the QR's `rid` rather than
 * trusting `rid` blindly. They are equal by construction, so a mismatch means the
 * QR was altered in transit, and refusing is free.
 *
 * Deriving rather than randomising is what makes it independently computable, and
 * costs nothing: the token is 32 random bytes with a 120-second single-use life, so
 * the id inherits that unguessability. It is domain-separated from every other
 * token use (the pairing proof, the SAS, the seal binder) so no value is reused
 * across purposes.
 */
export function deriveRendezvousRoutingId(token: string, bridgeId: string): string {
  // 16 bytes, matching `newRoutingId`, so it satisfies `isValidRoutingId`.
  return toBase64Url(sha256(domainMessage('pair-rendezvous', token, bridgeId)).subarray(0, 16));
}

export class PairingManager {
  private session: PairingSession | undefined;
  private readonly registry: DeviceRegistry;
  private readonly bridgeId: string;
  private readonly bridgeName: string;
  private readonly isDshReachable: () => boolean;
  private readonly now: () => number;
  private readonly tokenFactory: () => string;

  constructor(options: PairingManagerOptions) {
    this.registry = options.registry;
    this.bridgeId = options.bridgeId;
    this.bridgeName = options.bridgeName;
    this.isDshReachable = options.isDshReachable;
    this.now = options.now ?? (() => Date.now());
    this.tokenFactory = options.tokenFactory ?? (() => toBase64Url(randomToken(32)));
  }

  /**
   * Open a pairing window. Replaces any previous session: only one pairing may
   * be in flight, so a stale QR left on screen cannot be claimed later.
   */
  begin(): PairingSession {
    const createdAt = this.now();
    const session: PairingSession = {
      token: this.tokenFactory(),
      createdAt,
      expiresAt: createdAt + PAIRING_TOKEN_TTL_MS,
      state: 'awaiting-claim',
    };
    this.session = session;
    return session;
  }

  /** Current session, with expiry applied. */
  current(): PairingSession | undefined {
    const session = this.session;
    if (session === undefined) return undefined;
    if (session.state === 'awaiting-claim' && this.now() > session.expiresAt) {
      session.state = 'expired';
    }
    return session;
  }

  cancel(): void {
    if (this.session !== undefined && this.session.state !== 'completed') {
      this.session.state = 'failed';
    }
    this.session = undefined;
  }

  /**
   * Process a phone's claim. Consumes the token atomically on success AND on a
   * proof failure, because a failed proof against a valid token means someone
   * other than the intended phone had the token — the operator should re-run
   * `pair` rather than let the window stay open.
   */
  claim(input: { token: string; devicePublicKey: string; label: string; proof: string }): ClaimResult {
    // Refused before touching the token: pairing into an unreachable dsh
    // produces a device that appears paired but cannot do anything.
    if (!this.isDshReachable()) return { ok: false, reason: 'dsh-unavailable' };

    const session = this.current();
    if (session === undefined) return { ok: false, reason: 'token-unknown' };
    if (session.state === 'expired') return { ok: false, reason: 'token-expired' };
    // A replayed claim inside the TTL must fail: the token is single-use.
    if (session.state !== 'awaiting-claim') return { ok: false, reason: 'token-consumed' };
    // Constant-time compare so a wrong token leaks nothing about the right one.
    if (!constantTimeEqualB64(session.token, input.token)) return { ok: false, reason: 'token-unknown' };

    const raw = fromBase64Url(input.devicePublicKey);
    if (raw === undefined || raw.length !== ED25519_PUBLIC_KEY_BYTES) {
      return { ok: false, reason: 'bad-public-key' };
    }

    // Consume before verifying the proof. This is the atomic step: even if the
    // proof fails, the token is spent, so an attacker gets exactly one attempt.
    session.state = 'awaiting-confirmation';

    const message = pairingProofMessage(session.token, this.bridgeId);
    if (!verifySignatureB64(input.devicePublicKey, message, input.proof)) {
      session.state = 'failed';
      return { ok: false, reason: 'bad-proof' };
    }

    const existing = this.registry.findByPublicKey(input.devicePublicKey);
    if (existing !== undefined && existing.revokedAt === undefined) {
      session.state = 'failed';
      return { ok: false, reason: 'already-paired' };
    }

    const deviceId = deriveDeviceId(input.devicePublicKey);
    const sas = computeSas(session.token, this.bridgeId, input.devicePublicKey);
    session.sas = sas;
    session.pending = { publicKey: input.devicePublicKey, label: input.label };

    return { ok: true, sas, deviceId, bridgeName: this.bridgeName, tier: 'default' };
  }

  /**
   * The operator's confirmation at the workstation. Mandatory — including on
   * LAN. Without it, an attacker who photographed the QR is paired.
   */
  confirm(options: { tier?: ScopeTier } = {}): DeviceRecord | undefined {
    const session = this.session;
    if (session === undefined || session.state !== 'awaiting-confirmation') return undefined;
    const pending = session.pending;
    if (pending === undefined) return undefined;

    const record = this.registry.register({
      publicKey: pending.publicKey,
      label: pending.label,
      tier: options.tier ?? 'default',
    });
    session.state = 'completed';
    return record;
  }

  /** The operator rejecting the SAS. The token stays consumed. */
  reject(): void {
    if (this.session?.state === 'awaiting-confirmation') this.session.state = 'failed';
  }

  /** Whether a claimed device is still waiting on the operator. */
  isAwaitingConfirmation(): boolean {
    return this.current()?.state === 'awaiting-confirmation';
  }

  /**
   * Whether a token could still be claimed or confirmed right now.
   *
   * Distinct from `current() !== undefined` because a completed session is
   * deliberately retained for a moment so the phone's final poll can read its
   * result. Advertising that as an open pairing window would be wrong: nothing is
   * claimable, and a status display saying otherwise invites the operator to expect
   * a second phone to be able to pair.
   */
  isOpen(): boolean {
    const state = this.current()?.state;
    return state === 'awaiting-claim' || state === 'awaiting-confirmation';
  }

  /**
   * Let the claiming phone learn the operator's decision.
   *
   * Needed because the token is spent by `claim()`: the phone cannot re-claim to
   * find out whether the SAS was confirmed. This is a read — it consumes nothing
   * and registers nothing.
   *
   * Authorization is the proof, re-verified against the *pending* public key. A
   * caller who did not make the original claim cannot produce it (they would need
   * the device private key AND the token), so this does not become a way to
   * discover whether some other phone just paired.
   */
  pollClaim(input: { devicePublicKey: string; proof: string }): PollResult {
    const session = this.session;
    if (session === undefined) return { status: 'unknown' };
    const pending = session.pending;
    if (pending === undefined) return { status: 'unknown' };
    // Compare the claimed key to the pending one before spending a verify.
    if (!constantTimeEqualB64(pending.publicKey, input.devicePublicKey)) return { status: 'unknown' };
    if (!verifySignatureB64(input.devicePublicKey, pairingProofMessage(session.token, this.bridgeId), input.proof)) {
      return { status: 'unknown' };
    }

    if (session.state === 'awaiting-confirmation') {
      return { status: 'awaiting-confirmation', sas: session.sas ?? '', expiresAt: session.expiresAt };
    }
    if (session.state === 'completed') {
      const record = this.registry.findByPublicKey(pending.publicKey);
      // Registered and then revoked before the phone polled: report it as
      // rejected rather than handing back a device id that cannot authenticate.
      if (record === undefined || record.revokedAt !== undefined) return { status: 'rejected' };
      return { status: 'paired', device: record };
    }
    return { status: 'rejected' };
  }
}

/** Outcome of {@link PairingManager.pollClaim}. */
export type PollResult =
  | { status: 'awaiting-confirmation'; sas: string; expiresAt: number }
  | { status: 'paired'; device: DeviceRecord }
  /** Operator said no, the window failed, or the device was revoked meanwhile. */
  | { status: 'rejected' }
  /** No such pending claim. Deliberately indistinguishable from a bad proof. */
  | { status: 'unknown' };

function deriveDeviceId(publicKey: string): string {
  // Imported lazily to keep the crypto import list at the top honest; the
  // registry derives the same value when it registers.
  return toBase64Url(sha256(fromBase64Url(publicKey) as Buffer).subarray(0, 16));
}

/**
 * QR payload the workstation renders. Versioned, so a future pairing change does
 * not silently reinterpret an old code.
 *
 * Mode A (LAN) carries the SPKI fingerprint the phone pins. Mode B (relay)
 * carries the relay origin plus the **rendezvous** routing id AND the bridge's
 * static public key, so a relay can never substitute its own identity.
 *
 * `rid` in Mode B is the token-derived rendezvous id from
 * {@link deriveRendezvousRoutingId}, not a durable per-device routing id. The
 * durable pair is established during pairing and the phone learns the bridge's
 * side of it from the claim response, inside the sealed channel.
 */
export function buildPairingUri(input: {
  bridgeId: string;
  token: string;
  /** Mode A: base64url SHA-256 of the TLS SPKI. */
  fingerprint?: string;
  /** Mode B: relay origin. */
  relay?: string;
  /** Mode B: the token-derived rendezvous routing id. */
  routingId?: string;
  /** Bridge static Ed25519 public key, pinned by the phone in both modes. */
  bridgeKey: string;
}): string {
  const params = new URLSearchParams();
  params.set('v', '1');
  params.set('bid', input.bridgeId);
  params.set('tok', input.token);
  params.set('bk', input.bridgeKey);
  if (input.fingerprint !== undefined) params.set('fp', input.fingerprint);
  if (input.relay !== undefined) params.set('relay', input.relay);
  if (input.routingId !== undefined) params.set('rid', input.routingId);
  return `dshm://pair?${params.toString()}`;
}

/** Parse a pairing URI. Returns `undefined` for anything unrecognized. */
export function parsePairingUri(uri: string):
  | {
      version: string;
      bridgeId: string;
      token: string;
      bridgeKey: string;
      fingerprint?: string;
      relay?: string;
      routingId?: string;
    }
  | undefined {
  if (!uri.startsWith('dshm://pair?')) return undefined;
  const params = new URLSearchParams(uri.slice('dshm://pair?'.length));
  const version = params.get('v');
  const bridgeId = params.get('bid');
  const token = params.get('tok');
  const bridgeKey = params.get('bk');
  // An unknown version is refused rather than best-effort parsed.
  if (version !== '1' || bridgeId === null || token === null || bridgeKey === null) return undefined;

  const result: ReturnType<typeof parsePairingUri> = { version, bridgeId, token, bridgeKey };
  const fingerprint = params.get('fp');
  const relay = params.get('relay');
  const routingId = params.get('rid');
  if (fingerprint !== null) result!.fingerprint = fingerprint;
  if (relay !== null) result!.relay = relay;
  if (routingId !== null) result!.routingId = routingId;
  return result;
}

/**
 * Pairing URI parsing and the checks the phone owes itself before trusting one.
 *
 * A pairing URI is the root of trust for a bridge: it carries the Ed25519 static
 * key (`bk`) the phone pins in BOTH modes, which is what makes a relay unable to
 * substitute its own identity. So the parse is strict, and every field is
 * validated for shape before anything is dialled.
 *
 * The one non-obvious rule is `rid`. It is a **rendezvous** id, derived from the
 * pairing token, alive for the pairing window and one pairing only. The phone
 * recomputes it and refuses a mismatch — they are equal by construction, so a
 * disagreement means the QR was assembled by something other than the bridge that
 * owns the token. It is never persisted; the durable id arrives inside the sealed
 * claim response.
 */

import { toBase64Url } from './bytes';
import { domainMessage, isValidEd25519PublicKey, sha256 } from './crypto';
import { isValidRoutingId } from './seal';
import type { ConnectionMode, PairingUri } from './types';

/** Longest URI we will even look at. A QR cannot legitimately be near this. */
const MAX_URI_LENGTH = 2048;

export type PairingUriProblem =
  /** Not a `dshm://pair` URI at all, or unparseable. */
  | 'not-a-pairing-uri'
  /** A version this build does not understand. Refused, not best-effort parsed. */
  | 'unsupported-version'
  /** A required field is missing. */
  | 'incomplete'
  /** `bk` is not a usable Ed25519 public key. Without a pin there is no trust. */
  | 'bad-bridge-key'
  /** Neither `fp` (Mode A) nor `relay` (Mode B) is present. */
  | 'no-transport'
  /** Mode B without a rendezvous id, or with one that is not routing-id shaped. */
  | 'bad-rendezvous-id'
  /**
   * The `rid` in the QR is not the one derived from `tok` and `bid`.
   *
   * Terminal for this QR. Either the code was altered in transit or it was not
   * produced by the bridge that owns the token; neither is worth dialling.
   */
  | 'rendezvous-mismatch';

export type ParsePairingResult =
  | { ok: true; uri: PairingUri; mode: ConnectionMode }
  | { ok: false; problem: PairingUriProblem };

/**
 * Parse and validate a pairing URI.
 *
 * Kept as a result type rather than `undefined` because the UI has genuinely
 * different things to say about "that is not a pairing code" and "that code does
 * not match its own token".
 */
export function parsePairingUriStrict(value: string): ParsePairingResult {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_URI_LENGTH) return { ok: false, problem: 'not-a-pairing-uri' };
  if (!trimmed.startsWith('dshm://pair?')) return { ok: false, problem: 'not-a-pairing-uri' };

  // `URLSearchParams` directly rather than `new URL`: RN's URL polyfill has
  // historically disagreed with the web on non-special schemes like `dshm:`, and
  // the query string is all that is needed.
  const params = new URLSearchParams(trimmed.slice('dshm://pair?'.length));
  const version = params.get('v');
  if (version !== '1') return { ok: false, problem: 'unsupported-version' };

  const bid = params.get('bid');
  const tok = params.get('tok');
  const bk = params.get('bk');
  if (bid === null || bid.length === 0) return { ok: false, problem: 'incomplete' };
  if (tok === null || tok.length === 0) return { ok: false, problem: 'incomplete' };
  if (bk === null || bk.length === 0) return { ok: false, problem: 'incomplete' };
  // The pin must be a real point on the curve. A malformed one would fail later,
  // during the handshake, where it would look like a network problem instead of a
  // bad code.
  if (!isValidEd25519PublicKey(bk)) return { ok: false, problem: 'bad-bridge-key' };

  const fp = params.get('fp');
  const relay = params.get('relay');
  const rid = params.get('rid');

  const uri: PairingUri = {
    v: 1,
    bid,
    tok,
    bk,
    ...(fp !== null && fp.length > 0 ? { fp } : {}),
    ...(relay !== null && relay.length > 0 ? { relay } : {}),
    ...(rid !== null && rid.length > 0 ? { rid } : {}),
  };

  // Mode B takes precedence when both are present: a QR carrying a relay origin
  // was printed by a bridge that expects to be reached that way, and `fp` may
  // additionally be there for a LAN fallback.
  if (uri.relay !== undefined) {
    if (uri.rid === undefined || !isValidRoutingId(uri.rid)) return { ok: false, problem: 'bad-rendezvous-id' };
    // The load-bearing check. Both sides derive this from the token independently,
    // so equality is guaranteed for a genuine code.
    if (deriveRendezvousRoutingId(uri.tok, uri.bid) !== uri.rid) {
      return { ok: false, problem: 'rendezvous-mismatch' };
    }
    return { ok: true, uri, mode: 'relay' };
  }

  if (uri.fp !== undefined) return { ok: true, uri, mode: 'lan' };

  // Neither transport. Nothing to dial, and a Mode A code without `fp` would mean
  // an unpinned TLS connection, which this client does not do.
  return { ok: false, problem: 'no-transport' };
}

/**
 * Back-compatible parse.
 *
 * Kept because it is the existing signature; new code should prefer
 * {@link parsePairingUriStrict}, which explains a refusal.
 */
export function parsePairingUri(value: string): PairingUri | undefined {
  const result = parsePairingUriStrict(value);
  return result.ok ? result.uri : undefined;
}

/**
 * Recompute the Mode B rendezvous routing id.
 *
 * Must agree with `deriveRendezvousRoutingId` in `bridge/src/identity/pairing.ts`:
 * the first 16 bytes of `sha256(domain('pair-rendezvous', token, bridgeId))`,
 * base64url. 16 bytes so the result satisfies the relay's routing-id shape.
 */
export function deriveRendezvousRoutingId(token: string, bridgeId: string): string {
  return toBase64Url(sha256(domainMessage('pair-rendezvous', token, bridgeId)).subarray(0, 16));
}

/**
 * The 6-digit SAS, recomputed locally.
 *
 * The phone displays the value the BRIDGE sent, since that is what the operator is
 * comparing against the workstation. This exists so the phone can verify the two
 * agree: a mismatch means the response did not come from a party that knows the
 * token and our device key, which is exactly what the SAS is for.
 */
export function computeSas(token: string, bridgeId: string, devicePublicKey: string): string {
  const digest = sha256(domainMessage('sas', token, bridgeId, devicePublicKey));
  const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
  return (view.getUint32(0, false) % 1_000_000).toString().padStart(6, '0');
}

/** The message a device signs to prove it holds the private key. */
export function pairingProofMessage(token: string, bridgeId: string): Uint8Array {
  return domainMessage('pair', token, bridgeId);
}

/** Domain-separated auth challenge response message. */
export function authProofMessage(nonce: string, deviceId: string, bridgeId: string): Uint8Array {
  return domainMessage('auth', nonce, deviceId, bridgeId);
}

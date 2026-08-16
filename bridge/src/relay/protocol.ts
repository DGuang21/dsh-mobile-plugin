/**
 * [OUR DESIGN] Relay control protocol.
 *
 * This is the ONLY thing the relay understands. Everything of value travels as an
 * opaque `SealedRecord` inside `relay/data`, which the relay forwards without
 * being able to read (see relay/seal.ts).
 *
 * The relay is deliberately given the least information that still lets it route:
 *   - a routing id per party, which is an opaque 16-byte random value
 *   - a paired routing id to forward to
 *   - byte counts, for quotas
 *
 * It is NOT given, and cannot derive: device ids, public keys, method names,
 * session ids, prompt text, or approval outcomes. A compromised relay learns who
 * is talking to whom (by routing id, which it cannot link to an identity) and
 * when, and nothing else.
 *
 * Routing ids are registered, never assigned by the relay. A relay that could
 * choose ids could steer a phone at a bridge of its choosing; instead both sides
 * bring ids agreed out of band at pairing time, and the sealed handshake would
 * fail anyway if the relay misrouted.
 *
 * ## Two registration modes, and why the second exists
 *
 * `mode: 'peer'` is steady state: both sides name each other, and the relay
 * refuses to move a byte unless the naming is mutual. That invariant is what stops
 * one peer from injecting frames into someone else's tunnel.
 *
 * `mode: 'rendezvous'` exists to solve first-pair sequencing. Before a phone has
 * ever been paired it has no routing id, so a workstation printing a QR code
 * cannot possibly name one — requiring it made `pair --relay` depend on a value
 * nobody could know yet. A rendezvous registration therefore names NO peer, and
 * the relay will deliver inbound frames to it from any sender, tagging each frame
 * with the sender's routing id in `from` so the holder can answer via `to`.
 *
 * That relaxation is safe because a rendezvous id is not a capability. It is
 * derived from the 32-byte single-use pairing token (see
 * `deriveRendezvousRoutingId` in identity/pairing.ts), so reaching it at all
 * requires having seen the QR; and reaching it buys nothing on its own, because
 * the sealed pairing handshake still authenticates the bridge's pinned Ed25519
 * static key and the claim inside it still needs the token, a valid signature, and
 * an operator-confirmed SAS. The relay remains unable to read, forge, or
 * usefully redirect anything.
 */

import type { SealedRecord } from './seal.ts';

export const RELAY_PROTOCOL_VERSION = 1;

/** WebSocket subprotocol the relay requires. */
export const RELAY_SUBPROTOCOL = 'dshm.relay.v1';

/** Which side of a tunnel a peer is. */
export type RelayRole = 'bridge' | 'phone';

/**
 * How a registration routes.
 *
 * `peer` requires mutual naming and is what a paired tunnel uses. `rendezvous`
 * names no peer and accepts inbound frames from any sender; it is only ever used
 * by a bridge holding an open pairing window.
 */
export type RelayRegisterMode = 'peer' | 'rendezvous';

/** Peer → relay. */
export type RelayClientMessage =
  /**
   * Claim a routing id. The relay does not authenticate this beyond
   * "is it currently free": the security model does not depend on it, because a
   * squatter still cannot complete the sealed handshake.
   *
   * `peerRoutingId` is present for `mode: 'peer'` and absent for
   * `mode: 'rendezvous'`.
   */
  | {
      v: 1;
      type: 'relay/register';
      role: RelayRole;
      routingId: string;
      mode: RelayRegisterMode;
      peerRoutingId?: string;
    }
  /**
   * An opaque sealed frame.
   *
   * `to` is required only when the sender is a rendezvous holder, which has no
   * single fixed peer and must therefore name the claimant it is answering.
   */
  | { v: 1; type: 'relay/data'; record: SealedRecord; to?: string }
  /**
   * An opaque seal-handshake blob for the paired routing id.
   *
   * Carried separately from `relay/data` only because a handshake message is not
   * shaped like a sealed record — the relay treats it with the same indifference.
   * A relay that tampers with or forges one of these cannot succeed: it holds
   * neither side's Ed25519 static key, so the transcript signature fails and both
   * peers abort (see relay/seal.ts).
   */
  | { v: 1; type: 'relay/handshake'; hs: Record<string, unknown>; to?: string }
  /** Liveness. Kept at the control layer so it works before a tunnel is up. */
  | { v: 1; type: 'relay/ping'; at: number }
  /** Voluntary teardown. */
  | { v: 1; type: 'relay/bye' };

/** Relay → peer. */
export type RelayServerMessage =
  | { v: 1; type: 'relay/registered'; routingId: string; peerPresent: boolean }
  | { v: 1; type: 'relay/peer-online' }
  | { v: 1; type: 'relay/peer-offline' }
  /** `from` is set when the receiver is a rendezvous holder. */
  | { v: 1; type: 'relay/data'; record: SealedRecord; from?: string }
  | { v: 1; type: 'relay/handshake'; hs: Record<string, unknown>; from?: string }
  | { v: 1; type: 'relay/pong'; at: number }
  | { v: 1; type: 'relay/error'; code: RelayErrorCode; message: string };

export type RelayErrorCode =
  /** Version mismatch, malformed message, or wrong message for the state. */
  | 'bad-message'
  /** Routing id already held by a live connection. */
  | 'routing-id-taken'
  /** Sent data before registering. */
  | 'not-registered'
  /** The paired routing id has no live connection. */
  | 'peer-offline'
  /** Frame or rate quota exceeded. */
  | 'quota-exceeded'
  /** A rendezvous holder is already tracking its maximum concurrent claimants. */
  | 'rendezvous-busy'
  | 'internal';

/** Routing ids are opaque base64url 16-byte values; the relay checks only shape. */
export function isValidRoutingId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{22}$/.test(value);
}

/**
 * Read an optional `to` field.
 *
 * Returns `undefined` when absent, the id when valid, and the sentinel
 * `'invalid'` otherwise — so a malformed target is refused rather than silently
 * treated as absent, which would send a frame to the wrong place.
 */
function parseOptionalTarget(value: unknown): string | undefined | 'invalid' {
  if (value === undefined) return undefined;
  if (!isValidRoutingId(value)) return 'invalid';
  return value;
}

/**
 * Validate a peer→relay message.
 *
 * Returns a discriminated result rather than throwing: this parses hostile input
 * on a public endpoint, and an exception path there is a liability.
 */
export function parseClientMessage(raw: unknown): { ok: true; message: RelayClientMessage } | { ok: false; code: RelayErrorCode; reason: string } {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, code: 'bad-message', reason: 'message must be an object' };
  }
  const record = raw as Record<string, unknown>;
  if (record.v !== RELAY_PROTOCOL_VERSION) {
    return { ok: false, code: 'bad-message', reason: 'unsupported protocol version' };
  }

  switch (record.type) {
    case 'relay/register': {
      if (record.role !== 'bridge' && record.role !== 'phone') {
        return { ok: false, code: 'bad-message', reason: 'role must be bridge or phone' };
      }
      if (!isValidRoutingId(record.routingId)) {
        return { ok: false, code: 'bad-message', reason: 'routing ids must be 22-char base64url' };
      }
      // Absent `mode` is read as `peer`, so a v1 peer that predates rendezvous
      // keeps working unchanged.
      const mode = record.mode ?? 'peer';
      if (mode !== 'peer' && mode !== 'rendezvous') {
        return { ok: false, code: 'bad-message', reason: 'mode must be peer or rendezvous' };
      }
      if (mode === 'rendezvous') {
        // A rendezvous names no peer. Accepting one anyway would create two
        // sources of truth for where its frames may go.
        if (record.peerRoutingId !== undefined) {
          return { ok: false, code: 'bad-message', reason: 'a rendezvous registration must not name a peer' };
        }
        // Only a bridge holds a rendezvous. A phone claiming one would be
        // attempting to receive traffic addressed to a pairing window.
        if (record.role !== 'bridge') {
          return { ok: false, code: 'bad-message', reason: 'only a bridge may register a rendezvous' };
        }
        return { ok: true, message: { v: 1, type: 'relay/register', role: record.role, routingId: record.routingId, mode } };
      }
      if (!isValidRoutingId(record.peerRoutingId)) {
        return { ok: false, code: 'bad-message', reason: 'routing ids must be 22-char base64url' };
      }
      // Self-pairing would make a peer its own tunnel, which is only ever a bug
      // or an attempt to use the relay as an echo oracle.
      if (record.routingId === record.peerRoutingId) {
        return { ok: false, code: 'bad-message', reason: 'routingId and peerRoutingId must differ' };
      }
      return {
        ok: true,
        message: {
          v: 1,
          type: 'relay/register',
          role: record.role,
          routingId: record.routingId,
          mode,
          peerRoutingId: record.peerRoutingId,
        },
      };
    }
    case 'relay/data': {
      const candidate = record.record;
      if (typeof candidate !== 'object' || candidate === null) {
        return { ok: false, code: 'bad-message', reason: 'record must be an object' };
      }
      const sealed = candidate as Record<string, unknown>;
      // The relay validates only that this is shaped like a sealed record. It
      // cannot and must not inspect the contents.
      if (typeof sealed.n !== 'string' || typeof sealed.c !== 'string') {
        return { ok: false, code: 'bad-message', reason: 'record must have string n and c' };
      }
      const to = parseOptionalTarget(record.to);
      if (to === 'invalid') return { ok: false, code: 'bad-message', reason: 'to must be a routing id' };
      return {
        ok: true,
        message: { v: 1, type: 'relay/data', record: { n: sealed.n, c: sealed.c }, ...(to === undefined ? {} : { to }) },
      };
    }
    case 'relay/handshake': {
      const candidate = record.hs;
      if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) {
        return { ok: false, code: 'bad-message', reason: 'hs must be an object' };
      }
      const to = parseOptionalTarget(record.to);
      if (to === 'invalid') return { ok: false, code: 'bad-message', reason: 'to must be a routing id' };
      // Shape only. The relay cannot verify a handshake and must not try.
      return {
        ok: true,
        message: {
          v: 1,
          type: 'relay/handshake',
          hs: candidate as Record<string, unknown>,
          ...(to === undefined ? {} : { to }),
        },
      };
    }
    case 'relay/ping': {
      const at = typeof record.at === 'number' && Number.isFinite(record.at) ? record.at : 0;
      return { ok: true, message: { v: 1, type: 'relay/ping', at } };
    }
    case 'relay/bye':
      return { ok: true, message: { v: 1, type: 'relay/bye' } };
    default:
      return { ok: false, code: 'bad-message', reason: 'unknown message type' };
  }
}

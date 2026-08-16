/**
 * [OUR DESIGN] Tunnel wire format.
 *
 * These are the messages that travel *inside* a sealed record. The relay never
 * sees any of it. The design goal is that a phone speaking over the relay uses the
 * same `/m1` semantics it uses on the LAN, so there is exactly one server-side
 * authorization path and no second, weaker way in.
 *
 * Consequently a tunnel request is deliberately a thin HTTP shape: method, path,
 * and body. The bridge replays it against its own `/m1` router, which means
 * pairing, tokens, policy, rate limits, and audit all apply unchanged. Adding a
 * bespoke tunnel-only command set would have meant duplicating those checks, and a
 * duplicated check is a check that eventually diverges.
 */

/** Phone → bridge, inside the tunnel. */
export type TunnelClientMessage =
  /**
   * One `/m1` request. `id` correlates the response and is chosen by the phone.
   *
   * `path` is validated against the known `/m1` set by the bridge; it is not a
   * general-purpose proxy.
   */
  | { v: 1; type: 'tunnel/request'; id: string; method: 'GET' | 'POST'; path: string; token?: string; body?: unknown }
  /**
   * Subscribe to the event stream. At most one per tunnel: a second subscribe
   * replaces the first, which is what a reconnecting phone wants.
   */
  | { v: 1; type: 'tunnel/subscribe'; id: string; token: string; after?: number }
  /** Drop the subscription but keep the tunnel. */
  | { v: 1; type: 'tunnel/unsubscribe' }
  | { v: 1; type: 'tunnel/ping'; at: number };

/** Bridge → phone, inside the tunnel. */
export type TunnelServerMessage =
  /** Response to a `tunnel/request`, carrying the HTTP status verbatim. */
  | { v: 1; type: 'tunnel/response'; id: string; status: number; body: unknown }
  /** Accepted subscription. Mirrors the `/m1/stream` hello frame. */
  | { v: 1; type: 'tunnel/subscribed'; id: string; hello: unknown }
  /** Refused subscription, with the same status a `/m1/stream` upgrade would use. */
  | { v: 1; type: 'tunnel/subscribe-failed'; id: string; status: number; reason: string }
  /** One stream envelope, byte-identical to what `/m1/stream` would have sent. */
  | { v: 1; type: 'tunnel/event'; envelope: unknown }
  /** The bridge ended the subscription (revocation, dsh restart, shutdown). */
  | { v: 1; type: 'tunnel/unsubscribed'; reason: string }
  | { v: 1; type: 'tunnel/pong'; at: number }
  /** Tunnel-level failure. Distinct from an `/m1` error inside a response body. */
  | { v: 1; type: 'tunnel/error'; message: string };

/** Max plaintext size of one tunnel message, before sealing. */
export const TUNNEL_MAX_MESSAGE_BYTES = 1024 * 1024;

/**
 * Parse a phone→bridge tunnel message.
 *
 * Returns a result rather than throwing. Unlike the relay protocol, this input is
 * authenticated — it survived AES-GCM — but it is still attacker-chosen if a paired
 * device is malicious, so it gets the same treatment.
 */
export function parseTunnelClientMessage(
  raw: unknown,
): { ok: true; message: TunnelClientMessage } | { ok: false; reason: string } {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: 'message must be an object' };
  }
  const record = raw as Record<string, unknown>;
  if (record.v !== 1) return { ok: false, reason: 'unsupported tunnel version' };

  switch (record.type) {
    case 'tunnel/request': {
      if (typeof record.id !== 'string' || record.id.length === 0 || record.id.length > 128) {
        return { ok: false, reason: 'id must be a string of 1..128 chars' };
      }
      if (record.method !== 'GET' && record.method !== 'POST') {
        return { ok: false, reason: 'method must be GET or POST' };
      }
      if (typeof record.path !== 'string' || !record.path.startsWith('/m1/') || record.path.length > 256) {
        return { ok: false, reason: 'path must be an /m1 path' };
      }
      if (record.token !== undefined && (typeof record.token !== 'string' || record.token.length === 0 || record.token.length > 512)) {
        return { ok: false, reason: 'token must be a non-empty string when present' };
      }
      return {
        ok: true,
        message: {
          v: 1,
          type: 'tunnel/request',
          id: record.id,
          method: record.method,
          path: record.path,
          ...(record.token === undefined ? {} : { token: record.token }),
          ...(record.body === undefined ? {} : { body: record.body }),
        },
      };
    }
    case 'tunnel/subscribe': {
      if (typeof record.id !== 'string' || record.id.length === 0 || record.id.length > 128) {
        return { ok: false, reason: 'id must be a string of 1..128 chars' };
      }
      if (typeof record.token !== 'string' || record.token.length === 0 || record.token.length > 512) {
        return { ok: false, reason: 'token must be a non-empty string' };
      }
      if (record.after !== undefined && (!Number.isInteger(record.after) || (record.after as number) < 0)) {
        return { ok: false, reason: 'after must be a non-negative integer' };
      }
      return {
        ok: true,
        message: {
          v: 1,
          type: 'tunnel/subscribe',
          id: record.id,
          token: record.token,
          ...(record.after === undefined ? {} : { after: record.after as number }),
        },
      };
    }
    case 'tunnel/unsubscribe':
      return { ok: true, message: { v: 1, type: 'tunnel/unsubscribe' } };
    case 'tunnel/ping': {
      const at = typeof record.at === 'number' && Number.isFinite(record.at) ? record.at : 0;
      return { ok: true, message: { v: 1, type: 'tunnel/ping', at } };
    }
    default:
      return { ok: false, reason: 'unknown tunnel message type' };
  }
}

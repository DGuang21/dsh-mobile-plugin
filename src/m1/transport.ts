/**
 * [OUR DESIGN] One request/stream interface over both transports.
 *
 * Mode A is HTTPS plus a WebSocket to the bridge on the LAN. Mode B is a sealed
 * tunnel through an untrusted relay. Above this seam they are the same thing:
 * `request()` returns a status and a body, `subscribe()` delivers a hello and then
 * envelopes.
 *
 * The point of collapsing them here is that everything above — auth, token
 * rotation, resync, revocation, reconnect policy — is then written once. A second
 * copy for the relay path would be a second place for the token-rotation rule to
 * be subtly wrong.
 *
 * What deliberately does NOT live behind this seam: pinning. Mode A pins a TLS
 * SPKI, Mode B pins an Ed25519 static key in the seal handshake, and they fail at
 * different layers. Both surface as a `pin-mismatch`, but the check itself belongs
 * where the evidence is.
 */

import type { M1StreamEnvelope, M1StreamHello, PinMismatchDetail, RelayErrorCode } from './types';

/** A response, shaped like HTTP because that is what the bridge speaks. */
export interface TransportResponse {
  status: number;
  body: unknown;
}

export type TransportFailureKind =
  /** Could not reach the far side. Retryable. */
  | 'offline'
  /** Reached it, no answer in time. Retryable. */
  | 'timeout'
  /**
   * The path itself misbehaved: a sealed record that would not open, a relay
   * sending nonsense, a TLS pin mismatch. NOT retryable without re-establishing.
   */
  | 'transport'
  /**
   * Pinned-key verification failed. Terminal, and never to be retried or
   * user-overridable — this is what a man in the middle looks like.
   */
  | 'pin-mismatch';

export class TransportError extends Error {
  readonly kind: TransportFailureKind;
  /**
   * The relay's own code, when the relay is what failed.
   *
   * Carried on the error rather than folded into `kind` because the core needs the
   * exact code to choose a state: `routing-id-taken` is terminal
   * (`routing-collision`), `rendezvous-busy` is terminal for this QR, and
   * everything else is a back-off (`relay-unavailable`).
   */
  readonly relayCode?: RelayErrorCode;
  /** Which pin failed. Only set when `kind` is `pin-mismatch`. */
  readonly pinDetail?: PinMismatchDetail;

  constructor(
    kind: TransportFailureKind,
    message: string,
    extra?: { relayCode?: RelayErrorCode; pinDetail?: PinMismatchDetail },
  ) {
    super(message);
    this.name = 'TransportError';
    this.kind = kind;
    if (extra?.relayCode !== undefined) this.relayCode = extra.relayCode;
    if (extra?.pinDetail !== undefined) this.pinDetail = extra.pinDetail;
  }
}

export interface StreamHandlers {
  onHello: (hello: M1StreamHello) => void;
  onEnvelope: (envelope: M1StreamEnvelope) => void;
  /**
   * The stream ended. `reason` is operator-readable and secret-free.
   *
   * `status` is present only when the far side gave one — a Mode B
   * `tunnel/subscribe-failed`. Mode A cannot supply it: the bridge refuses the
   * upgrade with an HTTP status the WebSocket API does not expose. So a `401` here
   * is a fast path to re-auth, and its absence must not be read as success.
   */
  onClosed: (reason: string, status?: number) => void;
}

/** A live stream subscription. `stop()` is idempotent. */
export interface StreamSubscription {
  stop: () => void;
}

/**
 * The transport contract.
 *
 * `request` carries the token explicitly rather than reading it from shared state,
 * so the memory-only token has exactly one owner (the core) and cannot be
 * accidentally persisted by a transport.
 */
export interface M1Transport {
  readonly mode: 'lan' | 'relay';
  /**
   * Get the transport ready to carry requests.
   *
   * Mode A has nothing to do here. Mode B opens the relay socket, registers, and
   * runs the sealed handshake — so this is where a pin mismatch surfaces, before
   * any application byte is sent.
   */
  start(): Promise<void>;
  request(input: {
    method: 'GET' | 'POST';
    path: string;
    token?: string;
    body?: unknown;
  }): Promise<TransportResponse>;
  subscribe(input: { token: string; after: number; handlers: StreamHandlers }): StreamSubscription;
  /** Release everything. The transport is not reusable afterwards. */
  close(): void;
}

/**
 * A transport died on its own, with no request in flight to reject.
 *
 * Mode B needs this: a relay socket can drop while the phone is idle, and without
 * a notification the core would keep showing `ready` over a tunnel that is gone.
 * The core owns reconnect policy, so this only reports — it never retries.
 */
export type TransportLostHandler = (failure: TransportError) => void;

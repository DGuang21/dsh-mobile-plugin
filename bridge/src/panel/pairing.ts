/**
 * [OUR DESIGN] Panel-side pairing controller.
 *
 * The management panel is a browser page, not a long-lived socket, so it cannot
 * hold the pairing stream open the way the CLI does over the control socket. This
 * turns the push-based `ControlHandlers.beginPair` into a pull-based (pollable)
 * state machine: `beginPair`'s `emit` callback is captured into a single latest
 * snapshot that a `GET` can read, and the operator's SAS decision and cancel are
 * forwarded straight through to the disposer `beginPair` returned.
 *
 * WHY REUSE `beginPair` RATHER THAN RE-IMPLEMENT
 *
 * `beginPair` is the audited pairing state machine — relay-vs-LAN QR minting, the
 * rendezvous listener, the SAS gate, the post-confirm route registration, and the
 * bounded lingers that let a phone's final poll land. A second copy of that for
 * the panel would be a second thing to get subtly wrong. So this file adds no
 * pairing logic; it only adapts the transport.
 *
 * WHAT IT NEVER EXPOSES
 *
 * The raw pairing token. `beginPair` emits `pair-open` with both `uri` and `token`;
 * the panel keeps only `uri` (which embeds the token as `tok=`, exactly as the QR
 * the operator scans does) and drops the bare `token`. Nothing here writes the
 * token to a status field, a log, or the audit trail.
 *
 * SELF-TERMINATION
 *
 * An abandoned panel pairing does not leak. `beginPair`'s internal 200 ms poll
 * emits `pair-failed` when the 120-second token TTL lapses, and its `finish()`
 * closes any relay rendezvous — so a window the operator walks away from ages out
 * and tears itself down with no further interaction. Starting a new pairing first
 * cancels the previous one.
 */

import type { ControlHandlers, ControlResponse } from '../control.ts';

/** The pull-able phase the panel renders. */
export type PanelPairingPhase = 'idle' | 'open' | 'claimed' | 'done' | 'failed';

/**
 * A single snapshot of the current pairing, safe to hand to the panel.
 *
 * Deliberately omits the raw token: `uri` is the only token-bearing field, and it
 * is the same value the operator would scan off a screen.
 */
export interface PanelPairingSnapshot {
  phase: PanelPairingPhase;
  /** Present from `open` onward: the QR payload to render. */
  uri?: string;
  /** Epoch ms the pairing window closes. */
  expiresAt?: number;
  /** Present in `claimed`: the 6-digit code the operator must compare. */
  sas?: string;
  /** Present in `claimed`/`done`: the claiming/paired device. */
  deviceId?: string;
  label?: string;
  /** Requested scope tier for this window. */
  tier?: 'default' | 'extended';
  /** Whether this is a relay-mode (Mode B) window. */
  relay?: boolean;
  /** Present in `done`: the tier actually granted. */
  grantedTier?: string;
  /** Present in `failed`: why. Never contains secrets. */
  reason?: string;
  /** Monotonic revision, so a poller can tell a genuinely new snapshot from a repeat. */
  rev: number;
}

/**
 * Wraps `ControlHandlers.beginPair` in a pollable snapshot + forwardable controls.
 *
 * One controller instance tracks at most one in-flight pairing. `start` replaces
 * any previous one (cancelling it first), mirroring `PairingManager.begin`, which
 * also replaces — two QRs on two screens claimable at once is exactly what the
 * single-session model refuses.
 */
export class PanelPairingController {
  private readonly handlers: Pick<ControlHandlers, 'beginPair'>;
  private handle: { confirm(accept: boolean): void; cancel(): void } | undefined;
  private snapshot: PanelPairingSnapshot = { phase: 'idle', rev: 0 };
  private rev = 0;

  constructor(handlers: Pick<ControlHandlers, 'beginPair'>) {
    this.handlers = handlers;
  }

  /**
   * Open a pairing window.
   *
   * Returns the first snapshot synchronously reachable — but the QR URI arrives
   * asynchronously (relay mode only emits `pair-open` once the rendezvous is
   * registered), so callers should read {@link current} until `uri` is present or
   * the phase is `failed`.
   */
  start(input: { tier: 'default' | 'extended'; relay: boolean }): PanelPairingSnapshot {
    // Replace any previous window. `beginPair`'s own `pairing.begin()` already
    // replaces the session; cancelling here also tears down the previous relay
    // rendezvous so an abandoned Mode B window does not linger.
    this.handle?.cancel();

    this.rev += 1;
    this.snapshot = { phase: 'open', tier: input.tier, relay: input.relay, rev: this.rev };

    this.handle = this.handlers.beginPair(input, (message: ControlResponse) => this.ingest(message, input));
    return this.snapshot;
  }

  /** The latest snapshot. `idle` before the first `start`. */
  current(): PanelPairingSnapshot {
    return this.snapshot;
  }

  /** Forward the operator's SAS decision. No-op if nothing is awaiting it. */
  confirm(accept: boolean): { ok: boolean; message: string } {
    if (this.handle === undefined || this.snapshot.phase !== 'claimed') {
      return { ok: false, message: 'no pairing is awaiting confirmation' };
    }
    this.handle.confirm(accept);
    return { ok: true, message: accept ? 'confirmed' : 'declined' };
  }

  /** Cancel an in-flight window. Idempotent. */
  cancel(): { ok: boolean; message: string } {
    if (this.handle === undefined) return { ok: false, message: 'no pairing in flight' };
    // A terminal snapshot (done/failed) means the window already closed; cancelling
    // is a no-op but still clears our handle.
    const wasTerminal = this.snapshot.phase === 'done' || this.snapshot.phase === 'failed';
    this.handle.cancel();
    this.handle = undefined;
    if (!wasTerminal) {
      this.rev += 1;
      this.snapshot = { phase: 'idle', rev: this.rev };
    }
    return { ok: true, message: 'cancelled' };
  }

  /** Whether a window is open or awaiting confirmation right now. */
  isActive(): boolean {
    return this.snapshot.phase === 'open' || this.snapshot.phase === 'claimed';
  }

  /** Translate one `beginPair` emission into the next snapshot. */
  private ingest(message: ControlResponse, input: { tier: 'default' | 'extended'; relay: boolean }): void {
    this.rev += 1;
    const base = { tier: input.tier, relay: input.relay, rev: this.rev };
    switch (message.type) {
      case 'pair-open':
        // `message.token` is dropped on purpose: the panel renders `uri`, which
        // already carries the token, and a second copy is a second thing to leak.
        this.snapshot = { ...base, phase: 'open', uri: message.uri, expiresAt: message.expiresAt };
        break;
      case 'pair-claimed':
        this.snapshot = {
          ...base,
          phase: 'claimed',
          // Keep the URI so the QR stays on screen while the operator compares.
          ...(this.snapshot.uri === undefined ? {} : { uri: this.snapshot.uri }),
          sas: message.sas,
          deviceId: message.deviceId,
          label: message.label,
          expiresAt: message.expiresAt,
        };
        break;
      case 'pair-done':
        this.snapshot = {
          ...base,
          phase: 'done',
          deviceId: message.deviceId,
          label: message.label,
          grantedTier: message.tier,
        };
        // The window is closed; drop the handle so `cancel` after `done` is a no-op
        // that does not undo the completed pairing.
        this.handle = undefined;
        break;
      case 'pair-failed':
        this.snapshot = { ...base, phase: 'failed', reason: message.reason };
        this.handle = undefined;
        break;
      default:
        // `ok`/`error` are not part of the pairing progress vocabulary; ignore them
        // rather than let an unexpected message clobber the snapshot.
        this.rev -= 1;
        break;
    }
  }
}

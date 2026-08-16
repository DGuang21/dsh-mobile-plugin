/**
 * [OUR DESIGN] Management panel API — transport-agnostic core.
 *
 * This is the whole panel surface as pure request→response logic, with no HTTP,
 * no auth, and no knowledge of where it is mounted. `panel/server.ts` wraps it
 * with the loopback + bearer-token fence; tests drive it directly. Splitting it
 * this way means the security wrapper and the business logic are each testable in
 * isolation, and the same logic serves whether the panel ends up on dsh's own
 * listener or a dedicated loopback one.
 *
 * WHAT THIS DELIBERATELY REUSES
 *
 * Every privileged action goes through `ControlHandlers` — the exact surface the
 * owner-only control socket exposes — so the panel can never do anything a local
 * operator with the control socket could not. `status`, `list`, and `revoke` are
 * called unmodified; pairing goes through {@link PanelPairingController}, which
 * wraps `beginPair`. No new authorization path is introduced.
 *
 * WHAT IT NEVER RETURNS
 *
 * - The bridge's private key (it is never in `ControlHandlers` output to begin with).
 * - Raw pairing tokens (the pairing controller drops them; only the QR `uri` is
 *   returned, and only to this already-authenticated local operator).
 * - Access/session tokens or nonces (not present in any handler output).
 *
 * The public bridge key and TLS SPKI pin ARE returned: they are public by
 * construction (a phone pins them from the QR) and the panel needs them to render
 * the same identity the operator would compare.
 */

import type { AuditEntry } from '../audit/log.ts';
import type { ControlHandlers } from '../control.ts';
import { PanelPairingController, type PanelPairingSnapshot } from './pairing.ts';

/** A resolved response: an HTTP status and a JSON-serializable body. */
export interface PanelResponse {
  status: number;
  body: unknown;
}

/** The relay accessors the panel needs. Narrowed from `IdentityStore`. */
export interface PanelIdentity {
  readonly relayUrl: string | undefined;
  setRelayUrl(url: string | undefined): void;
}

/** The audit accessor the panel needs. Narrowed from `AuditLog`. */
export interface PanelAudit {
  tail(count?: number): readonly AuditEntry[];
}

export interface PanelApiOptions {
  /** The owner-only control surface. Every privileged action routes through it. */
  handlers: ControlHandlers;
  /** For relay URL status/set/clear. */
  identity: PanelIdentity;
  /** For the recent-audit view. */
  audit: PanelAudit;
  /** Pull-based pairing, wrapping `handlers.beginPair`. */
  pairing?: PanelPairingController;
}

/** Largest audit page the panel will return in one call. */
const MAX_AUDIT_LIMIT = 200;

export class PanelApi {
  private readonly handlers: ControlHandlers;
  private readonly identity: PanelIdentity;
  private readonly audit: PanelAudit;
  private readonly pairing: PanelPairingController;

  constructor(options: PanelApiOptions) {
    this.handlers = options.handlers;
    this.identity = options.identity;
    this.audit = options.audit;
    this.pairing = options.pairing ?? new PanelPairingController(options.handlers);
  }

  /** Exposed so the server can share one controller (and tests can inspect it). */
  get pairingController(): PanelPairingController {
    return this.pairing;
  }

  // ── GET /status ─────────────────────────────────────────────────────────────

  /**
   * Everything the panel dashboard renders in one call.
   *
   * Built from `handlers.status()` (the control-socket status, already
   * secret-free) plus the on-disk relay value so the panel can show a
   * "restart required" hint when the operator changed the relay while the bridge
   * was running.
   */
  getStatus(): PanelResponse {
    const status = this.handlers.status() as Record<string, unknown>;
    const relay = this.relayView(status);
    return ok({
      ...status,
      relay: {
        ...(typeof status.relay === 'object' && status.relay !== null ? status.relay : {}),
        ...relay,
      },
      pairing: this.pairing.current(),
    });
  }

  // ── GET /devices, POST /devices/revoke ────────────────────────────────────────

  listDevices(): PanelResponse {
    return ok({ devices: this.handlers.list() });
  }

  revokeDevice(deviceId: unknown): PanelResponse {
    if (typeof deviceId !== 'string' || deviceId.length === 0) {
      return err(400, 'bad-request', 'deviceId is required');
    }
    const result = this.handlers.revoke(deviceId);
    if (!result.ok) return err(404, 'not-found', result.message);
    return ok({ message: result.message });
  }

  // ── GET /audit ────────────────────────────────────────────────────────────────

  getAudit(limitRaw: unknown): PanelResponse {
    let limit = 50;
    if (typeof limitRaw === 'string' && limitRaw.length > 0) {
      const parsed = Number(limitRaw);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        return err(400, 'bad-request', 'limit must be a positive integer');
      }
      limit = Math.min(parsed, MAX_AUDIT_LIMIT);
    }
    return ok({ entries: this.audit.tail(limit) });
  }

  // ── Relay URL: GET / PUT / DELETE ─────────────────────────────────────────────

  getRelay(): PanelResponse {
    return ok(this.relayView(this.handlers.status() as Record<string, unknown>));
  }

  /**
   * Set the relay URL the bridge dials.
   *
   * Validation mirrors the CLI `relay` command exactly: `wss://` for a real relay,
   * `ws://` only for loopback testing. The value is persisted; the running bridge
   * does not adopt it until restart, so the response says so rather than implying
   * an immediate effect it cannot deliver.
   *
   * REFUSED WHEN THE RELAY IS EXTERNALLY PINNED. If the running bridge got its
   * relay from plugin config/env or a CLI flag, that pin overrides the on-disk
   * value at every start — so writing to disk here would be a lie: the panel would
   * promise a restart adopts the change when the pin would silently win again. We
   * refuse with 409 and say where the relay is actually controlled, rather than
   * persist a value that can never take effect.
   */
  setRelay(urlRaw: unknown): PanelResponse {
    const pin = this.relayPin();
    if (pin.pinned) return err(409, 'conflict', pinnedMessage(pin.source));
    if (typeof urlRaw !== 'string' || urlRaw.length === 0) {
      return err(400, 'bad-request', 'url is required');
    }
    let parsed: URL;
    try {
      parsed = new URL(urlRaw);
    } catch {
      return err(400, 'bad-request', `not a URL: ${urlRaw}`);
    }
    if (parsed.protocol !== 'wss:' && parsed.protocol !== 'ws:') {
      return err(400, 'bad-request', 'relay URL must be wss:// (ws:// is accepted only for local testing)');
    }
    if (parsed.protocol === 'ws:' && parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
      return err(400, 'bad-request', 'ws:// is only allowed for 127.0.0.1 or localhost; use wss:// for a real relay');
    }
    this.identity.setRelayUrl(urlRaw);
    return ok({ configured: urlRaw, restartRequired: true, message: 'relay set; restart the bridge for it to take effect' });
  }

  clearRelay(): PanelResponse {
    const pin = this.relayPin();
    if (pin.pinned) return err(409, 'conflict', pinnedMessage(pin.source));
    this.identity.setRelayUrl(undefined);
    return ok({ configured: null, restartRequired: true, message: 'relay cleared; restart the bridge for it to take effect' });
  }

  // ── Pairing: POST /pairing (start), GET /pairing, POST /pairing/confirm, DELETE /pairing ──

  startPairing(body: unknown): PanelResponse {
    const record = asRecord(body) ?? {};
    const tierRaw = record.tier;
    if (tierRaw !== undefined && tierRaw !== 'default' && tierRaw !== 'extended') {
      return err(400, 'bad-request', "tier must be 'default' or 'extended'");
    }
    const relayRaw = record.relay;
    if (relayRaw !== undefined && typeof relayRaw !== 'boolean') {
      return err(400, 'bad-request', 'relay must be a boolean');
    }
    const snapshot = this.pairing.start({
      tier: tierRaw === 'extended' ? 'extended' : 'default',
      relay: relayRaw === true,
    });
    // The QR URI may not be present yet (relay mode registers the rendezvous first);
    // the panel polls GET /pairing until `uri` appears or the phase turns `failed`.
    return ok(this.publicPairing(snapshot));
  }

  getPairing(): PanelResponse {
    return ok(this.publicPairing(this.pairing.current()));
  }

  confirmPairing(body: unknown): PanelResponse {
    const record = asRecord(body) ?? {};
    if (typeof record.accept !== 'boolean') {
      return err(400, 'bad-request', 'accept (boolean) is required');
    }
    const result = this.pairing.confirm(record.accept);
    if (!result.ok) return err(409, 'conflict', result.message);
    return ok({ message: result.message, pairing: this.publicPairing(this.pairing.current()) });
  }

  cancelPairing(): PanelResponse {
    const result = this.pairing.cancel();
    if (!result.ok) return err(409, 'conflict', result.message);
    return ok({ message: result.message });
  }

  /**
   * The pairing snapshot as the panel sees it.
   *
   * Identical to the controller's snapshot today — the controller already strips
   * the raw token — but funneled through one method so any future field added to
   * the snapshot has to pass an explicit allow-list decision rather than leak by
   * default.
   */
  private publicPairing(snapshot: PanelPairingSnapshot): PanelPairingSnapshot {
    return snapshot;
  }

  /**
   * The relay block the panel renders and mutates against, folding the running
   * bridge's state together with the on-disk value.
   *
   * `restartRequired` means exactly "a restart would change the active relay". That
   * is true only when the running value differs from what is on disk AND the relay
   * is not externally pinned — because a pin overrides the on-disk value at the next
   * start too, so a restart would not adopt it. Reporting `restartRequired: true`
   * under a pin was the false promise this fixes; `managedExternally` is what the UI
   * shows instead.
   */
  private relayView(status: Record<string, unknown>): {
    active: string | null;
    configured: string | null;
    pinned: boolean;
    source: 'config' | 'env' | 'cli' | null;
    managedExternally: boolean;
    restartRequired: boolean;
  } {
    const running = this.runningRelayUrl(status);
    const configured = this.identity.relayUrl ?? null;
    const pin = this.relayPin(status);
    return {
      active: running,
      configured,
      pinned: pin.pinned,
      source: pin.source,
      managedExternally: pin.pinned,
      restartRequired: !pin.pinned && running !== configured,
    };
  }

  /**
   * Whether the running relay is fixed by config/env or a CLI flag, and by which.
   * Read from `handlers.status().relay`, which the composition root stamps with
   * `pinned`/`source` at build time. A status payload from an older bridge that
   * lacks the fields is treated as not pinned — the panel-editable default.
   */
  private relayPin(status?: Record<string, unknown>): { pinned: boolean; source: 'config' | 'env' | 'cli' | null } {
    const s = status ?? (this.handlers.status() as Record<string, unknown>);
    const relay = s.relay;
    if (typeof relay !== 'object' || relay === null) return { pinned: false, source: null };
    const pinned = (relay as { pinned?: unknown }).pinned === true;
    const sourceRaw = (relay as { source?: unknown }).source;
    const source = sourceRaw === 'config' || sourceRaw === 'env' || sourceRaw === 'cli' ? sourceRaw : null;
    return { pinned, source: pinned ? source : null };
  }

  /** Pull the running bridge's relay URL out of the status payload. */
  private runningRelayUrl(status: Record<string, unknown>): string | null {
    const relay = status.relay;
    if (typeof relay === 'object' && relay !== null && 'url' in relay) {
      const url = (relay as { url: unknown }).url;
      return typeof url === 'string' ? url : null;
    }
    return null;
  }
}

/** Explain a refused relay mutation, naming where the relay is actually set. */
function pinnedMessage(source: 'config' | 'env' | 'cli' | null): string {
  const where =
    source === 'cli'
      ? 'a --relay start flag'
      : source === 'env'
        ? 'an environment variable'
        : 'the plugin/profile configuration';
  return `relay is managed externally (${where}); change it there and restart the bridge`;
}

function ok(value: unknown): PanelResponse {
  return { status: 200, body: { ok: true, value } };
}

function err(status: number, code: string, message: string): PanelResponse {
  return { status, body: { ok: false, error: { code, message } } };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

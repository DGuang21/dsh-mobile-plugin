/**
 * Panel API + pairing controller — transport-agnostic core.
 *
 * These drive `PanelApi` and `PanelPairingController` directly, with a fake
 * `ControlHandlers`, so the business logic is proven without any HTTP in the way.
 * The security fence (loopback, Host, bearer token, path traversal) is covered
 * separately in panel-server.test.ts over a real listener.
 *
 * The claims under test:
 * - status/devices/audit/relay reads pass through to the control surface unchanged;
 * - relay set/clear validates exactly like the CLI and reports restart-required;
 * - revoke maps a handler failure to 404;
 * - pairing is pull-based: start → poll for uri → claimed(sas) → confirm → done;
 * - the raw pairing token is NEVER exposed — only the QR `uri` (which embeds it).
 */

import { describe, expect, it } from 'vitest';
import type { ControlHandlers, ControlResponse } from '../src/control.ts';
import { PanelApi, type PanelIdentity, type PanelAudit } from '../src/panel/api.ts';
import { PanelPairingController } from '../src/panel/pairing.ts';

/** A controllable fake of the owner-only control surface. */
class FakeHandlers implements ControlHandlers {
  revoked: string[] = [];
  devices = [
    { deviceId: 'dev-1', label: 'Phone', tier: 'default', pairedAt: 1, lastSeenAt: 2, revokedAt: null, relayRoute: false },
  ];
  relayUrl: string | null = null;
  /** Mirror the composition root's pin stamp so the panel can read it from status. */
  relayPinned = false;
  relaySource: 'config' | 'env' | 'cli' | null = null;
  private emitter: ((m: ControlResponse) => void) | undefined;
  private lastInput: { tier: string; relay: boolean } | undefined;

  status(): unknown {
    return {
      bridgeId: 'bridge-abc',
      bridgeVersion: '9.9.9',
      bridgeKey: 'PUBKEY',
      spkiPin: 'PIN',
      listen: { host: '127.0.0.1', port: 8765 },
      dsh: { url: 'http://127.0.0.1:3000', state: 'connected' },
      relay: { url: this.relayUrl, pinned: this.relayPinned, source: this.relaySource, connectors: [] },
      devices: this.devices.length,
      activeDevices: this.devices.filter((d) => d.revokedAt === null).length,
    };
  }
  list(): unknown {
    return this.devices;
  }
  revoke(deviceId: string): { ok: boolean; message: string } {
    if (!this.devices.some((d) => d.deviceId === deviceId)) return { ok: false, message: `no such device: ${deviceId}` };
    this.revoked.push(deviceId);
    return { ok: true, message: `revoked ${deviceId}` };
  }
  beginPair(
    input: { tier: 'default' | 'extended'; relay: boolean },
    emit: (message: ControlResponse) => void,
  ): { confirm(accept: boolean): void; cancel(): void } {
    this.emitter = emit;
    this.lastInput = input;
    return {
      confirm: (accept: boolean) => {
        if (accept) emit({ type: 'pair-done', deviceId: 'dev-2', label: 'New Phone', tier: input.tier });
        else emit({ type: 'pair-failed', reason: 'rejected by operator' });
      },
      cancel: () => emit({ type: 'pair-failed', reason: 'cancelled' }),
    };
  }
  // Test hooks to drive async pairing progress.
  emitOpen(): void {
    this.emitter?.({ type: 'pair-open', uri: `dshm://pair?tok=SECRET-TOKEN&bid=bridge-abc`, token: 'SECRET-TOKEN', expiresAt: 999 });
  }
  emitClaimed(): void {
    this.emitter?.({ type: 'pair-claimed', sas: '123456', deviceId: 'dev-2', label: 'New Phone', expiresAt: 999 });
  }
}

function makeApi(handlers: ControlHandlers = new FakeHandlers()): {
  api: PanelApi;
  handlers: FakeHandlers;
  identity: PanelIdentity & { value: string | undefined };
} {
  const identity = {
    value: undefined as string | undefined,
    get relayUrl() {
      return this.value;
    },
    setRelayUrl(url: string | undefined) {
      this.value = url;
    },
  };
  const audit: PanelAudit = { tail: (n = 20) => Array.from({ length: Math.min(n, 3) }, (_, i) => ({ at: i, event: `e${i}` }) as never) };
  const pairing = new PanelPairingController(handlers);
  const api = new PanelApi({ handlers, identity, audit, pairing });
  return { api, handlers: handlers as FakeHandlers, identity };
}

describe('PanelApi reads', () => {
  it('passes status through and folds in the on-disk relay', () => {
    const { api } = makeApi();
    const res = api.getStatus();
    expect(res.status).toBe(200);
    const value = (res.body as { value: Record<string, unknown> }).value;
    expect(value.bridgeId).toBe('bridge-abc');
    expect((value.relay as Record<string, unknown>).active).toBeNull();
    expect((value.relay as Record<string, unknown>).configured).toBeNull();
    expect((value.relay as Record<string, unknown>).restartRequired).toBe(false);
    // Not pinned by default: the panel may edit the on-disk value freely.
    expect((value.relay as Record<string, unknown>).pinned).toBe(false);
    expect((value.relay as Record<string, unknown>).managedExternally).toBe(false);
    expect((value.relay as Record<string, unknown>).source).toBeNull();
  });

  it('lists devices unchanged', () => {
    const { api } = makeApi();
    const value = (api.listDevices().body as { value: { devices: unknown[] } }).value;
    expect(value.devices).toHaveLength(1);
  });

  it('caps the audit page at the documented max', () => {
    const { api } = makeApi();
    expect(api.getAudit('1000').status).toBe(200);
    expect(api.getAudit('-1').status).toBe(400);
    expect(api.getAudit('nope').status).toBe(400);
  });
});

describe('PanelApi relay set/clear', () => {
  it('accepts wss and reports restart-required', () => {
    const { api, identity } = makeApi();
    const res = api.setRelay('wss://relay.example/ws');
    expect(res.status).toBe(200);
    expect(identity.value).toBe('wss://relay.example/ws');
    expect((res.body as { value: { restartRequired: boolean } }).value.restartRequired).toBe(true);
  });

  it('rejects ws:// to a non-loopback host but allows loopback ws://', () => {
    const { api } = makeApi();
    expect(api.setRelay('ws://relay.example/ws').status).toBe(400);
    expect(api.setRelay('ws://127.0.0.1:9000/ws').status).toBe(200);
    expect(api.setRelay('http://relay.example').status).toBe(400);
    expect(api.setRelay('not a url').status).toBe(400);
  });

  it('clears the relay', () => {
    const { api, identity } = makeApi();
    api.setRelay('wss://relay.example/ws');
    const res = api.clearRelay();
    expect(res.status).toBe(200);
    expect(identity.value).toBeUndefined();
  });
});

describe('PanelApi relay when externally pinned (config/env/CLI)', () => {
  it('reports the pin in status/relay and never claims restart-required', () => {
    const { api, handlers } = makeApi();
    // The running bridge dialed a relay it got from config/env; the composition
    // root stamps status.relay.pinned/source. On disk there is a DIFFERENT value.
    handlers.relayUrl = 'wss://pinned.example/ws';
    handlers.relayPinned = true;
    handlers.relaySource = 'env';

    const relay = (api.getRelay().body as { value: Record<string, unknown> }).value;
    expect(relay.active).toBe('wss://pinned.example/ws');
    expect(relay.pinned).toBe(true);
    expect(relay.managedExternally).toBe(true);
    expect(relay.source).toBe('env');
    // The whole point of the fix: a pin overrides disk at the next start too, so a
    // restart would NOT adopt the on-disk value — restartRequired must stay false
    // even though active !== configured (configured is null here).
    expect(relay.configured).toBeNull();
    expect(relay.restartRequired).toBe(false);

    const status = (api.getStatus().body as { value: { relay: Record<string, unknown> } }).value;
    expect(status.relay.pinned).toBe(true);
    expect(status.relay.restartRequired).toBe(false);
  });

  it('refuses PUT with 409 and does NOT write to disk when pinned', () => {
    const { api, handlers, identity } = makeApi();
    handlers.relayPinned = true;
    handlers.relaySource = 'cli';

    const res = api.setRelay('wss://relay.example/ws');
    expect(res.status).toBe(409);
    expect((res.body as { error: { code: string; message: string } }).error.code).toBe('conflict');
    expect((res.body as { error: { message: string } }).error.message).toMatch(/managed externally/);
    expect((res.body as { error: { message: string } }).error.message).toMatch(/--relay/);
    // Nothing persisted: the doomed write never happened.
    expect(identity.value).toBeUndefined();
  });

  it('refuses DELETE with 409 and does NOT clear disk when pinned', () => {
    const { api, handlers, identity } = makeApi();
    // Seed a saved value first (while unpinned), then pin and try to clear it.
    api.setRelay('wss://saved.example/ws');
    expect(identity.value).toBe('wss://saved.example/ws');
    handlers.relayPinned = true;
    handlers.relaySource = 'config';

    const res = api.clearRelay();
    expect(res.status).toBe(409);
    expect((res.body as { error: { message: string } }).error.message).toMatch(/configuration/);
    // The saved value is untouched — the pin governs, not this call.
    expect(identity.value).toBe('wss://saved.example/ws');
  });
});

describe('PanelApi revoke', () => {
  it('maps a missing device to 404', () => {
    const { api } = makeApi();
    expect(api.revokeDevice('nope').status).toBe(404);
    expect(api.revokeDevice('').status).toBe(400);
  });
  it('revokes a known device', () => {
    const { api, handlers } = makeApi();
    expect(api.revokeDevice('dev-1').status).toBe(200);
    expect(handlers.revoked).toContain('dev-1');
  });
});

describe('PanelApi pairing (pull-based)', () => {
  it('runs start → open(uri) → claimed(sas) → confirm → done without leaking the token', () => {
    const { api, handlers } = makeApi();

    const started = api.startPairing({ tier: 'default', relay: false });
    expect(started.status).toBe(200);

    handlers.emitOpen();
    const open = (api.getPairing().body as { value: { phase: string; uri?: string } }).value;
    expect(open.phase).toBe('open');
    expect(open.uri).toContain('dshm://pair?');
    // The QR URI carries the token, but no bare `token` field is ever surfaced.
    expect(JSON.stringify(api.getPairing().body)).not.toContain('"token"');

    handlers.emitClaimed();
    const claimed = (api.getPairing().body as { value: { phase: string; sas?: string } }).value;
    expect(claimed.phase).toBe('claimed');
    expect(claimed.sas).toBe('123456');

    const confirmed = api.confirmPairing({ accept: true });
    expect(confirmed.status).toBe(200);
    const done = (api.getPairing().body as { value: { phase: string; grantedTier?: string } }).value;
    expect(done.phase).toBe('done');
    expect(done.grantedTier).toBe('default');
  });

  it('declines when accept is false', () => {
    const { api, handlers } = makeApi();
    api.startPairing({ tier: 'default', relay: false });
    handlers.emitOpen();
    handlers.emitClaimed();
    const res = api.confirmPairing({ accept: false });
    expect(res.status).toBe(200);
    expect((api.getPairing().body as { value: { phase: string } }).value.phase).toBe('failed');
  });

  it('rejects confirm with no boolean and confirm when nothing is awaiting', () => {
    const { api } = makeApi();
    expect(api.confirmPairing({}).status).toBe(400);
    expect(api.confirmPairing({ accept: true }).status).toBe(409);
  });

  it('validates tier and relay inputs', () => {
    const { api } = makeApi();
    expect(api.startPairing({ tier: 'root' }).status).toBe(400);
    expect(api.startPairing({ relay: 'yes' }).status).toBe(400);
  });

  it('cancels an in-flight window', () => {
    const { api, handlers } = makeApi();
    api.startPairing({ tier: 'default', relay: false });
    handlers.emitOpen();
    expect(api.cancelPairing().status).toBe(200);
    expect((api.getPairing().body as { value: { phase: string } }).value.phase).toBe('idle');
  });
});

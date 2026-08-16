/**
 * Storage policy tests (`docs/FRONTEND_CONTRACT.md` §11).
 *
 * Two things are being guarded, and the second is the one that matters:
 *
 *   1. `validateStoredBridge` rejects records that cannot be used — including the
 *      specific failure this codebase is most exposed to, a Mode B record holding a
 *      rendezvous id where a durable one belongs.
 *   2. **Nothing but the device key and the durable route is ever written.** The
 *      access token is memory-only. The fake keystore below records every key it is
 *      handed, so a future change that persists a token fails here.
 *
 * `expo-secure-store` is mocked because its published source is Flow-typed and
 * cannot be parsed outside a React Native bundler. The mock is also what lets these
 * assertions be about the storage *policy* rather than about the platform.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { readBridge, validateStoredBridge, writeBridge } from '../src/storage';
import { newRoutingId } from '../src/m1/seal';
import { fixedIdentity } from './helpers/identity';

/** Every write the app makes, in order, so the policy can be asserted on it. */
const writes: { key: string; value: string; options?: unknown }[] = [];
const store = new Map<string, string>();

vi.mock('expo-secure-store', () => ({
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'whenUnlockedThisDeviceOnly',
  getItemAsync: async (key: string) => store.get(key) ?? null,
  setItemAsync: async (key: string, value: string, options?: unknown) => {
    writes.push({ key, value, options });
    store.set(key, value);
  },
  deleteItemAsync: async (key: string) => {
    store.delete(key);
  },
}));

// `expo-crypto` is pulled in by identity.ts, which storage.ts does not import — but
// the core does, and this file imports the core's crypto for a real key.
// Both `vi.mock` calls are hoisted above the imports above by vitest, which is what
// makes a static import of the modules under test safe here.
vi.mock('expo-crypto', () => ({
  getRandomBytes: (length: number) => new Uint8Array(length).fill(7),
  getRandomBytesAsync: async (length: number) => new Uint8Array(length).fill(7),
}));

/** A real Ed25519 public key: the validator checks the pin can actually parse. */
const bridgeKey = fixedIdentity(11).publicKey;

function lanRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    mode: 'lan',
    bridgeId: 'bridge-1',
    bridgeName: 'Workstation',
    deviceId: 'device-1',
    bridgeKey,
    scopeTier: 'default',
    baseUrl: 'https://192.168.1.5:8443',
    ...overrides,
  };
}

function relayRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    mode: 'relay',
    bridgeId: 'bridge-1',
    bridgeName: 'Workstation',
    deviceId: 'device-1',
    bridgeKey,
    scopeTier: 'extended',
    relayUrl: 'https://relay.example',
    bridgeRoutingId: newRoutingId(),
    deviceRoutingId: newRoutingId(),
    ...overrides,
  };
}

beforeEach(() => {
  writes.length = 0;
  store.clear();
});

describe('validateStoredBridge', () => {
  it('accepts a complete Mode A record', () => {
    expect(validateStoredBridge(lanRecord())).toMatchObject({ mode: 'lan', baseUrl: 'https://192.168.1.5:8443' });
  });

  it('accepts a complete Mode B record and keeps both routing ids', () => {
    const record = relayRecord();
    const stored = validateStoredBridge(record);
    expect(stored?.bridgeRoutingId).toBe(record.bridgeRoutingId);
    expect(stored?.deviceRoutingId).toBe(record.deviceRoutingId);
  });

  it('rejects a non-object', () => {
    for (const value of [null, undefined, 42, 'paired', []]) {
      expect(validateStoredBridge(value)).toBeUndefined();
    }
  });

  it('rejects an unknown mode', () => {
    expect(validateStoredBridge(lanRecord({ mode: 'bluetooth' }))).toBeUndefined();
    expect(validateStoredBridge(lanRecord({ mode: undefined }))).toBeUndefined();
  });

  it('rejects a missing or malformed pinned bridge key', () => {
    // The pin is the entire basis of Mode B trust. A record that cannot carry it is
    // not a weaker pairing, it is an unusable one.
    expect(validateStoredBridge(lanRecord({ bridgeKey: undefined }))).toBeUndefined();
    expect(validateStoredBridge(lanRecord({ bridgeKey: '' }))).toBeUndefined();
    expect(validateStoredBridge(lanRecord({ bridgeKey: 'not-base64url!!' }))).toBeUndefined();
    // Right encoding, wrong length: 16 bytes where 32 are required.
    expect(validateStoredBridge(lanRecord({ bridgeKey: 'AAAAAAAAAAAAAAAAAAAAAA' }))).toBeUndefined();
  });

  it('rejects an unknown scope tier', () => {
    expect(validateStoredBridge(lanRecord({ scopeTier: 'root' }))).toBeUndefined();
    expect(validateStoredBridge(lanRecord({ scopeTier: undefined }))).toBeUndefined();
  });

  it('rejects a Mode A record with no base URL', () => {
    expect(validateStoredBridge(lanRecord({ baseUrl: undefined }))).toBeUndefined();
  });

  it('keeps the TLS fingerprint on Mode A when present, and tolerates its absence', () => {
    expect(validateStoredBridge(lanRecord({ tlsFingerprint: 'abc' }))?.tlsFingerprint).toBe('abc');
    expect(validateStoredBridge(lanRecord())?.tlsFingerprint).toBeUndefined();
  });

  it('rejects a Mode B record with no relay URL', () => {
    expect(validateStoredBridge(relayRecord({ relayUrl: undefined }))).toBeUndefined();
  });

  it('rejects a Mode B record missing either half of the durable routing pair', () => {
    expect(validateStoredBridge(relayRecord({ bridgeRoutingId: undefined }))).toBeUndefined();
    expect(validateStoredBridge(relayRecord({ deviceRoutingId: undefined }))).toBeUndefined();
  });

  it('rejects a routing id that is not 16 bytes of base64url', () => {
    // This is the shape of the bug this type exists to prevent: a rendezvous id, a
    // truncated id, or a bridge id landing in a routing slot.
    for (const bad of ['', 'short', 'bridge-1', 'AAAA', `${newRoutingId()}=`, `${newRoutingId()}AAAA`]) {
      expect(validateStoredBridge(relayRecord({ bridgeRoutingId: bad }))).toBeUndefined();
      expect(validateStoredBridge(relayRecord({ deviceRoutingId: bad }))).toBeUndefined();
    }
  });

  it('keeps a LAN origin alongside a relay route when the bridge offered one', () => {
    const stored = validateStoredBridge(relayRecord({ baseUrl: 'https://192.168.1.5:8443' }));
    expect(stored?.baseUrl).toBe('https://192.168.1.5:8443');
    expect(stored?.mode).toBe('relay');
  });

  it('drops unknown fields rather than carrying them forward', () => {
    // A record is rebuilt field by field, so a token smuggled into the keystore by
    // an older build does not survive a read.
    const stored = validateStoredBridge(lanRecord({ token: 'leaked-token', extra: 1 }));
    expect(stored).toBeDefined();
    expect(Object.keys(stored as object)).not.toContain('token');
    expect(Object.keys(stored as object)).not.toContain('extra');
  });
});

describe('readBridge / writeBridge', () => {
  it('round-trips a Mode B record', async () => {
    const record = validateStoredBridge(relayRecord());
    expect(record).toBeDefined();
    await writeBridge(record);
    expect(await readBridge()).toEqual(record);
  });

  it('writes only the one bridge key, with device-only keychain protection', async () => {
    await writeBridge(validateStoredBridge(relayRecord()));
    expect(writes).toHaveLength(1);
    expect(writes[0]?.key).toBe('dshm.bridge.v1');
    expect(writes[0]?.options).toEqual({ keychainAccessible: 'whenUnlockedThisDeviceOnly' });
  });

  it('never writes an access token, in any field', async () => {
    // The policy assertion. The token lives in `M1Core` memory and has no path here.
    await writeBridge(validateStoredBridge(relayRecord()));
    const persisted = writes.map((entry) => entry.value).join('\n');
    expect(persisted).not.toMatch(/token/i);
  });

  it('strips a smuggled token instead of serializing whatever it was handed', async () => {
    // `writeBridge` persists the validated projection, not its argument, so a caller
    // that spread a session into the record cannot leak it to the keychain. The cast is
    // the point: the type system already forbids this, and this is the runtime backstop.
    await writeBridge({
      ...(validateStoredBridge(relayRecord()) as NonNullable<ReturnType<typeof validateStoredBridge>>),
      token: 'super-secret-access-token',
      tokenExpiresAt: 9_999_999,
    } as never);

    const persisted = writes.map((entry) => entry.value).join('\n');
    expect(persisted).not.toMatch(/super-secret-access-token/);
    expect(persisted).not.toMatch(/token/i);
    // And the record is still usable: stripping is not corrupting.
    expect(await readBridge()).toMatchObject({ mode: 'relay' });
  });

  it('refuses to store an incomplete record instead of writing a dead route', async () => {
    await expect(writeBridge({ mode: 'relay', bridgeId: 'b' } as never)).rejects.toThrow(/incomplete/);
    expect(writes).toHaveLength(0);
  });

  it('deletes on undefined', async () => {
    await writeBridge(validateStoredBridge(relayRecord()));
    await writeBridge(undefined);
    expect(await readBridge()).toBeUndefined();
  });

  it('reads undefined for absent, unparseable, and structurally invalid entries', async () => {
    expect(await readBridge()).toBeUndefined();
    store.set('dshm.bridge.v1', '{not json');
    expect(await readBridge()).toBeUndefined();
    // Valid JSON, invalid record: a Mode B route whose durable ids were lost.
    store.set('dshm.bridge.v1', JSON.stringify(relayRecord({ bridgeRoutingId: undefined })));
    expect(await readBridge()).toBeUndefined();
  });
});

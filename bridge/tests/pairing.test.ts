import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  generateEd25519KeyPair,
  signMessage,
  toBase64Url,
} from '../src/identity/crypto.ts';
import {
  PAIRING_TOKEN_TTL_MS,
  PairingManager,
  buildPairingUri,
  computeSas,
  pairingProofMessage,
  parsePairingUri,
} from '../src/identity/pairing.ts';
import { DeviceRegistry } from '../src/identity/registry.ts';

const BRIDGE_ID = 'bridge-abc123';
const BRIDGE_NAME = 'daguang-macbook';

/** A phone: an Ed25519 keypair plus the ability to produce a pairing proof. */
function makeDevice() {
  const keys = generateEd25519KeyPair();
  return {
    publicKey: keys.publicKeyB64,
    proofFor: (token: string, bridgeId = BRIDGE_ID) =>
      toBase64Url(signMessage(keys.privateKey, pairingProofMessage(token, bridgeId))),
  };
}

function setup(options: { now?: () => number; dshUp?: boolean; registry?: DeviceRegistry } = {}) {
  const registry = options.registry ?? DeviceRegistry.inMemory();
  const manager = new PairingManager({
    registry,
    bridgeId: BRIDGE_ID,
    bridgeName: BRIDGE_NAME,
    isDshReachable: () => options.dshUp ?? true,
    now: options.now,
    tokenFactory: () => 'dGVzdC10b2tlbi0zMi1ieXRlcy1mb3ItcGFpcmluZw',
  });
  return { registry, manager };
}

describe('pairing token', () => {
  it('is single-use: a replayed claim fails even inside the TTL', () => {
    const { manager } = setup();
    const device = makeDevice();
    const session = manager.begin();

    const first = manager.claim({
      token: session.token,
      devicePublicKey: device.publicKey,
      label: 'Pixel 8',
      proof: device.proofFor(session.token),
    });
    expect(first.ok).toBe(true);

    // Same valid token, same valid proof, immediately after: must fail.
    const replay = manager.claim({
      token: session.token,
      devicePublicKey: device.publicKey,
      label: 'Pixel 8',
      proof: device.proofFor(session.token),
    });
    expect(replay).toEqual({ ok: false, reason: 'token-consumed' });
  });

  it('is consumed even when the proof fails, so an attacker gets one attempt', () => {
    const { manager } = setup();
    const attacker = makeDevice();
    const realPhone = makeDevice();
    const session = manager.begin();

    // Attacker photographed the QR but signs with the wrong key relationship:
    // they sign a different bridgeId, so the proof does not verify.
    const bad = manager.claim({
      token: session.token,
      devicePublicKey: attacker.publicKey,
      label: 'attacker',
      proof: attacker.proofFor(session.token, 'some-other-bridge'),
    });
    expect(bad).toEqual({ ok: false, reason: 'bad-proof' });

    // The window is now closed for everyone, including the legitimate phone.
    const legitimate = manager.claim({
      token: session.token,
      devicePublicKey: realPhone.publicKey,
      label: 'Pixel 8',
      proof: realPhone.proofFor(session.token),
    });
    expect(legitimate.ok).toBe(false);
  });

  it('expires after 120 seconds', () => {
    let now = 1_000_000;
    const { manager } = setup({ now: () => now });
    const device = makeDevice();
    const session = manager.begin();

    now += PAIRING_TOKEN_TTL_MS + 1;

    expect(
      manager.claim({
        token: session.token,
        devicePublicKey: device.publicKey,
        label: 'Pixel 8',
        proof: device.proofFor(session.token),
      }),
    ).toEqual({ ok: false, reason: 'token-expired' });
    expect(PAIRING_TOKEN_TTL_MS).toBe(120_000);
  });

  it('rejects a wrong token without revealing the right one', () => {
    const { manager } = setup();
    const device = makeDevice();
    manager.begin();

    const wrongToken = toBase64Url(Buffer.alloc(32, 7));
    expect(
      manager.claim({
        token: wrongToken,
        devicePublicKey: device.publicKey,
        label: 'Pixel 8',
        proof: device.proofFor(wrongToken),
      }),
    ).toEqual({ ok: false, reason: 'token-unknown' });
  });

  it('refuses to pair when dsh is unreachable', () => {
    const { manager } = setup({ dshUp: false });
    const device = makeDevice();
    const session = manager.begin();

    expect(
      manager.claim({
        token: session.token,
        devicePublicKey: device.publicKey,
        label: 'Pixel 8',
        proof: device.proofFor(session.token),
      }),
    ).toEqual({ ok: false, reason: 'dsh-unavailable' });
  });

  it('rejects a malformed public key', () => {
    const { manager } = setup();
    const session = manager.begin();

    for (const publicKey of ['', 'not base64url!!', toBase64Url(Buffer.alloc(16))]) {
      expect(
        manager.claim({ token: session.token, devicePublicKey: publicKey, label: 'x', proof: 'AAAA' }).ok,
      ).toBe(false);
    }
  });
});

describe('SAS confirmation', () => {
  it('requires operator confirmation before the device is registered', () => {
    const { manager, registry } = setup();
    const device = makeDevice();
    const session = manager.begin();

    const claim = manager.claim({
      token: session.token,
      devicePublicKey: device.publicKey,
      label: 'Pixel 8',
      proof: device.proofFor(session.token),
    });
    expect(claim.ok).toBe(true);

    // A successful claim alone must not register anything.
    expect(registry.list()).toHaveLength(0);
    expect(manager.isAwaitingConfirmation()).toBe(true);

    const record = manager.confirm();
    expect(record?.label).toBe('Pixel 8');
    expect(registry.list()).toHaveLength(1);
    expect(registry.getActive(record!.deviceId)).toBeDefined();
  });

  it('registers nothing when the operator rejects the SAS', () => {
    const { manager, registry } = setup();
    const device = makeDevice();
    const session = manager.begin();

    manager.claim({
      token: session.token,
      devicePublicKey: device.publicKey,
      label: 'Pixel 8',
      proof: device.proofFor(session.token),
    });
    manager.reject();

    expect(manager.confirm()).toBeUndefined();
    expect(registry.list()).toHaveLength(0);
  });

  it('binds the SAS to the device key, so a substituted key shows a different code', () => {
    const realPhone = makeDevice();
    const attacker = makeDevice();
    const token = 'a-token';

    const realSas = computeSas(token, BRIDGE_ID, realPhone.publicKey);
    const attackerSas = computeSas(token, BRIDGE_ID, attacker.publicKey);

    expect(realSas).not.toBe(attackerSas);
    expect(realSas).toMatch(/^\d{6}$/);
    // And it is bound to the bridge identity too.
    expect(computeSas(token, 'other-bridge', realPhone.publicKey)).not.toBe(realSas);
  });

  it('is deterministic for the same triple', () => {
    const device = makeDevice();
    expect(computeSas('t', BRIDGE_ID, device.publicKey)).toBe(computeSas('t', BRIDGE_ID, device.publicKey));
  });

  it('refuses a second registration of an already-paired key', () => {
    const { manager } = setup();
    const device = makeDevice();

    const first = manager.begin();
    manager.claim({
      token: first.token,
      devicePublicKey: device.publicKey,
      label: 'Pixel 8',
      proof: device.proofFor(first.token),
    });
    manager.confirm();

    const second = manager.begin();
    expect(
      manager.claim({
        token: second.token,
        devicePublicKey: device.publicKey,
        label: 'Pixel 8 again',
        proof: device.proofFor(second.token),
      }),
    ).toEqual({ ok: false, reason: 'already-paired' });
  });
});

describe('pairing proof domain separation', () => {
  it('a proof for one bridge does not verify for another', () => {
    const { manager } = setup();
    const device = makeDevice();
    const session = manager.begin();

    // Signed against a different bridgeId: the domain-separated message differs.
    expect(
      manager.claim({
        token: session.token,
        devicePublicKey: device.publicKey,
        label: 'Pixel 8',
        proof: device.proofFor(session.token, 'different-bridge'),
      }),
    ).toEqual({ ok: false, reason: 'bad-proof' });
  });

  it('length-prefixes parts so concatenations cannot collide', () => {
    // "ab"+"c" must not produce the same message as "a"+"bc".
    expect(pairingProofMessage('ab', 'c').equals(pairingProofMessage('a', 'bc'))).toBe(false);
  });
});

describe('pairing URI', () => {
  it('round-trips a Mode A (LAN) payload', () => {
    const uri = buildPairingUri({
      bridgeId: BRIDGE_ID,
      token: 'tok123',
      fingerprint: 'fp-spki-sha256',
      bridgeKey: 'bridge-pub',
    });
    expect(uri.startsWith('dshm://pair?')).toBe(true);
    expect(parsePairingUri(uri)).toEqual({
      version: '1',
      bridgeId: BRIDGE_ID,
      token: 'tok123',
      bridgeKey: 'bridge-pub',
      fingerprint: 'fp-spki-sha256',
    });
  });

  it('round-trips a Mode B (relay) payload including the pinned bridge key', () => {
    const uri = buildPairingUri({
      bridgeId: BRIDGE_ID,
      token: 'tok123',
      relay: 'https://relay.example',
      routingId: 'rid-xyz',
      bridgeKey: 'bridge-pub',
    });
    const parsed = parsePairingUri(uri);
    expect(parsed?.relay).toBe('https://relay.example');
    expect(parsed?.routingId).toBe('rid-xyz');
    // Mode B still pins the bridge key: a relay cannot substitute its identity.
    expect(parsed?.bridgeKey).toBe('bridge-pub');
  });

  it('refuses an unknown version or a missing field rather than guessing', () => {
    expect(parsePairingUri('dshm://pair?v=2&bid=b&tok=t&bk=k')).toBeUndefined();
    expect(parsePairingUri('dshm://pair?v=1&bid=b&tok=t')).toBeUndefined();
    expect(parsePairingUri('https://evil.example/pair?v=1')).toBeUndefined();
  });
});

describe('device registry persistence', () => {
  it('writes the registry 0600 and reloads it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dshm-registry-'));
    const registry = DeviceRegistry.open(dir);
    const device = makeDevice();

    const record = registry.register({ publicKey: device.publicKey, label: 'Pixel 8' });

    const filePath = join(dir, 'devices.json');
    expect(statSync(filePath).mode & 0o777).toBe(0o600);

    const reloaded = DeviceRegistry.open(dir);
    expect(reloaded.getActive(record.deviceId)?.label).toBe('Pixel 8');
  });

  it('refuses a hand-edited registry whose deviceId does not match its key', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dshm-registry-'));
    const registry = DeviceRegistry.open(dir);
    const device = makeDevice();
    registry.register({ publicKey: device.publicKey, label: 'Pixel 8' });

    const filePath = join(dir, 'devices.json');
    const file = JSON.parse(readFileSync(filePath, 'utf8')) as { devices: { deviceId: string }[] };
    file.devices[0]!.deviceId = 'attacker-chosen-id';
    writeFileSync(filePath, JSON.stringify(file));

    expect(() => DeviceRegistry.open(dir)).toThrowError(/does not match its public key/);
  });

  it('derives the deviceId from the key rather than trusting a caller', () => {
    const registry = DeviceRegistry.inMemory();
    const a = makeDevice();
    const b = makeDevice();
    const first = registry.register({ publicKey: a.publicKey, label: 'a' });
    const second = registry.register({ publicKey: b.publicKey, label: 'b' });
    expect(first.deviceId).not.toBe(second.deviceId);
    // Stable across registries.
    expect(DeviceRegistry.inMemory().register({ publicKey: a.publicKey, label: 'x' }).deviceId).toBe(first.deviceId);
  });
});

describe('revocation', () => {
  it('is immediate and notifies listeners so live streams can be dropped', () => {
    const registry = DeviceRegistry.inMemory();
    const device = makeDevice();
    const record = registry.register({ publicKey: device.publicKey, label: 'Pixel 8' });

    const dropped: string[] = [];
    registry.onRevocation((deviceId) => dropped.push(deviceId));

    expect(registry.revoke(record.deviceId)).toBe(true);
    // The listener ran as part of the revoke call, not later.
    expect(dropped).toEqual([record.deviceId]);
    expect(registry.getActive(record.deviceId)).toBeUndefined();
    // The record survives for status output, marked revoked.
    expect(registry.get(record.deviceId)?.revokedAt).toBeTypeOf('number');
  });

  it('is idempotent', () => {
    const registry = DeviceRegistry.inMemory();
    const device = makeDevice();
    const record = registry.register({ publicKey: device.publicKey, label: 'Pixel 8' });
    expect(registry.revoke(record.deviceId)).toBe(true);
    expect(registry.revoke(record.deviceId)).toBe(false);
    expect(registry.revoke('never-existed')).toBe(false);
  });

  it('lets a revoked key pair again', () => {
    const registry = DeviceRegistry.inMemory();
    const { manager } = setup({ registry });
    const device = makeDevice();

    const first = manager.begin();
    manager.claim({
      token: first.token,
      devicePublicKey: device.publicKey,
      label: 'Pixel 8',
      proof: device.proofFor(first.token),
    });
    const record = manager.confirm()!;
    registry.revoke(record.deviceId);

    const second = manager.begin();
    expect(
      manager.claim({
        token: second.token,
        devicePublicKey: device.publicKey,
        label: 'Pixel 8 re-paired',
        proof: device.proofFor(second.token),
      }).ok,
    ).toBe(true);
  });
});

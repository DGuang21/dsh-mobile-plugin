/**
 * [OUR DESIGN] Device registry.
 *
 * Holds one record per paired phone. The registry file is the workstation's
 * record of who may talk to the bridge, so it is written `0600` and every write
 * is atomic (write-temp-then-rename) — a torn registry file would either lock the
 * user out or, worse, resurrect a revoked device.
 *
 * Revocation is immediate: it flips state, persists, and fires a listener so live
 * streams for that device are dropped. A revocation that only took effect at the
 * next auth attempt would leave an attacker's existing stream running.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { deviceIdFromPublicKey, fromBase64Url, ED25519_PUBLIC_KEY_BYTES } from './crypto.ts';
import type { ScopeTier } from '../policy/methods.ts';

export interface DeviceRecord {
  deviceId: string;
  /** base64url raw Ed25519 public key. */
  publicKey: string;
  /** User-facing label, e.g. "Pixel 8". Never trusted for authorization. */
  label: string;
  tier: ScopeTier;
  allowSlashCommands: boolean;
  createdAt: number;
  lastSeenAt: number | undefined;
  revokedAt: number | undefined;
}

/** Registry file shape. Versioned so a future format change is detectable. */
interface RegistryFile {
  v: 1;
  devices: DeviceRecord[];
}

export interface RegisterDeviceInput {
  publicKey: string;
  label: string;
  tier?: ScopeTier;
  allowSlashCommands?: boolean;
}

export type RevocationListener = (deviceId: string) => void;

export class DeviceRegistry {
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly revocationListeners = new Set<RevocationListener>();

  private readonly filePath: string | undefined;

  // Written out longhand rather than as a parameter property: parameter properties
  // need type-directed emit, which `node --experimental-strip-types` refuses.
  private constructor(filePath: string | undefined) {
    this.filePath = filePath;
  }

  /** In-memory registry, for tests and for a `--ephemeral` bridge. */
  static inMemory(): DeviceRegistry {
    return new DeviceRegistry(undefined);
  }

  /** Load from disk, creating an empty registry when the file is absent. */
  static open(stateDir: string): DeviceRegistry {
    const filePath = join(stateDir, 'devices.json');
    const registry = new DeviceRegistry(filePath);
    if (existsSync(filePath)) registry.load();
    return registry;
  }

  private load(): void {
    if (this.filePath === undefined) return;
    const raw = readFileSync(this.filePath, 'utf8');
    const parsed = JSON.parse(raw) as RegistryFile;
    if (parsed.v !== 1) {
      throw new Error(`unsupported device registry version: ${String(parsed.v)}`);
    }
    for (const device of parsed.devices) {
      // Re-derive the id rather than trusting the file: a hand-edited registry
      // must not be able to bind a label or tier to a key it does not own.
      const derived = deviceIdFromPublicKey(device.publicKey);
      if (derived === undefined || derived !== device.deviceId) {
        throw new Error(`device registry entry has a deviceId that does not match its public key: ${device.deviceId}`);
      }
      this.devices.set(device.deviceId, device);
    }
  }

  private persist(): void {
    if (this.filePath === undefined) return;
    const dir = dirname(this.filePath);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file: RegistryFile = { v: 1, devices: [...this.devices.values()] };
    const temp = `${this.filePath}.tmp`;
    // 0600 from creation, never a wider mode even briefly.
    writeFileSync(temp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
    renameSync(temp, this.filePath);
    chmodSync(this.filePath, 0o600);
  }

  /** Fires when a device is revoked, so transports can drop its live streams. */
  onRevocation(listener: RevocationListener): () => void {
    this.revocationListeners.add(listener);
    return () => this.revocationListeners.delete(listener);
  }

  /**
   * Register a newly paired device. The `deviceId` is always derived from the
   * public key, never supplied by the caller.
   */
  register(input: RegisterDeviceInput): DeviceRecord {
    const raw = fromBase64Url(input.publicKey);
    if (raw === undefined || raw.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new Error('device public key must be a base64url raw 32-byte Ed25519 key');
    }
    const deviceId = deviceIdFromPublicKey(input.publicKey);
    if (deviceId === undefined) throw new Error('could not derive a deviceId from the public key');

    const label = input.label.trim().slice(0, 64) || 'unnamed device';
    const record: DeviceRecord = {
      deviceId,
      publicKey: input.publicKey,
      label,
      tier: input.tier ?? 'default',
      allowSlashCommands: input.allowSlashCommands ?? true,
      createdAt: Date.now(),
      lastSeenAt: undefined,
      revokedAt: undefined,
    };
    this.devices.set(deviceId, record);
    this.persist();
    return record;
  }

  /** An active (non-revoked) device, or `undefined`. */
  getActive(deviceId: string): DeviceRecord | undefined {
    const record = this.devices.get(deviceId);
    if (record === undefined || record.revokedAt !== undefined) return undefined;
    return record;
  }

  /** Any record, including revoked, for status output. */
  get(deviceId: string): DeviceRecord | undefined {
    return this.devices.get(deviceId);
  }

  list(): DeviceRecord[] {
    return [...this.devices.values()].sort((a, b) => a.createdAt - b.createdAt);
  }

  has(deviceId: string): boolean {
    return this.devices.has(deviceId);
  }

  /** Look up by public key, to detect a device re-pairing with the same key. */
  findByPublicKey(publicKey: string): DeviceRecord | undefined {
    return [...this.devices.values()].find((device) => device.publicKey === publicKey);
  }

  touch(deviceId: string): void {
    const record = this.devices.get(deviceId);
    if (record === undefined) return;
    record.lastSeenAt = Date.now();
    this.persist();
  }

  /**
   * Revoke a device. Idempotent, and returns whether this call was the one that
   * performed the revocation, so a CLI can report honestly.
   */
  revoke(deviceId: string): boolean {
    const record = this.devices.get(deviceId);
    if (record === undefined || record.revokedAt !== undefined) return false;
    record.revokedAt = Date.now();
    this.persist();
    // Notify before returning so streams are dropped as part of this call.
    for (const listener of this.revocationListeners) {
      try {
        listener(deviceId);
      } catch (error) {
        console.error('[bridge:identity] revocation listener threw:', error);
      }
    }
    return true;
  }

  updatePolicy(deviceId: string, changes: { tier?: ScopeTier; allowSlashCommands?: boolean }): DeviceRecord | undefined {
    const record = this.getActive(deviceId);
    if (record === undefined) return undefined;
    if (changes.tier !== undefined) record.tier = changes.tier;
    if (changes.allowSlashCommands !== undefined) record.allowSlashCommands = changes.allowSlashCommands;
    this.persist();
    return record;
  }
}

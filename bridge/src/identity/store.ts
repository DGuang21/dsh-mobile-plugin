/**
 * Persistent bridge identity.
 *
 * Three things must survive a restart or every phone would have to re-pair:
 *   - the bridge id, which is bound into every pairing and auth proof
 *   - the bridge's static Ed25519 keypair, which a phone pins at pairing and which
 *     authenticates the relay tunnel
 *   - per-device relay routing ids, which are agreed at pairing time
 *
 * The private key is written at mode 0600 in a 0700 directory and never leaves the
 * process. It is stored raw rather than PEM-encrypted: a passphrase the daemon must
 * supply at every start is a passphrase that ends up in a shell script, and the
 * threat this would defend against — an attacker who can already read the file as
 * this user — can also read the running process.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { dirname, join } from 'node:path';
import {
  fromBase64Url,
  generateEd25519KeyPair,
  privateKeyFromRaw,
  rawFromPrivateKey,
  toBase64Url,
} from './crypto.ts';
import { newRoutingId } from '../relay/seal.ts';
import { isValidRoutingId } from '../relay/protocol.ts';

/** One paired device's relay routing pair. */
export interface RelayRoute {
  /** Our routing id for this device's tunnel. */
  routingId: string;
  /** The device's routing id. */
  peerRoutingId: string;
  /** The device's static Ed25519 public key, base64url raw. Pinned at pairing. */
  peerStaticPublicKey: string;
}

interface IdentityFile {
  v: 1;
  bridgeId: string;
  /** base64url raw Ed25519 private key (32 bytes). */
  sk: string;
  /** base64url raw Ed25519 public key (32 bytes). */
  pk: string;
  /** Relay origin this bridge dials, if relay mode is configured. */
  relayUrl?: string;
  /** deviceId → routing pair. */
  routes?: Record<string, RelayRoute>;
}

export interface BridgeIdentity {
  bridgeId: string;
  publicKeyB64: string;
  privateKey: KeyObject;
}

export class IdentityStore {
  private file: IdentityFile;
  private readonly path: string;
  private privateKeyObject: KeyObject | undefined;

  private constructor(path: string, file: IdentityFile) {
    this.path = path;
    this.file = file;
  }

  /**
   * Load the identity, generating one on first run.
   *
   * Generation is the common first-run path, so it is not treated as exceptional —
   * but an existing file with an unknown version is, because silently rewriting it
   * would orphan every paired phone.
   */
  static open(stateDir: string): IdentityStore {
    const path = join(stateDir, 'identity.json');
    if (existsSync(path)) {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as IdentityFile;
      if (parsed.v !== 1) throw new Error(`unsupported identity file version: ${String(parsed.v)}`);
      if (typeof parsed.bridgeId !== 'string' || typeof parsed.sk !== 'string' || typeof parsed.pk !== 'string') {
        throw new Error('identity file is missing required fields');
      }
      return new IdentityStore(path, parsed);
    }

    const keys = generateEd25519KeyPair();
    const store = new IdentityStore(path, {
      v: 1,
      bridgeId: randomUUID(),
      sk: toBase64Url(rawFromPrivateKey(keys.privateKey)),
      pk: keys.publicKeyB64,
      routes: {},
    });
    store.persist();
    return store;
  }

  get bridgeId(): string {
    return this.file.bridgeId;
  }

  get publicKeyB64(): string {
    return this.file.pk;
  }

  /** The Ed25519 private key, imported once and cached. */
  privateKey(): KeyObject {
    if (this.privateKeyObject !== undefined) return this.privateKeyObject;
    const raw = fromBase64Url(this.file.sk);
    if (raw === undefined) throw new Error('identity private key is not valid base64url');
    const key = privateKeyFromRaw(raw);
    if (key === undefined) throw new Error('identity private key is not a valid Ed25519 key');
    this.privateKeyObject = key;
    return key;
  }

  identity(): BridgeIdentity {
    return { bridgeId: this.bridgeId, publicKeyB64: this.publicKeyB64, privateKey: this.privateKey() };
  }

  get relayUrl(): string | undefined {
    return this.file.relayUrl;
  }

  setRelayUrl(url: string | undefined): void {
    if (url === undefined) delete this.file.relayUrl;
    else this.file.relayUrl = url;
    this.persist();
  }

  routes(): Record<string, RelayRoute> {
    return { ...(this.file.routes ?? {}) };
  }

  routeFor(deviceId: string): RelayRoute | undefined {
    return this.file.routes?.[deviceId];
  }

  /**
   * Record a device's relay route, minting our side's routing id.
   *
   * A fresh routing id per device is deliberate: a shared id would let one paired
   * phone observe another's tunnel metadata at the relay.
   */
  addRoute(deviceId: string, input: { peerRoutingId: string; peerStaticPublicKey: string }): RelayRoute {
    // Validated here rather than only at the call site: this value is written to
    // disk and later fed to the relay connector, which refuses to dial a malformed
    // id — a rejection that would surface long after the pairing that caused it.
    if (!isValidRoutingId(input.peerRoutingId)) {
      throw new Error('peerRoutingId must be a 22-character base64url routing id');
    }
    const routes = this.file.routes ?? {};
    const route: RelayRoute = {
      routingId: routes[deviceId]?.routingId ?? newRoutingId(),
      peerRoutingId: input.peerRoutingId,
      peerStaticPublicKey: input.peerStaticPublicKey,
    };
    routes[deviceId] = route;
    this.file.routes = routes;
    this.persist();
    return route;
  }

  removeRoute(deviceId: string): void {
    if (this.file.routes?.[deviceId] === undefined) return;
    delete this.file.routes[deviceId];
    this.persist();
  }

  /** Atomic write: a truncated identity file would be unrecoverable. */
  private persist(): void {
    const dir = dirname(this.path);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(this.file, null, 2)}\n`, { mode: 0o600 });
    renameSync(temporary, this.path);
    // rename preserves the temp file's mode, but be explicit: this file is a
    // private key.
    chmodSync(this.path, 0o600);
  }
}

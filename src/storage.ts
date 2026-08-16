/**
 * Durable pairing state, in the platform keystore.
 *
 * Storage policy (`docs/FRONTEND_CONTRACT.md` §11), and the whole of it:
 *
 *   - **Device private key** — `expo-secure-store`, written by `src/m1/identity.ts`.
 *   - **Durable route** — `expo-secure-store`, this file. What is needed to find
 *     and authenticate the bridge again: its id, name, pinned keys, and for Mode B
 *     the durable routing pair.
 *   - **Access token** — memory only, never here. It has a 15-minute TTL and is
 *     re-minted from the device key on demand, so persisting it would add a
 *     stealable credential and buy nothing.
 *   - **Message history** — not persisted by the core at all; it is re-fetched
 *     from the bridge, which is the only authority on it.
 *
 * A stored record is validated on read rather than trusted. It is attacker-adjacent
 * in one narrow sense — a keystore entry can be corrupted or partially written —
 * and a half-valid route produces confusing connection failures rather than an
 * honest "not paired".
 */

import * as SecureStore from 'expo-secure-store';
import { isValidEd25519PublicKey } from './m1/crypto';
import { isValidRoutingId } from './m1/seal';
import type { ConnectionMode, ScopeTier } from './m1/types';

const BRIDGE_KEY = 'dshm.bridge.v1';

/**
 * Everything needed to reconnect to one bridge, and nothing else.
 *
 * The two routing ids are named for who they address, because the previous
 * `routingId`/`peerRoutingId` pair was ambiguous from the phone's side and that
 * ambiguity is exactly how a rendezvous id ends up stored as a durable one.
 */
export type StoredBridge = {
  /** Which transport this pairing uses. Decided at pairing, not per connection. */
  mode: ConnectionMode;
  bridgeId: string;
  bridgeName: string;
  deviceId: string;
  /** base64url raw Ed25519 bridge static key, pinned from the QR's `bk`. */
  bridgeKey: string;
  scopeTier: ScopeTier;
  /** Mode A: the bridge's HTTPS origin. */
  baseUrl?: string;
  /** Mode A: base64url SHA-256 of the TLS SPKI to pin (the QR's `fp`). */
  tlsFingerprint?: string;
  /** Mode B: the relay origin to dial. */
  relayUrl?: string;
  /**
   * Mode B: the bridge's DURABLE routing id, from the sealed claim response.
   *
   * Never the QR's `rid`, which is a rendezvous id scoped to one pairing attempt.
   */
  bridgeRoutingId?: string;
  /** Mode B: this phone's own durable routing id, minted locally at pairing. */
  deviceRoutingId?: string;
};

export async function readBridge(): Promise<StoredBridge | undefined> {
  const raw = await SecureStore.getItemAsync(BRIDGE_KEY);
  if (raw === null) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  return validateStoredBridge(parsed);
}

export async function writeBridge(value: StoredBridge | undefined): Promise<void> {
  if (value === undefined) {
    await SecureStore.deleteItemAsync(BRIDGE_KEY);
    return;
  }
  // Validate on the way out too. A route this app cannot read back is worse than
  // no route: it would present as paired and fail every connection.
  const projected = validateStoredBridge(value);
  if (projected === undefined) throw new Error('refusing to store an incomplete bridge record');
  // The *projection* is what gets written, not the argument. `validateStoredBridge`
  // rebuilds the record from known fields only, so this is what makes "nothing but the
  // durable route is persisted" a structural property rather than a convention: a
  // caller that spread an access token into the record cannot leak it to the keystore.
  await SecureStore.setItemAsync(BRIDGE_KEY, JSON.stringify(projected), {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

/**
 * Structural validation of a stored record.
 *
 * Exported for tests, which is why it takes `unknown`: the interesting cases are
 * the malformed ones.
 */
export function validateStoredBridge(value: unknown): StoredBridge | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;

  const mode = record.mode;
  if (mode !== 'lan' && mode !== 'relay') return undefined;
  if (!isNonEmptyString(record.bridgeId)) return undefined;
  if (!isNonEmptyString(record.bridgeName)) return undefined;
  if (!isNonEmptyString(record.deviceId)) return undefined;
  // The pin is the whole basis of trust in Mode B, and is checked against the
  // bridge's signature in Mode A too. A record whose pin will not parse can never
  // authenticate anything.
  if (!isNonEmptyString(record.bridgeKey) || !isValidEd25519PublicKey(record.bridgeKey)) return undefined;
  if (record.scopeTier !== 'default' && record.scopeTier !== 'extended') return undefined;

  const stored: StoredBridge = {
    mode,
    bridgeId: record.bridgeId,
    bridgeName: record.bridgeName,
    deviceId: record.deviceId,
    bridgeKey: record.bridgeKey,
    scopeTier: record.scopeTier,
  };

  if (mode === 'lan') {
    // Without an origin there is nothing to dial. The QR is gone by now, so this
    // record is unusable.
    if (!isNonEmptyString(record.baseUrl)) return undefined;
    stored.baseUrl = record.baseUrl;
    if (isNonEmptyString(record.tlsFingerprint)) stored.tlsFingerprint = record.tlsFingerprint;
  } else {
    if (!isNonEmptyString(record.relayUrl)) return undefined;
    // Both halves of the durable pair are required: the bridge's id is where to
    // send, ours is what to register, and one without the other cannot connect.
    if (!isValidRoutingId(record.bridgeRoutingId)) return undefined;
    if (!isValidRoutingId(record.deviceRoutingId)) return undefined;
    stored.relayUrl = record.relayUrl;
    stored.bridgeRoutingId = record.bridgeRoutingId;
    stored.deviceRoutingId = record.deviceRoutingId;
    // A relay pairing may also carry a LAN origin: the same bridge is often
    // reachable directly at home. Optional, and never required to connect.
    if (isNonEmptyString(record.baseUrl)) stored.baseUrl = record.baseUrl;
  }

  return stored;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

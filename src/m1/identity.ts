/**
 * [OUR DESIGN] Device key storage, and the only expo-coupled module in the core.
 *
 * Two jobs, both deliberately isolated here so `crypto.ts`, `seal.ts` and
 * `core.ts` stay importable under plain Node (which is what makes the cross-tree
 * integration test possible — `expo-secure-store` throws on import outside RN):
 *
 *   1. Install an `expo-crypto`-backed CSPRNG, because Hermes has no
 *      `crypto.getRandomValues`. Done at import time so no protocol code can run
 *      before a real entropy source exists.
 *   2. Load or create the Ed25519 device key in the platform keystore.
 *
 * **The device private key is the only secret this app persists.** Per
 * `docs/FRONTEND_CONTRACT.md` §11 the access token is memory-only, which
 * `core.ts` enforces by never handing it to a store.
 */

import * as SecureStore from 'expo-secure-store';
import * as ExpoCrypto from 'expo-crypto';
import { fromBase64Url, toBase64Url } from './bytes';
import {
  ED25519_PRIVATE_KEY_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
  type DeviceIdentity,
  deviceIdFromPublicKey,
  ed25519PublicKeyFromSeed,
  setRandomSource,
} from './crypto';

const PRIVATE_KEY = 'dshm.device.private.v1';
const PUBLIC_KEY = 'dshm.device.public.v1';

/**
 * `WHEN_UNLOCKED_THIS_DEVICE_ONLY`: the key must not ride an iCloud keychain
 * backup to another device, because a device identity that can be restored
 * elsewhere is not a device identity.
 */
const KEYCHAIN_OPTIONS = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY } as const;

// Installed eagerly: `import './identity'` is enough to make the core's RNG real
// on a phone. `getRandomBytes` is the sync variant, which is what `randomBytes`
// needs — every ephemeral and routing id is minted on a synchronous path.
setRandomSource((length) => ExpoCrypto.getRandomBytes(length));

export type { DeviceIdentity };

/**
 * Load the device identity, creating it on first run.
 *
 * A stored pair that fails validation is replaced rather than repaired: a
 * half-written keystore entry would otherwise produce signatures no bridge can
 * verify, which looks like a protocol bug rather than a storage fault. Replacing
 * it costs a re-pair, and the alternative is an app that can never recover.
 */
export async function loadOrCreateIdentity(): Promise<DeviceIdentity> {
  const [storedPrivate, storedPublic] = await Promise.all([
    SecureStore.getItemAsync(PRIVATE_KEY),
    SecureStore.getItemAsync(PUBLIC_KEY),
  ]);

  if (storedPrivate !== null && storedPublic !== null) {
    const existing = validateStoredPair(storedPrivate, storedPublic);
    if (existing !== undefined) return existing;
  }

  // `getRandomBytesAsync` on creation: this is the one moment worth waiting for
  // the platform's best entropy path.
  const seed = await ExpoCrypto.getRandomBytesAsync(ED25519_PRIVATE_KEY_BYTES);
  const publicKey = toBase64Url(ed25519PublicKeyFromSeed(seed));
  const deviceId = deviceIdFromPublicKey(publicKey);
  if (deviceId === undefined) throw new Error('failed to derive a device id for the new key');

  await Promise.all([
    SecureStore.setItemAsync(PRIVATE_KEY, toBase64Url(seed), KEYCHAIN_OPTIONS),
    SecureStore.setItemAsync(PUBLIC_KEY, publicKey, KEYCHAIN_OPTIONS),
  ]);
  return { publicKey, privateKey: seed, deviceId };
}

/**
 * Both halves must be present, the right length, and mutually consistent.
 *
 * The derivation check is the important one: a public key that does not follow
 * from the stored seed means one of the two writes was lost, and trusting the
 * stored public half would make every proof verify against a key the bridge does
 * not have.
 */
function validateStoredPair(privateEncoded: string, publicEncoded: string): DeviceIdentity | undefined {
  const seed = fromBase64Url(privateEncoded);
  const publicKey = fromBase64Url(publicEncoded);
  if (seed === undefined || seed.byteLength !== ED25519_PRIVATE_KEY_BYTES) return undefined;
  if (publicKey === undefined || publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES) return undefined;

  let derived: string;
  try {
    derived = toBase64Url(ed25519PublicKeyFromSeed(seed));
  } catch {
    return undefined;
  }
  if (derived !== publicEncoded) return undefined;

  const deviceId = deviceIdFromPublicKey(publicEncoded);
  if (deviceId === undefined) return undefined;
  return { publicKey: publicEncoded, privateKey: seed, deviceId };
}

/**
 * Destroy the device key.
 *
 * Deliberately NOT called on revocation: a revoked device that keeps its key can
 * re-pair with the same identity, which is the friendlier outcome and leaks
 * nothing — the bridge decides what a key is allowed to do. This exists for an
 * explicit "forget this device" action.
 */
export async function destroyIdentity(): Promise<void> {
  await Promise.all([SecureStore.deleteItemAsync(PRIVATE_KEY), SecureStore.deleteItemAsync(PUBLIC_KEY)]);
}

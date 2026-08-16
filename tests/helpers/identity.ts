/**
 * Test-only device identities.
 *
 * The app mints its key inside `src/m1/identity.ts`, which is expo-coupled on
 * purpose. Tests need the same shape without the keystore, so they build it from
 * the same primitives the app uses — `ed25519PublicKeyFromSeed` and
 * `deviceIdFromPublicKey` — rather than hard-coding a fixture. A stale fixture
 * would keep passing after a change to the derivation.
 */

import { deviceIdFromPublicKey, ed25519PublicKeyFromSeed, randomBytes, type DeviceIdentity } from '../../src/m1/crypto';
import { toBase64Url } from '../../src/m1/bytes';

/**
 * A fresh Ed25519 device identity.
 *
 * Pass `seed` for a deterministic one; a test that asserts on a device id needs the
 * key to be stable across runs.
 */
export function testIdentity(seed: Uint8Array = randomBytes(32)): DeviceIdentity {
  const publicKey = toBase64Url(ed25519PublicKeyFromSeed(seed));
  const deviceId = deviceIdFromPublicKey(publicKey);
  if (deviceId === undefined) throw new Error('test seed produced an invalid device id');
  return { publicKey, privateKey: seed, deviceId };
}

/** A deterministic identity, so failures reproduce. */
export function fixedIdentity(fill = 3): DeviceIdentity {
  return testIdentity(new Uint8Array(32).fill(fill));
}

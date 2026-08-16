/**
 * Guards the one piece of deliberate duplication in the codebase.
 *
 * `src/m1/paths.ts` (RN app, ESM for Metro) and `bridge/src/m1/wire.ts` (Node)
 * declare the same wire constants. They are separate files so the RN bundle
 * never resolves anything under `bridge/`. This test is the reason that is safe:
 * it runs under the root vitest, which can import both trees, and fails if they
 * drift.
 */

import { describe, expect, it } from 'vitest';
// Extensionless, matching the app tree's convention: this file is typechecked by
// the root tsconfig, which does not enable allowImportingTsExtensions.
import * as bridge from '../bridge/src/m1/wire';
import * as app from '../src/m1/paths';

describe('m1 wire constants', () => {
  it('agree on the protocol version', () => {
    expect(bridge.M1_PROTOCOL_VERSION).toBe(app.M1_PROTOCOL_VERSION);
  });

  it('agree on every endpoint path', () => {
    expect(bridge.M1_PATHS).toEqual(app.M1_PATHS);
  });

  it('agree on the stream subprotocols', () => {
    expect(bridge.M1_STREAM_SUBPROTOCOL).toBe(app.M1_STREAM_SUBPROTOCOL);
    expect(bridge.M1_TOKEN_SUBPROTOCOL_PREFIX).toBe(app.M1_TOKEN_SUBPROTOCOL_PREFIX);
    expect(bridge.M1_PAIRING_URI_SCHEME).toBe(app.M1_PAIRING_URI_SCHEME);
  });

  it('agree on the closed error-code set', () => {
    expect([...bridge.M1_BRIDGE_ERROR_CODES]).toEqual([...app.M1_BRIDGE_ERROR_CODES]);
  });

  it('maps every error code to an HTTP status', () => {
    for (const code of app.M1_BRIDGE_ERROR_CODES) {
      const status = bridge.BRIDGE_ERROR_STATUS[code];
      expect(status, `missing status for ${code}`).toBeGreaterThanOrEqual(400);
      expect(status).toBeLessThan(600);
    }
    expect(Object.keys(bridge.BRIDGE_ERROR_STATUS).sort()).toEqual([...app.M1_BRIDGE_ERROR_CODES].sort());
  });

  it('keeps the paths under the /m1 namespace', () => {
    for (const path of Object.values(app.M1_PATHS)) {
      expect(path.startsWith('/m1/')).toBe(true);
    }
  });
});

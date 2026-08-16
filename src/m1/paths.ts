/**
 * [OUR DESIGN] `m1` runtime constants for the React Native app.
 *
 * Mirrored by `bridge/src/m1/wire.ts`; `tests/m1-contract.test.ts` asserts the
 * two are identical. The duplication is deliberate: it keeps the RN bundle from
 * resolving anything under `bridge/`, which is Node-only code.
 */

/** Bumped only on a breaking change to the `m1` envelopes. */
export const M1_PROTOCOL_VERSION = 1;

export const M1_PATHS = {
  pairClaim: '/m1/pair/claim',
  authSession: '/m1/auth/session',
  rpc: '/m1/rpc',
  stream: '/m1/stream',
  respond: '/m1/respond',
  health: '/m1/health',
} as const;

/** WebSocket subprotocols for `/m1/stream`. The token never goes in the URL. */
export const M1_STREAM_SUBPROTOCOL = 'dshm.v1';
export const M1_TOKEN_SUBPROTOCOL_PREFIX = 'dshm.token.';

/** Pairing URI scheme carried by the QR code. */
export const M1_PAIRING_URI_SCHEME = 'dshm:';

/** Closed set of bridge error codes, as runtime values for exhaustive UI mapping. */
export const M1_BRIDGE_ERROR_CODES = [
  'unauthenticated',
  'method-denied',
  'device-revoked',
  'bad-request',
  'payload-too-large',
  'rate-limited',
  'dsh-unavailable',
  'dsh-protocol-error',
  'pairing-invalid',
  'pairing-unconfirmed',
  'pairing-rejected',
  'internal',
] as const;

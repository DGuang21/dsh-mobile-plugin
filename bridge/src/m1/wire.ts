/**
 * [OUR DESIGN] `m1` runtime constants for the bridge (Node side).
 *
 * Mirror of `src/m1/paths.ts`. `tests/m1-contract.test.ts` (run by the root
 * vitest, which can import both trees) asserts they are identical, so a change
 * to one that is not made to the other fails CI rather than shipping a bridge
 * that answers on paths the app does not call.
 */

export const M1_PROTOCOL_VERSION = 1;

export const M1_PATHS = {
  pairClaim: '/m1/pair/claim',
  authSession: '/m1/auth/session',
  rpc: '/m1/rpc',
  stream: '/m1/stream',
  respond: '/m1/respond',
  health: '/m1/health',
} as const;

export const M1_STREAM_SUBPROTOCOL = 'dshm.v1';
export const M1_TOKEN_SUBPROTOCOL_PREFIX = 'dshm.token.';
export const M1_PAIRING_URI_SCHEME = 'dshm:';

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

/** HTTP status for each bridge error code. Single source for the whole server. */
export const BRIDGE_ERROR_STATUS: Record<(typeof M1_BRIDGE_ERROR_CODES)[number], number> = {
  unauthenticated: 401,
  'method-denied': 403,
  'device-revoked': 403,
  'bad-request': 400,
  'payload-too-large': 413,
  'rate-limited': 429,
  'dsh-unavailable': 503,
  'dsh-protocol-error': 502,
  'pairing-invalid': 400,
  'pairing-unconfirmed': 409,
  'pairing-rejected': 403,
  internal: 500,
};

/**
 * [OUR DESIGN] Runtime predicates and labels over {@link M1ClientState}.
 *
 * Separate from `types.ts` because that file must stay free of value exports: the
 * bridge compiles it under `verbatimModuleSyntax` with CommonJS resolution, where
 * a top-level value export is TS1287. Keeping the split explicit means a helper
 * added here can never break `npm run typecheck:bridge`.
 */

import type { M1ClientState } from './types';

/**
 * True when the state will not change again without user action.
 *
 * The core stops all retries in these states, so a UI should offer a way out —
 * re-pair, or unpair — rather than a spinner that will never resolve.
 */
export function isTerminalState(state: M1ClientState): boolean {
  switch (state.name) {
    case 'revoked':
    case 'pin-mismatch':
    case 'rendezvous-busy':
    case 'routing-collision':
      return true;
    case 'unpaired':
      // A fresh install is not terminal: scanning a QR moves it along. A refusal
      // is, in the sense that the same QR will never work again.
      return state.reason !== undefined && state.reason !== 'fresh';
    default:
      return false;
  }
}

/** True while the core is working toward a live stream and will get there on its own. */
export function isTransientState(state: M1ClientState): boolean {
  switch (state.name) {
    case 'connecting':
    case 'reconnecting':
    case 'relay-unavailable':
    case 'resyncing':
    case 'paired':
      return true;
    default:
      return false;
  }
}

/** True when the core can serve RPCs right now. */
export function isOnline(state: M1ClientState): boolean {
  return state.name === 'ready' || state.name === 'harness-offline' || state.name === 'resyncing';
}

/**
 * A short operator-readable label.
 *
 * Provided so every consumer does not reinvent a switch over 15 members, and so
 * the wording for the security-relevant states is written once, here, rather than
 * softened accidentally in a component. Not localized — a UI that needs
 * translation should switch on `state.name` itself.
 */
export function describeState(state: M1ClientState): string {
  switch (state.name) {
    case 'unpaired':
      switch (state.reason) {
        case 'pairing-rejected':
          return 'Pairing was declined on the workstation';
        case 'pairing-invalid':
          return 'That pairing code was expired or already used';
        case 'cleared':
          return 'Not paired';
        default:
          return 'Not paired';
      }
    case 'scanning':
      return 'Scanning for a pairing code';
    case 'pairing':
      return state.mode === 'relay' ? 'Pairing over the relay' : 'Pairing on the local network';
    case 'awaiting-confirmation':
      return `Confirm ${state.sas} on ${state.bridgeName}`;
    case 'paired':
      return `Paired with ${state.bridgeName}`;
    case 'connecting':
      switch (state.phase) {
        case 'relay':
          return 'Connecting to the relay';
        case 'sealing':
          return 'Verifying the workstation';
        case 'authenticating':
          return 'Signing in';
        default:
          return 'Opening the live stream';
      }
    case 'ready':
      return state.dsh === 'up' ? 'Connected' : 'Connected, harness offline';
    case 'reconnecting':
      return 'Reconnecting';
    case 'harness-offline':
      return 'Workstation reachable, harness offline';
    case 'relay-unavailable':
      return 'Relay unavailable';
    case 'rendezvous-busy':
      return 'That pairing code is busy — open a new one on the workstation';
    case 'routing-collision':
      return 'Relay address already in use — re-pair to get a new one';
    case 'resyncing':
      return 'Catching up on history';
    case 'revoked':
      return 'This device was removed on the workstation';
    case 'pin-mismatch':
      switch (state.detail) {
        case 'tls-fingerprint':
          return 'The workstation certificate did not match. Do not continue.';
        case 'bridge-identity':
          return 'A different workstation answered. Do not continue.';
        default:
          return 'The workstation key did not match. Do not continue.';
      }
  }
}

/**
 * [OUR DESIGN] The `m1` mobile wire protocol — client-facing types.
 *
 * This file is the contract between the bridge and the React Native app. It is
 * deliberately node-free (no Buffer, no node: imports) so the RN bundle can
 * import it directly, and deliberately separate from bridge/src/dsh/types.ts so
 * an upstream dsh change cannot silently reshape the phone's contract.
 *
 * See docs/FRONTEND_CONTRACT.md for the narrative version, the state machine and
 * worked examples.
 */

/**
 * This file declares **types only**, on purpose. The bridge imports these with
 * `import type`, which costs nothing at runtime and lets both trees share one
 * definition without the RN bundle ever reaching into `bridge/`.
 *
 * Runtime constants (paths, subprotocol names, version number) live in
 * `src/m1/paths.ts` for the app and `bridge/src/m1/wire.ts` for the bridge;
 * `tests/m1-contract.test.ts` asserts the two agree, so they cannot drift.
 */

// ── errors ──────────────────────────────────────────────────────────────────

/**
 * Closed set of bridge-level error codes. Distinct from dsh's `RpcErrorCode`:
 * a `BridgeErrorCode` is about the bridge refusing or being unable to act, while
 * a dsh error is a business outcome that reached the harness.
 */
export type BridgeErrorCode =
  /** No/!valid token, or the token expired. HTTP 401. */
  | 'unauthenticated'
  /** Method on the hard deny list, or outside the device's scope tier. HTTP 403. */
  | 'method-denied'
  /** Device revoked on the workstation. HTTP 403. */
  | 'device-revoked'
  /** Malformed envelope, unknown method, or a failed structural check. HTTP 400. */
  | 'bad-request'
  /** Payload over a documented limit. HTTP 413. */
  | 'payload-too-large'
  /** Too many requests from this device. HTTP 429. */
  | 'rate-limited'
  /** dsh is not reachable or not ready. HTTP 503. */
  | 'dsh-unavailable'
  /** dsh answered, but not in a shape the contract allows. HTTP 502. */
  | 'dsh-protocol-error'
  /** Pairing token unknown, expired, or already consumed. HTTP 400. */
  | 'pairing-invalid'
  /** The operator has not confirmed the SAS yet. HTTP 409. */
  | 'pairing-unconfirmed'
  /** The operator rejected the pairing at the workstation. HTTP 403. */
  | 'pairing-rejected'
  /** Unexpected bridge fault. HTTP 500. */
  | 'internal';

export interface BridgeError {
  code: BridgeErrorCode;
  message: string;
  /** Present on `method-denied` so the UI can name the capability limit. */
  method?: string;
  /** Present on `rate-limited` and `dsh-unavailable`: hint in milliseconds. */
  retryAfterMs?: number;
}

/** Envelope for every non-stream response body. */
export type M1Response<T> = { ok: true; value: T } | { ok: false; error: BridgeError };

// ── pairing ─────────────────────────────────────────────────────────────────

/** `POST /m1/pair/claim` request. */
export interface PairClaimRequest {
  v: 1;
  /** From the QR/numeric code. Single-use, 120 s TTL. */
  token: string;
  /** base64url raw 32-byte Ed25519 public key. */
  devicePublicKey: string;
  /** Human label shown on the workstation, e.g. "Pixel 8". */
  label: string;
  /** base64url Ed25519 signature over the domain-separated pairing message. */
  proof: string;
}

/**
 * `POST /m1/pair/claim` success.
 *
 * The claim is accepted but NOT yet trusted: `sas` must be read aloud/compared
 * and confirmed by the operator at the workstation. The phone polls or retries
 * the claim; only after confirmation does the device exist in the registry.
 */
export interface PairClaimAccepted {
  status: 'awaiting-confirmation';
  /** 6-digit short authentication string, bound to token + bridge + device key. */
  sas: string;
  /** Shown on the phone so the user knows which workstation answered. */
  bridgeName: string;
  bridgeId: string;
  /** Deadline for the operator to confirm. */
  expiresAt: number;
}

export interface PairClaimConfirmed {
  status: 'paired';
  deviceId: string;
  bridgeId: string;
  bridgeName: string;
  scopeTier: ScopeTier;
  /** base64url SHA-256 of the bridge's TLS SPKI; the phone pins this. */
  bridgeKeyFingerprint?: string;
  /**
   * Mode B only: the durable routing pair, added by the relay rendezvous.
   *
   * This is the ONLY place a durable `bridgeRoutingId` comes from. It arrives
   * inside the sealed channel, so the relay cannot forge or observe it, and it
   * replaces the QR's short-lived rendezvous id for every future connection.
   */
  relay?: PairedRelayRoute;
}

/**
 * The durable relay route assigned at pairing.
 *
 * `peerRoutingId` is the phone's own id, echoed back so the phone can confirm
 * the bridge registered the id it actually asked for. `bridgeRoutingId` is the
 * bridge's durable id — distinct from the QR's `rid`, which is a rendezvous id
 * and is dead the moment pairing completes.
 */
export interface PairedRelayRoute {
  /** Durable id the bridge will register at the relay from now on. */
  bridgeRoutingId: string;
  /** The phone's own durable id, as the bridge recorded it. */
  peerRoutingId: string;
}

export type PairClaimResult = PairClaimAccepted | PairClaimConfirmed;

/**
 * Capability tiers, matching `bridge/src/policy/methods.ts`.
 *
 * `default` is the documented allow-list. `extended` additionally permits the
 * opt-in workspace/host methods and must be granted explicitly at the
 * workstation. Neither tier can reach a denied method — that list is hard.
 */
export type ScopeTier = 'default' | 'extended';

/** Parsed `dshm://pair` QR payload. */
export interface PairingUri {
  v: 1;
  /** Bridge instance id, stable across restarts. */
  bid: string;
  /** One-shot pairing token. */
  tok: string;
  /** base64url raw Ed25519 bridge public key; pinned by the phone. */
  bk: string;
  /** Mode A: base64url SHA-256 of the TLS SPKI to pin. */
  fp?: string;
  /** Mode B: relay origin (https) the phone should dial instead. */
  relay?: string;
  /**
   * Mode B: the **rendezvous** routing id for this pairing attempt.
   *
   * NOT a durable address, and never persisted. It is derived from the pairing
   * token (`sha256(domain('pair-rendezvous', token, bridgeId))[0..16]`), lives as
   * long as the pairing window (≤120 s), and serves exactly one pairing. The
   * phone recomputes it from `tok` and `bid` and refuses a QR where the two
   * disagree, since a mismatch means the QR was assembled by something other than
   * the bridge that owns the token.
   *
   * The durable id arrives later, inside the sealed claim response, as
   * {@link PairedRelayRoute.bridgeRoutingId}.
   */
  rid?: string;
}

/** Which transport a pairing URI selects. */
export type ConnectionMode = 'lan' | 'relay';

// ── auth ────────────────────────────────────────────────────────────────────

/** `POST /m1/auth/session` step 1. */
export interface AuthChallengeRequest {
  v: 1;
  deviceId: string;
}

export interface AuthChallengeResponse {
  /** base64url nonce. Single-use, 60 s TTL, bound to this device. */
  nonce: string;
  bridgeId: string;
  expiresAt: number;
}

/** `POST /m1/auth/session` step 2. */
export interface AuthProveRequest {
  v: 1;
  deviceId: string;
  nonce: string;
  /** base64url Ed25519 signature over the domain-separated auth message. */
  signature: string;
}

export interface AuthSession {
  /** Opaque bearer token. In-memory on both ends; 15 min TTL. */
  token: string;
  expiresAt: number;
  deviceId: string;
  scopeTier: ScopeTier;
  /** Methods this device may call right now. Drives UI affordances. */
  allowedMethods: readonly string[];
  /** False when the operator disabled mobile slash commands for this device. */
  slashCommandsEnabled: boolean;
}

// ── rpc ─────────────────────────────────────────────────────────────────────

/**
 * `POST /m1/rpc`. The bridge mints the dsh `rpcId`; the phone never supplies one.
 * `requestId` is the phone's own correlation id and is echoed untouched.
 */
export interface M1RpcRequest {
  v: 1;
  method: string;
  payload: unknown;
  requestId?: string;
}

/**
 * A dsh business error, passed through unchanged.
 *
 * Kept structurally separate from `BridgeError` so the UI can tell "the harness
 * said no" from "the bridge would not ask".
 */
export interface DshBusinessError {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export type M1RpcResult =
  | { ok: true; requestId?: string; value: unknown }
  | { ok: false; requestId?: string; error: BridgeError }
  | { ok: false; requestId?: string; dshError: DshBusinessError };

// ── respond ─────────────────────────────────────────────────────────────────

/**
 * `POST /m1/respond`. `rpcId` is echoed verbatim from the answerable frame; the
 * bridge rejects an `rpcId` that is not currently pending for this device.
 *
 * Only `allowed-once` and `rejected` are sendable for approvals — there is no
 * "always allow" on mobile, by design.
 *
 * There is deliberately no slot for `sessionId` or `approvalId`. The bridge takes
 * the correlation ids from the frame it delivered, because dsh re-checks them
 * against its own pending entry: an answer that named them itself could be
 * attributed to a session the device was never shown.
 */
export type M1RespondRequest =
  | { v: 1; rpcId: string; kind: 'approval'; outcome: 'allowed-once' | 'rejected' }
  | { v: 1; rpcId: string; kind: 'question'; answers: QuestionAnswer[] };

/**
 * One answer in a question batch.
 *
 * Send one per question in the frame, in the same order, `id` matching. dsh answers
 * an `ask()` as a whole batch and never per question, so a partial array is a 400.
 *
 * The bridge sorts `value` into the two slots upstream expects: a value equal to one
 * of the question's `options[].label` becomes a selection, anything else non-blank
 * becomes free text. Several labels, or labels plus one free-text value, are allowed
 * only when the question set `multiSelect`. Capped at 32 KiB of UTF-8 per answer,
 * over which the reply is `payload-too-large` rather than `bad-request`.
 */
export interface QuestionAnswer {
  /** `id` of the `AskUserQuestionItem` being answered. */
  id: string;
  /** Free text, or the chosen option label(s). */
  value: string | string[];
}

/**
 * Result of answering. `already-resolved` is a benign state, not an error: dsh
 * `respond` is single-shot, and a late answer legitimately returns `not-pending`.
 */
export type M1RespondResult =
  | { status: 'accepted' }
  | { status: 'already-resolved' }
  | { status: 'rejected'; reason: 'bad-response' };

// ── stream ──────────────────────────────────────────────────────────────────

/** Our control frames. `kind: 'bridge'` never collides with a dsh frame type. */
export type M1BridgeFrame =
  | { type: 'resync-required'; reason: 'window-overflow' | 'dsh-restarted' }
  | { type: 'dsh-disconnected'; error?: string }
  | { type: 'dsh-ready'; generation: number }
  | { type: 'token-expiring'; expiresAt: number }
  | { type: 'device-revoked' }
  | { type: 'pong'; at: number };

/**
 * Stream envelope.
 *
 * `bseq` is bridge-assigned and monotonic; it is NOT dsh's per-session `seq` and
 * the two must never be compared. Persist the highest `bseq` seen and send it as
 * `?after=` on reconnect.
 *
 * `frame` is intentionally `unknown` here: mux/host frame vocabularies are
 * upstream's and will grow. Fold unknown `frame.type` to a generic card, never a
 * crash.
 */
export interface M1StreamEnvelope {
  v: 1;
  bseq: number;
  kind: 'mux' | 'host' | 'bridge';
  /** Present on answerable frames; echo it verbatim to `/m1/respond`. */
  rpcId?: string;
  frame: unknown;
}

/**
 * First message on `/m1/stream`, before any frames.
 *
 * `resync: true` means the requested `after` was outside the retention window.
 * The phone must discard derived state and re-baseline via the official dsh
 * procedure (`session.list`, `workspace.list`, `session.history` per open
 * session) rather than trusting a partial delta.
 */
export interface M1StreamHello {
  v: 1;
  kind: 'hello';
  bridgeId: string;
  /** Rotated token; replaces the one used to connect. */
  token: string;
  tokenExpiresAt: number;
  lastBseq: number;
  resync: boolean;
  /** Number of pending answerable frames replayed immediately after this. */
  pendingCount: number;
}

/** Client→server messages on `/m1/stream`. The stream is not an RPC channel. */
export type M1StreamClientMessage =
  | { v: 1; kind: 'ping'; at: number }
  /** Acknowledge processed frames so the bridge can log the cursor. */
  | { v: 1; kind: 'ack'; bseq: number };

// ── health ──────────────────────────────────────────────────────────────────

export interface M1Health {
  ok: boolean;
  protocol: number;
  bridgeId: string;
  bridgeName: string;
  bridgeVersion: string;
  /** `up` requires both dsh downlinks open AND a successful `host.describe`. */
  dsh: 'up' | 'down' | 'connecting';
  dshState: 'idle' | 'connecting' | 'connected' | 'reconnecting';
  uptimeSeconds: number;
  pairedDevices: number;
  /** Present only when a pairing window is currently open. */
  pairingOpen?: boolean;
}

// ── relay ───────────────────────────────────────────────────────────────────

/**
 * Closed set of relay error codes, mirroring `bridge/src/relay/protocol.ts`.
 *
 * The relay is untrusted, so these are treated as hints about the transport and
 * never as statements about the bridge. `routing-id-taken` is the only one that
 * will not fix itself by waiting.
 */
export type RelayErrorCode =
  /** Malformed control frame. Our bug, or a relay that is not a relay. */
  | 'bad-message'
  /** Something else holds the routing id we asked for. Will not self-heal. */
  | 'routing-id-taken'
  /** We sent data before registering. Our bug. */
  | 'not-registered'
  /** The named peer is not connected right now. Transient. */
  | 'peer-offline'
  /** Frame rate or size quota exceeded. Back off. */
  | 'quota-exceeded'
  /** Too many phones are already claiming this rendezvous. */
  | 'rendezvous-busy'
  /** Relay fault. */
  | 'internal';

// ── client state machine ────────────────────────────────────────────────────

/**
 * The phone's top-level state, exhaustive by design.
 *
 * Every failure mode in `docs/FRONTEND_CONTRACT.md` lands in exactly one member,
 * so a UI that handles all of them cannot be surprised. Three of them are
 * terminal and must never auto-retry: `revoked`, `pin-mismatch`, and a
 * `unpaired` carrying `reason: 'pairing-rejected'`.
 */
export type M1ClientState =
  /** No stored pairing. `reason` distinguishes a fresh install from a refusal. */
  | { name: 'unpaired'; reason?: UnpairedReason }
  /** The camera is open; nothing has been claimed yet. */
  | { name: 'scanning' }
  /**
   * A pairing URI is being claimed. `mode` tells the UI whether this is a LAN
   * claim or a relay rendezvous, which is the difference between "check you are
   * on the same Wi-Fi" and "check the workstation is online".
   */
  | { name: 'pairing'; mode: ConnectionMode; bridgeName?: string }
  /**
   * Claim accepted, waiting for the operator to confirm the SAS at the
   * workstation. `sas` must be displayed; `expiresAt` bounds the wait.
   */
  | { name: 'awaiting-confirmation'; sas: string; bridgeName: string; expiresAt: number }
  /**
   * Pairing completed, or a stored pairing was loaded, but there is no live
   * session yet. The device key re-authenticates silently from here — the user is
   * never asked to pair again.
   */
  | { name: 'paired'; bridgeName: string }
  /** Working through auth, tunnel setup and stream open. */
  | { name: 'connecting'; attempt: number; phase: ConnectingPhase }
  /** Live stream. `lastBseq` is what a reconnect resumes from. */
  | { name: 'ready'; lastBseq: number; dsh: 'up' | 'down' }
  /**
   * Transient: radio loss, backgrounding, bridge restart. `nextRetryAt` is a
   * wall-clock deadline so the UI can count down; `reason` is a short
   * human-readable cause, already free of secrets.
   */
  | { name: 'reconnecting'; attempt: number; nextRetryAt: number; reason?: string }
  /** Bridge reachable but dsh is not. Local history stays rendered. */
  | { name: 'harness-offline' }
  /**
   * Mode B only: the relay itself is unreachable or refusing. The bridge may be
   * perfectly healthy — this is a statement about the middle of the path.
   */
  | { name: 'relay-unavailable'; attempt: number; nextRetryAt: number; code?: RelayErrorCode }
  /**
   * Mode B pairing only: too many phones are claiming this rendezvous. Retrying
   * the same QR will not help; the operator should open a fresh pairing window.
   */
  | { name: 'rendezvous-busy' }
  /**
   * Mode B only: the relay says our routing id is already held. Since the relay
   * never evicts an incumbent, this needs a new id, which means re-pairing.
   */
  | { name: 'routing-collision'; routingId: string }
  /** Retention window overflowed; re-baselining before rendering deltas again. */
  | { name: 'resyncing' }
  /** Terminal until re-paired. The stored route is already gone. */
  | { name: 'revoked' }
  /**
   * Terminal for this bridge: the key that authenticated the path was not the
   * pinned one. Never auto-recover, never offer a "trust anyway" affordance —
   * this is what a man in the middle looks like.
   */
  | { name: 'pin-mismatch'; detail: PinMismatchDetail };

/** Why there is no pairing. */
export type UnpairedReason =
  /** Nothing was ever stored. */
  | 'fresh'
  /** The operator refused at the workstation. Terminal; needs a new QR. */
  | 'pairing-rejected'
  /** The token was unknown, expired or already spent. A new QR will work. */
  | 'pairing-invalid'
  /** The user unpaired deliberately. */
  | 'cleared';

/** Sub-step of `connecting`, for a progress label. */
export type ConnectingPhase =
  /** Mode B: opening the relay socket and registering a routing id. */
  | 'relay'
  /** Mode B: running the sealed handshake. */
  | 'sealing'
  /** Proving the device key and getting a token. */
  | 'authenticating'
  /** Opening the event stream. */
  | 'streaming';

/** Which pin failed, so the UI can say something true about it. */
export type PinMismatchDetail =
  /** Mode A: the TLS SPKI did not match `fp`. */
  | 'tls-fingerprint'
  /** Mode B: the seal handshake was not signed by the pinned `bk`. */
  | 'bridge-static-key'
  /** The bridge answered with a different `bridgeId` than the one stored. */
  | 'bridge-identity';

/**
 * True when the state will not change again without user action.
 *
 * Declared as a type-level marker only; the runtime predicate lives in
 * `src/m1/state.ts`, because this file must stay free of value exports — the
 * bridge compiles it under `verbatimModuleSyntax` with CommonJS resolution, where
 * a value export is an error (TS1287).
 */
export type TerminalStateName = 'revoked' | 'pin-mismatch' | 'rendezvous-busy' | 'routing-collision';

// ── core events ─────────────────────────────────────────────────────────────

/**
 * What the core pushes out. One channel, so a consumer cannot miss a category.
 *
 * `diagnostic` carries operator-readable text for an activity log and is
 * deliberately free of tokens, keys and routing ids: it is the one field likely
 * to be rendered, logged or shared in a bug report.
 */
export type M1CoreEvent =
  | { type: 'state'; state: M1ClientState }
  /** A stream frame. `bseq` is already folded into `state.lastBseq`. */
  | { type: 'envelope'; envelope: M1StreamEnvelope }
  /** Stream opened. Carries the resume cursor and pending-frame count. */
  | { type: 'hello'; hello: M1StreamHello }
  /** Derived state must be discarded and re-baselined before rendering deltas. */
  | { type: 'resync'; reason: 'window-overflow' | 'dsh-restarted' }
  | { type: 'diagnostic'; level: 'info' | 'warn' | 'error'; message: string };

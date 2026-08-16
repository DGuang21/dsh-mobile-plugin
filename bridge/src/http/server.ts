/**
 * [OUR DESIGN] The `m1` bridge server.
 *
 * Six routes, documented in docs/FRONTEND_CONTRACT.md. This file is the only
 * place where an untrusted request becomes a dsh call, so the ordering of checks
 * here is the security model:
 *
 *   authenticate → device still active → policy gate → payload limits → forward
 *
 * Nothing skips a step. In particular the policy gate runs on every `/m1/rpc`
 * regardless of tier, because dsh would happily serve a privileged method to us:
 * we are on loopback, which upstream treats as trusted (DSH_CORE_RESEARCH.md §4).
 *
 * TLS is NOT set up here — see `createTlsServer` in transport/tls.ts. This class
 * takes an already-listening server so LAN (TLS) and relay (tunnelled) modes
 * share exactly one request path.
 */

import { randomUUID } from 'node:crypto';
import type { IncomingMessage, Server, ServerResponse as HttpServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import type {
  AuthChallengeResponse,
  AuthSession,
  BridgeError,
  M1Health,
  M1RespondResult,
  M1StreamHello,
  PairClaimResult,
} from '../../../src/m1/types.ts';
import { AuditLog, payloadDigest } from '../audit/log.ts';
import {
  AuthService,
  TOKEN_EXPIRY_WARNING_MS,
  bearerFromHeader,
  tokenFromSubprotocols,
} from '../auth/tokens.ts';
import type { DshApiClient } from '../dsh/client.ts';
import { DshRpcError, DshTransportError, DshUnavailableError } from '../dsh/errors.ts';
import type { DshConnection } from '../dsh/connection.ts';
import type { RpcReceipt, SendableApprovalOutcome } from '../dsh/types.ts';
import type { DeviceRecord, DeviceRegistry } from '../identity/registry.ts';
import type { PairingManager } from '../identity/pairing.ts';
import { M1_PATHS, M1_PROTOCOL_VERSION, M1_STREAM_SUBPROTOCOL } from '../m1/wire.ts';
import { PolicyGate, type DevicePolicy } from '../policy/gate.ts';
import { allowedMethodsForTier } from '../policy/methods.ts';
import type { StreamHub, Subscriber } from '../stream/hub.ts';
import type { PendingAnswerable } from '../stream/snapshots.ts';
import {
  CLOSE,
  ServerWebSocket,
  checkUpgrade,
  writeHandshake,
} from './websocket.ts';
import {
  MAX_BODY_BYTES,
  asRecord,
  bridgeError,
  parsePath,
  peerAddress,
  readJsonBody,
  requireString,
  sendError,
  sendJson,
  sendOk,
} from './router.ts';

/**
 * Per-answer cap for a question response.
 *
 * Measured in UTF-8 bytes rather than UTF-16 code units, because the byte count is
 * what upstream and the network see. `.length` would let a string of astral
 * characters weigh twice what the limit claims.
 */
const MAX_ANSWER_BYTES = 32_768;

/** Simple fixed-window rate limiter, per device. */
class RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();

  private readonly limit: number;
  private readonly windowMs: number;
  private readonly now: () => number;

  constructor(limit: number, windowMs: number, now: () => number) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.now = now;
  }

  /** Returns `undefined` when allowed, or the ms until the window resets. */
  check(key: string): number | undefined {
    const at = this.now();
    const window = this.windows.get(key);
    if (window === undefined || at >= window.resetAt) {
      this.windows.set(key, { count: 1, resetAt: at + this.windowMs });
      return undefined;
    }
    if (window.count >= this.limit) return window.resetAt - at;
    window.count += 1;
    return undefined;
  }

  forget(key: string): void {
    this.windows.delete(key);
  }
}

export interface BridgeServerOptions {
  server: Server;
  client: DshApiClient;
  connection: DshConnection;
  hub: StreamHub;
  registry: DeviceRegistry;
  auth: AuthService;
  pairing: PairingManager;
  gate?: PolicyGate;
  audit?: AuditLog;
  bridgeId: string;
  bridgeName: string;
  bridgeVersion: string;
  /** base64url SHA-256 of the TLS SPKI, echoed to a phone at pairing. */
  bridgeKeyFingerprint?: string;
  /** Max `/m1/rpc` + `/m1/respond` calls per device per minute. */
  rateLimitPerMinute?: number;
  now?: () => number;
}

export class BridgeServer {
  private readonly server: Server;
  private readonly client: DshApiClient;
  private readonly connection: DshConnection;
  private readonly hub: StreamHub;
  private readonly registry: DeviceRegistry;
  private readonly auth: AuthService;
  private readonly pairing: PairingManager;
  private readonly gate: PolicyGate;
  private readonly audit: AuditLog;
  private readonly bridgeId: string;
  private readonly bridgeName: string;
  private readonly bridgeVersion: string;
  private readonly bridgeKeyFingerprint: string | undefined;
  private readonly now: () => number;
  private readonly rateLimiter: RateLimiter;
  private readonly startedAt: number;
  private readonly sockets = new Set<ServerWebSocket>();
  /**
   * Serializes answers per `rpcId`.
   *
   * dsh `respond` is single-shot: two phones answering the same approval at once
   * would race, and the loser would get `not-pending` *after* the bridge had
   * already told it the frame was open. Chaining on the rpcId makes the outcome
   * deterministic.
   */
  private readonly respondChains = new Map<string, Promise<unknown>>();

  constructor(options: BridgeServerOptions) {
    this.server = options.server;
    this.client = options.client;
    this.connection = options.connection;
    this.hub = options.hub;
    this.registry = options.registry;
    this.auth = options.auth;
    this.pairing = options.pairing;
    this.gate = options.gate ?? new PolicyGate();
    this.audit = options.audit ?? new AuditLog();
    this.bridgeId = options.bridgeId;
    this.bridgeName = options.bridgeName;
    this.bridgeVersion = options.bridgeVersion;
    this.bridgeKeyFingerprint = options.bridgeKeyFingerprint;
    this.now = options.now ?? Date.now;
    this.startedAt = this.now();
    this.rateLimiter = new RateLimiter(options.rateLimitPerMinute ?? 120, 60_000, this.now);

    this.server.on('request', (request, response) => {
      void this.handleRequest(request, response);
    });
    this.server.on('upgrade', (request, socket, head) => {
      this.handleUpgrade(request, socket as Duplex, head);
    });

    // Revocation must terminate live streams, not merely fail the next request.
    this.registry.onRevocation((deviceId) => {
      this.hub.disconnectDevice(deviceId);
      this.rateLimiter.forget(deviceId);
      this.audit.record({ event: 'device-revoke', deviceId, decision: 'allowed' });
    });
  }

  /**
   * Serve the same `/m1` routes on an additional listener.
   *
   * Used for the relay carrier: the relay connector reaches the bridge over a
   * loopback-only socket and speaks ordinary `/m1`, so a phone arriving through the
   * relay is authorized by exactly the same code as a phone on the LAN. That is the
   * point — a second, tunnel-specific authorization path is a second thing to get
   * wrong.
   *
   * The caller owns the extra server's lifecycle and its exposure. Bind it to
   * loopback or a Unix socket only: these routes assume the transport is either
   * TLS-protected or local.
   */
  attach(server: Server): void {
    server.on('request', (request, response) => {
      void this.handleRequest(request, response);
    });
    server.on('upgrade', (request, socket, head) => {
      this.handleUpgrade(request, socket as Duplex, head);
    });
  }

  /** Close every live socket. Called on shutdown. */
  closeSockets(reason = 'bridge shutting down'): void {
    for (const socket of [...this.sockets]) socket.close(CLOSE.goingAway, reason);
    this.sockets.clear();
  }

  // ── request dispatch ──────────────────────────────────────────────────────

  private async handleRequest(request: IncomingMessage, response: HttpServerResponse): Promise<void> {
    const { path } = parsePath(request);
    const method = (request.method ?? 'GET').toUpperCase();

    try {
      if (path === M1_PATHS.health && method === 'GET') return this.handleHealth(response);
      if (path === M1_PATHS.pairClaim && method === 'POST') return await this.handlePairClaim(request, response);
      if (path === M1_PATHS.authSession && method === 'POST') return await this.handleAuthSession(request, response);
      if (path === M1_PATHS.rpc && method === 'POST') return await this.handleRpc(request, response);
      if (path === M1_PATHS.respond && method === 'POST') return await this.handleRespond(request, response);
      if (path === M1_PATHS.stream) {
        // A plain GET on the stream path is a client that forgot to upgrade.
        // Mirrors how dsh answers its own event paths.
        sendJson(response, 426, {
          ok: false,
          error: bridgeError('bad-request', 'GET /m1/stream requires a WebSocket upgrade'),
        });
        return;
      }
      // Known path, wrong verb.
      if (Object.values(M1_PATHS).includes(path as (typeof M1_PATHS)[keyof typeof M1_PATHS])) {
        sendJson(response, 405, { ok: false, error: bridgeError('bad-request', `${method} not allowed on ${path}`) });
        return;
      }
      // Deliberately uninformative: this is not a discoverable API.
      sendJson(response, 404, { ok: false, error: bridgeError('bad-request', 'not found') });
    } catch (error) {
      console.error('[bridge:http] unhandled error:', error);
      if (!response.headersSent) sendError(response, bridgeError('internal', 'internal bridge error'));
      else response.end();
    }
  }

  // ── GET /m1/health ────────────────────────────────────────────────────────

  /**
   * Liveness. Deliberately unauthenticated, and deliberately says almost nothing:
   * a phone needs to distinguish "bridge down" from "harness down" before it has a
   * token, and an unauthenticated caller learns only that a bridge exists.
   */
  private handleHealth(response: HttpServerResponse): void {
    const state = this.connection.getState();
    const health: M1Health = {
      ok: true,
      protocol: M1_PROTOCOL_VERSION,
      bridgeId: this.bridgeId,
      bridgeName: this.bridgeName,
      bridgeVersion: this.bridgeVersion,
      dsh: state === 'connected' ? 'up' : state === 'idle' ? 'down' : 'connecting',
      dshState: state,
      uptimeSeconds: Math.floor((this.now() - this.startedAt) / 1000),
      pairedDevices: this.registry.list().filter((device) => !device.revokedAt).length,
      ...(this.pairing.isOpen() ? { pairingOpen: true } : {}),
    };
    sendJson(response, 200, health);
  }

  // ── POST /m1/pair/claim ───────────────────────────────────────────────────

  private async handlePairClaim(request: IncomingMessage, response: HttpServerResponse): Promise<void> {
    const body = await readJsonBody(request, 64 * 1024);
    if (!body.ok) return sendError(response, body.error);
    const record = asRecord(body.value);
    if (record === undefined) return sendError(response, bridgeError('bad-request', 'body must be an object'));

    const token = requireString(record, 'token', 512);
    const devicePublicKey = requireString(record, 'devicePublicKey', 512);
    const label = requireString(record, 'label', 64);
    const proof = requireString(record, 'proof', 512);
    if (!token || !devicePublicKey || !label || !proof) {
      this.audit.record({ event: 'pair-claim', decision: 'denied', reason: 'malformed', peer: peerAddress(request) });
      return sendError(response, bridgeError('bad-request', 'token, devicePublicKey, label and proof are required'));
    }

    // A re-POST is how the phone learns the operator's decision: the token was
    // spent by the first claim, so this is a proof-authenticated read, not a
    // second claim. Checked first so a retry never looks like a replay.
    const polled = this.pairing.pollClaim({ devicePublicKey, proof });
    if (polled.status === 'paired') {
      const value: PairClaimResult = {
        status: 'paired',
        deviceId: polled.device.deviceId,
        bridgeId: this.bridgeId,
        bridgeName: this.bridgeName,
        scopeTier: polled.device.tier,
        ...(this.bridgeKeyFingerprint !== undefined ? { bridgeKeyFingerprint: this.bridgeKeyFingerprint } : {}),
      };
      this.audit.record({
        event: 'pair-confirm',
        deviceId: polled.device.deviceId,
        deviceLabel: polled.device.label,
        decision: 'allowed',
        peer: peerAddress(request),
      });
      return sendOk(response, value);
    }
    if (polled.status === 'awaiting-confirmation') {
      const value: PairClaimResult = {
        status: 'awaiting-confirmation',
        sas: polled.sas,
        bridgeName: this.bridgeName,
        bridgeId: this.bridgeId,
        expiresAt: polled.expiresAt,
      };
      return sendOk(response, value);
    }
    if (polled.status === 'rejected') {
      this.audit.record({ event: 'pair-reject', decision: 'denied', peer: peerAddress(request) });
      return sendError(response, bridgeError('pairing-rejected', 'the operator rejected this pairing'));
    }

    const claim = this.pairing.claim({ token, devicePublicKey, label, proof });
    if (!claim.ok) {
      this.audit.record({
        event: 'pair-claim',
        decision: 'denied',
        reason: claim.reason,
        peer: peerAddress(request),
      });
      // `dsh-unavailable` is not the phone's fault, and saying so prevents a user
      // from blaming the app for a dead harness.
      const error: BridgeError =
        claim.reason === 'dsh-unavailable'
          ? bridgeError('dsh-unavailable', 'the workstation harness is not reachable; pairing refused')
          : bridgeError('pairing-invalid', `pairing refused: ${claim.reason}`);
      return sendError(response, error);
    }

    this.audit.record({ event: 'pair-claim', decision: 'allowed', peer: peerAddress(request) });

    // The operator has not confirmed the SAS yet. Nothing is registered, and the
    // phone holds no trust until it re-claims after confirmation.
    const value: PairClaimResult = {
      status: 'awaiting-confirmation',
      sas: claim.sas,
      bridgeName: claim.bridgeName,
      bridgeId: this.bridgeId,
      // The confirmation deadline is the token's own expiry: the operator has the
      // remainder of the 120-second window, not a fresh one.
      expiresAt: this.pairing.current()?.expiresAt ?? this.now(),
    };
    sendOk(response, value);
  }

  // ── POST /m1/auth/session ─────────────────────────────────────────────────

  /**
   * Two-step in one route: a body without `signature` is a challenge request,
   * a body with one is the proof. One route keeps the phone's retry logic simple
   * and means a challenge cannot be requested for a device that cannot prove it.
   */
  private async handleAuthSession(request: IncomingMessage, response: HttpServerResponse): Promise<void> {
    const body = await readJsonBody(request, 64 * 1024);
    if (!body.ok) return sendError(response, body.error);
    const record = asRecord(body.value);
    if (record === undefined) return sendError(response, bridgeError('bad-request', 'body must be an object'));

    const deviceId = requireString(record, 'deviceId', 128);
    if (deviceId === undefined) return sendError(response, bridgeError('bad-request', 'deviceId is required'));

    const signature = typeof record.signature === 'string' ? record.signature : undefined;
    if (signature === undefined) {
      const challenge = this.auth.challenge(deviceId);
      if (!challenge.ok) {
        this.audit.record({ event: 'auth-challenge', deviceId, decision: 'denied', reason: challenge.reason });
        // `unknown-device` and `device-revoked` are answered identically, so an
        // unauthenticated caller cannot enumerate which deviceIds ever existed.
        return sendError(response, bridgeError('unauthenticated', 'device is not authorized'));
      }
      this.audit.record({ event: 'auth-challenge', deviceId, decision: 'allowed' });
      const value: AuthChallengeResponse = {
        nonce: challenge.nonce,
        bridgeId: this.bridgeId,
        expiresAt: challenge.expiresAt,
      };
      return sendOk(response, value);
    }

    const nonce = requireString(record, 'nonce', 512);
    if (nonce === undefined) return sendError(response, bridgeError('bad-request', 'nonce is required'));

    const result = this.auth.authenticate({ deviceId, nonce, signature });
    if (!result.ok) {
      this.audit.record({ event: 'auth-failure', deviceId, decision: 'denied', reason: result.reason });
      return sendError(response, bridgeError('unauthenticated', `authentication failed: ${result.reason}`));
    }

    const device = this.registry.getActive(deviceId);
    if (device === undefined) {
      // Revoked between the challenge and the proof.
      return sendError(response, bridgeError('device-revoked', 'device was revoked'));
    }
    this.registry.touch(deviceId);
    this.audit.record({ event: 'auth-success', deviceId, deviceLabel: device.label, decision: 'allowed' });

    const value: AuthSession = {
      token: result.token,
      expiresAt: result.expiresAt,
      deviceId,
      scopeTier: device.tier,
      allowedMethods: [...allowedMethodsForTier(device.tier)].sort(),
      slashCommandsEnabled: device.allowSlashCommands,
    };
    sendOk(response, value);
  }

  // ── shared authorization ──────────────────────────────────────────────────

  /**
   * Resolve a bearer token to a live device.
   *
   * Re-checks the registry rather than trusting the token's binding: a token
   * issued before revocation must not outlive it, even for the milliseconds
   * before the revocation listener fires.
   */
  private authorize(request: IncomingMessage): { ok: true; device: DeviceRecord } | { ok: false; error: BridgeError } {
    const token = bearerFromHeader(
      typeof request.headers.authorization === 'string' ? request.headers.authorization : undefined,
    );
    if (token === undefined) return { ok: false, error: bridgeError('unauthenticated', 'missing bearer token') };
    const check = this.auth.verify(token);
    if (!check.ok) {
      return {
        ok: false,
        error:
          check.reason === 'device-revoked'
            ? bridgeError('device-revoked', 'device was revoked')
            : bridgeError('unauthenticated', `token ${check.reason}`),
      };
    }
    const device = this.registry.getActive(check.deviceId);
    if (device === undefined) return { ok: false, error: bridgeError('device-revoked', 'device was revoked') };
    return { ok: true, device };
  }

  private policyFor(device: DeviceRecord): DevicePolicy {
    return { tier: device.tier, allowSlashCommands: device.allowSlashCommands };
  }

  // ── POST /m1/rpc ──────────────────────────────────────────────────────────

  private async handleRpc(request: IncomingMessage, response: HttpServerResponse): Promise<void> {
    const authorized = this.authorize(request);
    if (!authorized.ok) return sendError(response, authorized.error);
    const device = authorized.device;

    const retryAfterMs = this.rateLimiter.check(device.deviceId);
    if (retryAfterMs !== undefined) {
      this.audit.record({ event: 'rpc', deviceId: device.deviceId, decision: 'rate-limited' });
      return sendError(response, bridgeError('rate-limited', 'too many requests', { retryAfterMs }));
    }

    const body = await readJsonBody(request, MAX_BODY_BYTES);
    if (!body.ok) return sendError(response, body.error);
    const record = asRecord(body.value);
    if (record === undefined) return sendError(response, bridgeError('bad-request', 'body must be an object'));

    const method = requireString(record, 'method', 128);
    const requestId = typeof record.requestId === 'string' ? record.requestId : undefined;
    if (method === undefined) return sendError(response, bridgeError('bad-request', 'method is required'));
    const payload = record.payload;

    const decision = this.gate.evaluate(method, payload, this.policyFor(device));
    const digest = payloadDigest(payload);
    if (!decision.allowed) {
      this.audit.record({
        event: 'rpc',
        deviceId: device.deviceId,
        deviceLabel: device.label,
        method,
        decision: 'denied',
        reason: decision.reason,
        payloadDigest: digest.digest,
        payloadBytes: digest.bytes,
      });
      return sendError(response, this.gateErrorFor(decision.reason, decision.message, method));
    }

    // `respond` has its own route with pending-frame validation. Allowing it here
    // would let a phone answer an arbitrary rpcId through the generic path.
    if (method === 'respond') {
      return sendError(response, bridgeError('bad-request', 'use POST /m1/respond to answer a frame'));
    }

    if (!this.connection.isConnected()) {
      this.audit.record({
        event: 'rpc',
        deviceId: device.deviceId,
        method,
        decision: 'failed',
        reason: 'dsh-unavailable',
        payloadDigest: digest.digest,
      });
      return sendError(
        response,
        bridgeError('dsh-unavailable', 'the workstation harness is not connected', { retryAfterMs: 2000 }),
      );
    }

    try {
      const result = await this.client.call(method, payload);
      this.audit.record({
        event: 'rpc',
        deviceId: device.deviceId,
        deviceLabel: device.label,
        method,
        decision: result.ok ? 'allowed' : 'failed',
        ...(result.ok ? {} : { reason: result.error.code }),
        payloadDigest: digest.digest,
        payloadBytes: digest.bytes,
        ...(typeof asRecord(payload)?.sessionId === 'string' ? { sessionId: String(asRecord(payload)?.sessionId) } : {}),
      });
      if (result.ok) {
        sendJson(response, 200, { ok: true, ...(requestId !== undefined ? { requestId } : {}), value: result.value });
        return;
      }
      // A dsh business error is not a bridge failure. It is reported under
      // `dshError` so the UI can tell "the harness said no" from "the bridge
      // would not ask", and it keeps HTTP 200 exactly as upstream does.
      sendJson(response, 200, {
        ok: false,
        ...(requestId !== undefined ? { requestId } : {}),
        dshError: result.error,
      });
    } catch (error) {
      this.audit.record({
        event: 'rpc',
        deviceId: device.deviceId,
        method,
        decision: 'failed',
        reason: error instanceof Error ? error.name : 'unknown',
        payloadDigest: digest.digest,
      });
      sendError(response, this.dshErrorFor(error));
    }
  }

  // ── POST /m1/respond ──────────────────────────────────────────────────────

  private async handleRespond(request: IncomingMessage, response: HttpServerResponse): Promise<void> {
    const authorized = this.authorize(request);
    if (!authorized.ok) return sendError(response, authorized.error);
    const device = authorized.device;

    const retryAfterMs = this.rateLimiter.check(device.deviceId);
    if (retryAfterMs !== undefined) {
      return sendError(response, bridgeError('rate-limited', 'too many requests', { retryAfterMs }));
    }

    const body = await readJsonBody(request, 256 * 1024);
    if (!body.ok) return sendError(response, body.error);
    const record = asRecord(body.value);
    if (record === undefined) return sendError(response, bridgeError('bad-request', 'body must be an object'));

    const rpcId = requireString(record, 'rpcId', 256);
    const kind = requireString(record, 'kind', 32);
    if (rpcId === undefined || (kind !== 'approval' && kind !== 'question')) {
      return sendError(response, bridgeError('bad-request', "rpcId and kind ('approval' | 'question') are required"));
    }

    const gated = this.gate.evaluate('respond', record, this.policyFor(device));
    if (!gated.allowed) {
      this.audit.record({
        event: 'respond',
        deviceId: device.deviceId,
        rpcId,
        decision: 'denied',
        reason: gated.reason,
      });
      return sendError(response, this.gateErrorFor(gated.reason, gated.message, 'respond'));
    }

    // The bridge only forwards an answer to a frame it actually delivered. This
    // is what stops a phone from answering an approval it never saw — including
    // one raised by a different client entirely.
    if (!this.hub.isPending(rpcId)) {
      this.audit.record({ event: 'respond', deviceId: device.deviceId, rpcId, decision: 'denied', reason: 'not-pending' });
      const value: M1RespondResult = { status: 'already-resolved' };
      return sendOk(response, value);
    }

    // The pending entry, not just its existence: the upstream answer payload carries
    // correlation ids that dsh re-checks against its own entry, and they must come
    // from the frame we delivered rather than from the request body.
    const pending = this.hub.getPending(rpcId);
    if (pending === undefined) {
      const value: M1RespondResult = { status: 'already-resolved' };
      return sendOk(response, value);
    }
    if (pending.frame.type !== `${kind}/requested`) {
      return sendError(response, bridgeError('bad-request', `rpcId is a ${pending.frame.type}, not a ${kind}`));
    }

    const built = this.buildResponsePayload(pending, record);
    if (!built.ok) return sendError(response, built.error);

    if (!this.connection.isConnected()) {
      return sendError(response, bridgeError('dsh-unavailable', 'the workstation harness is not connected'));
    }

    // Serialize per rpcId so two phones cannot both be told the frame is open.
    const previous = this.respondChains.get(rpcId) ?? Promise.resolve();
    const attempt = previous.then(async (): Promise<RpcReceipt> => {
      if (!this.hub.isPending(rpcId)) return { accepted: false, reason: 'not-pending' };
      const receipt = await this.client.respond(rpcId, built.value);
      if (receipt.accepted) this.hub.consumePending(rpcId);
      return receipt;
    });
    this.respondChains.set(
      rpcId,
      attempt.catch(() => undefined),
    );

    try {
      const receipt = await attempt;
      const pending = this.hub.pendingCount();
      this.audit.record({
        event: 'respond',
        deviceId: device.deviceId,
        deviceLabel: device.label,
        rpcId,
        method: kind,
        decision: receipt.accepted ? 'allowed' : 'denied',
        ...(receipt.accepted ? {} : { reason: receipt.reason }),
        payloadDigest: payloadDigest(built.value).digest,
      });
      void pending;
      const value: M1RespondResult = receipt.accepted
        ? { status: 'accepted' }
        : receipt.reason === 'not-pending'
          ? { status: 'already-resolved' }
          : { status: 'rejected', reason: 'bad-response' };
      sendOk(response, value);
    } catch (error) {
      sendError(response, this.dshErrorFor(error));
    } finally {
      // Only the last waiter clears the chain, so a queued answer still sees it.
      if (this.respondChains.get(rpcId) === attempt) this.respondChains.delete(rpcId);
    }
  }

  /**
   * Build the `result.value` of the `client-response` for an answerable frame.
   *
   * Shapes verified against the upstream payload schemas, not inferred:
   *   approval → `{sessionId, approvalId, outcome}`, and dsh rejects the answer as
   *     `bad-response` unless both ids match its own pending entry;
   *   question  → `{sessionId, answer: {answers: [{id, selected, custom?}]}}`, with
   *     one answer per question, in order, and every `selected` value a label that
   *     appeared in that question's `options`.
   *
   * The correlation ids come from `pending`, never from the request body. A phone
   * supplies only the decision, so it cannot answer the approval its `rpcId` names
   * while attributing the answer to some other session.
   *
   * Approvals are restricted to `allowed-once` and `rejected` — `cancelled` and
   * `unavailable` are host-side outcomes and the upstream schema refuses them from a
   * client. There is no "always allow" from a phone.
   */
  private buildResponsePayload(
    pending: PendingAnswerable,
    record: Record<string, unknown>,
  ): { ok: true; value: unknown } | { ok: false; error: BridgeError } {
    const frame = pending.frame;
    if (frame.type === 'approval/requested') {
      const outcome = record.outcome;
      if (outcome !== 'allowed-once' && outcome !== 'rejected') {
        return {
          ok: false,
          error: bridgeError('bad-request', "outcome must be 'allowed-once' or 'rejected'"),
        };
      }
      const value: { sessionId: string; approvalId: string; outcome: SendableApprovalOutcome } = {
        sessionId: frame.sessionId,
        approvalId: frame.approvalId,
        outcome,
      };
      return { ok: true, value };
    }

    const answers = record.answers;
    if (!Array.isArray(answers)) {
      return { ok: false, error: bridgeError('bad-request', 'answers must be an array') };
    }
    // One answer per question, positionally. Upstream compares by index *and* id, so
    // a partial batch is refused there as `bad-response`; refusing it here instead
    // lets the phone be told which question is missing.
    if (answers.length !== frame.questions.length) {
      return {
        ok: false,
        error: bridgeError('bad-request', `expected ${frame.questions.length} answers, got ${answers.length}`),
      };
    }

    const normalized: { id: string; selected: string[]; custom?: string }[] = [];
    for (const [index, question] of frame.questions.entries()) {
      const entry = asRecord(answers[index]);
      if (entry === undefined) {
        return { ok: false, error: bridgeError('bad-request', `answer ${index} is not an object`) };
      }
      const id = requireString(entry, 'id', 256);
      if (id !== question.id) {
        return { ok: false, error: bridgeError('bad-request', `answer ${index} must have id '${question.id}'`) };
      }

      const raw = entry.value;
      const values = typeof raw === 'string' ? [raw] : raw;
      if (!Array.isArray(values) || !values.every((item): item is string => typeof item === 'string')) {
        return { ok: false, error: bridgeError('bad-request', `answer '${id}' value must be a string or string[]`) };
      }
      const bytes = values.reduce((total, item) => total + Buffer.byteLength(item, 'utf8'), 0);
      if (bytes > MAX_ANSWER_BYTES) {
        return { ok: false, error: bridgeError('payload-too-large', `answer '${id}' is too long`) };
      }
      if (new Set(values).size !== values.length) {
        return { ok: false, error: bridgeError('bad-request', `answer '${id}' repeats a selection`) };
      }

      const labels = new Set((question.options ?? []).map((option) => option.label));
      const offered = values.filter((item) => labels.has(item));
      const free = values.filter((item) => !labels.has(item));

      // A value that is not one of the offered labels is free text, which upstream
      // carries in `custom` rather than `selected`. Splitting here is what lets the
      // phone send one `value` field for both cases.
      if (free.length > 1) {
        return { ok: false, error: bridgeError('bad-request', `answer '${id}' has more than one free-text value`) };
      }
      const custom = free[0];
      if (custom !== undefined && custom.trim() === '') {
        return { ok: false, error: bridgeError('bad-request', `answer '${id}' free text is blank`) };
      }
      if (question.multiSelect !== true) {
        if (offered.length > 1) {
          return { ok: false, error: bridgeError('bad-request', `question '${id}' is single-select`) };
        }
        if (custom !== undefined && offered.length > 0) {
          return { ok: false, error: bridgeError('bad-request', `question '${id}' takes a label or free text, not both`) };
        }
      }
      if (offered.length === 0 && custom === undefined) {
        return { ok: false, error: bridgeError('bad-request', `answer '${id}' is empty`) };
      }
      normalized.push({ id, selected: offered, ...(custom === undefined ? {} : { custom }) });
    }
    return { ok: true, value: { sessionId: frame.sessionId, answer: { answers: normalized } } };
  }

  // ── GET /m1/stream (WebSocket) ────────────────────────────────────────────

  private handleUpgrade(request: IncomingMessage, socket: Duplex, _head: Buffer): void {
    const { path, query } = parsePath(request);
    if (path !== M1_PATHS.stream) return this.refuseUpgrade(socket, 404, 'not found');

    const check = checkUpgrade(request);
    if (!check.ok || check.key === undefined) {
      return this.refuseUpgrade(socket, check.status ?? 400, check.reason ?? 'bad upgrade');
    }

    const protocols = check.subprotocols ?? [];
    // The token travels in the subprotocol, never the query string: query strings
    // land in access logs and shell history.
    const token = tokenFromSubprotocols(protocols);
    if (token === undefined) return this.refuseUpgrade(socket, 401, 'missing token subprotocol');

    const verified = this.auth.verify(token);
    if (!verified.ok) return this.refuseUpgrade(socket, 401, `token ${verified.reason}`);
    const device = this.registry.getActive(verified.deviceId);
    if (device === undefined) return this.refuseUpgrade(socket, 403, 'device revoked');

    const after = this.parseAfter(query.get('after'));
    if (after === undefined) return this.refuseUpgrade(socket, 400, 'after must be a non-negative integer');

    // Rotate on stream connect, per the auth design: the long-lived thing is the
    // device key, and the token the phone carries afterwards is a fresh one.
    const rotated = this.auth.rotate(token);
    if (!rotated.ok) return this.refuseUpgrade(socket, 401, `token ${rotated.reason}`);

    writeHandshake(socket, check.key, protocols.includes(M1_STREAM_SUBPROTOCOL) ? M1_STREAM_SUBPROTOCOL : undefined);

    const ws = new ServerWebSocket(socket, { maxMessageBytes: 64 * 1024 }, {});
    this.sockets.add(ws);

    const subscriber: Subscriber = {
      deviceId: device.deviceId,
      deliver: (envelope) => {
        ws.sendJson(envelope);
      },
    };

    const attached = this.hub.attach(subscriber, after);
    if (!attached.ok) {
      // dsh is not ready. Told explicitly rather than left to time out, so the
      // phone can render "harness offline" instead of "connecting".
      ws.sendJson({ v: 1, bseq: 0, kind: 'bridge', frame: { type: 'dsh-disconnected' } });
      ws.close(CLOSE.policyViolation, 'dsh not ready');
      this.sockets.delete(ws);
      return;
    }

    const hello: M1StreamHello = {
      v: 1,
      kind: 'hello',
      bridgeId: this.bridgeId,
      token: rotated.token,
      tokenExpiresAt: rotated.expiresAt,
      lastBseq: attached.lastBseq,
      resync: attached.resynced,
      pendingCount: attached.pending.length,
    };
    ws.sendJson(hello);

    if (attached.resynced) {
      ws.sendJson({
        v: 1,
        bseq: attached.lastBseq,
        kind: 'bridge',
        frame: { type: 'resync-required', reason: 'window-overflow' },
      });
      // Snapshots first: they are the cheapest way to make the phone's view
      // current before it re-baselines the rest.
      for (const snapshot of attached.snapshots) ws.sendJson(snapshot);
    } else {
      for (const envelope of attached.backlog) ws.sendJson(envelope);
    }

    // Pending obligations last, so they are the freshest thing on screen.
    for (const envelope of attached.pending) ws.sendJson(envelope);

    if (this.auth.isExpiringSoon(rotated.token)) {
      ws.sendJson({
        v: 1,
        bseq: attached.lastBseq,
        kind: 'bridge',
        frame: { type: 'token-expiring', expiresAt: rotated.expiresAt },
      });
    }

    this.audit.record({
      event: 'stream-attach',
      deviceId: device.deviceId,
      deviceLabel: device.label,
      decision: 'allowed',
      resync: attached.resynced,
      peer: peerAddress(request),
    });

    ws.setSinks({
      onMessage: (text) => this.handleStreamMessage(ws, text),
      onClose: () => {
        this.hub.detach(subscriber);
        this.sockets.delete(ws);
        this.auth.revokeToken(rotated.token);
        this.audit.record({ event: 'stream-detach', deviceId: device.deviceId, decision: 'allowed' });
      },
    });
  }

  /**
   * The stream is not an RPC channel.
   *
   * Only liveness and cursor acks are accepted. Anything else is ignored rather
   * than errored, so a future client addition cannot break an older bridge — but
   * it is emphatically not a second way to invoke methods.
   */
  private handleStreamMessage(ws: ServerWebSocket, text: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return;
    }
    const record = asRecord(parsed);
    if (record === undefined) return;
    if (record.kind === 'ping') ws.sendJson({ v: 1, bseq: 0, kind: 'bridge', frame: { type: 'pong', at: this.now() } });
  }

  private parseAfter(raw: string | null): number | undefined {
    if (raw === null || raw === '') return 0;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < 0) return undefined;
    return value;
  }

  private refuseUpgrade(socket: Duplex, status: number, reason: string): void {
    const text = `HTTP/1.1 ${status} ${reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`;
    try {
      socket.write(text);
    } catch {
      // Already gone.
    }
    socket.destroy();
  }

  // ── error mapping ─────────────────────────────────────────────────────────

  private gateErrorFor(reason: string, message: string, method: string): BridgeError {
    switch (reason) {
      case 'method-denied':
      case 'method-out-of-scope':
      case 'slash-command-disabled':
        return bridgeError('method-denied', message, { method });
      case 'payload-too-large':
        return bridgeError('payload-too-large', message);
      default:
        return bridgeError('bad-request', message, { method });
    }
  }

  /** Map a thrown dsh client error to a bridge error code. */
  private dshErrorFor(error: unknown): BridgeError {
    if (error instanceof DshUnavailableError) {
      return bridgeError('dsh-unavailable', error.message, { retryAfterMs: 2000 });
    }
    if (error instanceof DshRpcError) {
      return bridgeError('dsh-protocol-error', error.message);
    }
    if (error instanceof DshTransportError) {
      return error.retryable
        ? bridgeError('dsh-unavailable', error.message, { retryAfterMs: 2000 })
        : bridgeError('dsh-protocol-error', error.message);
    }
    // Includes DshRpcIdMismatchError: the carrier answered a different request
    // than we asked, which is a protocol violation, never a business outcome.
    return bridgeError('dsh-protocol-error', error instanceof Error ? error.message : 'unknown dsh failure');
  }

  /**
   * Periodic maintenance: drop expired tokens/nonces and warn devices whose
   * tokens are close to expiry, so the phone can re-auth before a request fails.
   *
   * Called from the runtime tick rather than a timer owned here, so a test can
   * drive it deterministically.
   */
  maintain(): void {
    this.auth.sweep();
    for (const device of this.registry.list()) {
      if (device.revokedAt) continue;
      const expiring = this.auth.expiringTokensFor(device.deviceId, TOKEN_EXPIRY_WARNING_MS);
      for (const expiresAt of expiring) {
        this.hub.notifyDevice(device.deviceId, { type: 'token-expiring', expiresAt });
      }
    }
  }

  /** For diagnostics/tests. */
  stats(): { sockets: number; pendingChains: number } {
    return { sockets: this.sockets.size, pendingChains: this.respondChains.size };
  }
}

/** Mint a bridge instance id. Stable across restarts only if persisted. */
export function newBridgeId(): string {
  return randomUUID();
}

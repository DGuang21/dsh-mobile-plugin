/**
 * [OUR DESIGN] The RN core: one state machine over both transports.
 *
 * Everything with a policy in it lives here — authentication, token rotation,
 * reconnect and backoff, resync, revocation, pin mismatch, and the 15-state model
 * the UI consumes. The transports below are deliberately dumb (send bytes, report
 * failures) and the hook above is deliberately thin (render state, forward calls),
 * so there is exactly one place where "what happens when the token expires
 * mid-stream" is decided.
 *
 * ## Invariants
 *
 *   - **The access token never leaves memory.** It lives in one private field, is
 *     passed per-request, and is replaced by the rotated token in every stream
 *     hello. `storage.ts` has no slot for it.
 *   - **Terminal is terminal.** `revoked`, `pin-mismatch`, `routing-collision` and
 *     `rendezvous-busy` stop the reconnect loop dead. No timer survives them, and
 *     only an explicit `clear()` or a new pairing restarts anything.
 *   - **One transport at a time.** Every connect attempt closes the previous
 *     transport before building the next, so a stale relay socket cannot deliver
 *     into a live session.
 *   - **A generation counter guards every async continuation.** `connect()` awaits
 *     several round trips; if the caller cleared or re-paired meanwhile, the
 *     continuation must not resurrect the old session.
 */

import type { DeviceIdentity } from './crypto';
import { signDomain } from './crypto';
import { LanTransport } from './lan-transport';
import { M1_PATHS } from './paths';
import { type PairFailure, type PairFlowHooks, type PairOutcome, runPairing } from './pair-flow';
import { RelayTransport } from './relay-transport';
import type { WebSocketFactory } from './relay';
import { isTerminalState } from './state';
import {
  type M1Transport,
  type StreamSubscription,
  TransportError,
} from './transport';
import type {
  AuthChallengeResponse,
  AuthSession,
  BridgeError,
  BridgeErrorCode,
  M1ClientState,
  M1CoreEvent,
  M1Health,
  M1Response,
  M1StreamEnvelope,
  M1StreamHello,
  QuestionAnswer,
  RelayErrorCode,
} from './types';
import type { StoredBridge } from '../storage';

/** Backoff schedule for reconnects, in milliseconds. Capped, then repeats. */
const BACKOFF_MS: readonly number[] = [500, 1_000, 2_000, 5_000, 10_000, 20_000, 30_000];
/** Jitter fraction, so a fleet of phones does not retry in lockstep. */
const BACKOFF_JITTER = 0.25;
/** Re-auth this far before the token expires rather than waiting for a 401. */
const TOKEN_REFRESH_MARGIN_MS = 60_000;

export interface M1CoreOptions {
  identity: DeviceIdentity;
  /** Reads and writes the durable route. Injected so the core stays Node-testable. */
  store: {
    read: () => Promise<StoredBridge | undefined>;
    write: (value: StoredBridge | undefined) => Promise<void>;
  };
  /** Mode A override, e.g. a user-entered LAN address. */
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  webSocketImpl?: typeof WebSocket;
  /** Mode B needs a raw socket factory; RN's `WebSocket` is adapted in `useDsh`. */
  createSocket?: WebSocketFactory;
  /**
   * Re-baseline hook, called on `resync` before returning to `ready`.
   *
   * The core cannot do this alone: re-baselining needs `session.history` per *open*
   * session, and only the consumer knows which sessions it is rendering.
   */
  onResync?: (reason: 'window-overflow' | 'dsh-restarted') => Promise<void>;
  now?: () => number;
  /** Injectable timers, so tests do not wait out a backoff. */
  setTimer?: (handler: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  /** Deterministic jitter in tests. */
  random?: () => number;
}

export type M1CoreListener = (event: M1CoreEvent) => void;

export class M1Error extends Error {
  readonly code: BridgeErrorCode | string;
  readonly status: number | undefined;
  readonly retryAfterMs: number | undefined;
  /** True when the harness answered with a business error, not the bridge. */
  readonly isDshError: boolean;

  constructor(input: {
    code: BridgeErrorCode | string;
    message: string;
    status?: number;
    retryAfterMs?: number;
    isDshError?: boolean;
  }) {
    super(input.message);
    this.name = 'M1Error';
    this.code = input.code;
    this.status = input.status;
    this.retryAfterMs = input.retryAfterMs;
    this.isDshError = input.isDshError === true;
  }
}

export class M1Core {
  private readonly options: M1CoreOptions;
  private readonly listeners = new Set<M1CoreListener>();
  private readonly now: () => number;
  private readonly random: () => number;

  private state: M1ClientState = { name: 'unpaired', reason: 'fresh' };
  private bridge: StoredBridge | undefined;
  /** Mode A address, from storage or a user override. */
  private baseUrl: string | undefined;

  /** The access token. Memory only, by contract. */
  private token: string | undefined;
  private tokenExpiresAt = 0;
  private session: AuthSession | undefined;

  private transport: M1Transport | undefined;
  private subscription: StreamSubscription | undefined;
  private lastBseq = 0;
  private attempt = 0;
  private retryTimer: unknown;
  /** Bumped on every connect, clear and pair, to strand stale continuations. */
  private generation = 0;
  private connecting = false;
  private started = false;
  private authInFlight: Promise<AuthSession> | undefined;
  private resyncInFlight = false;
  /**
   * The pairing run currently in flight, keyed by its URI.
   *
   * A pairing token is single-use: the bridge consumes it on the first claim and
   * only re-verifies the identical proof on subsequent polls. So a second `pair()`
   * for the same code must not start a second run — it would strand a run that may
   * already have succeeded and then fail on a spent token. Re-attaching to the live
   * promise makes a repeat tap harmless, which matters because the natural UI for
   * "waiting for confirmation" is a button the user can press again.
   */
  private pairInFlight: { uri: string; promise: Promise<PairOutcome> } | undefined;

  constructor(options: M1CoreOptions) {
    this.options = options;
    this.now = options.now ?? (() => Date.now());
    this.random = options.random ?? Math.random;
    this.baseUrl = options.baseUrl;
  }

  // ── observation ───────────────────────────────────────────────────────────

  subscribe(listener: M1CoreListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  getState(): M1ClientState {
    return this.state;
  }

  getBridge(): StoredBridge | undefined {
    return this.bridge;
  }

  getSession(): AuthSession | undefined {
    return this.session;
  }

  getLastBseq(): number {
    return this.lastBseq;
  }

  get deviceId(): string {
    return this.options.identity.deviceId;
  }

  get mode(): 'lan' | 'relay' | undefined {
    return this.bridge?.mode;
  }

  /** Whether a token is currently held. For diagnostics; never the token itself. */
  hasToken(): boolean {
    return this.token !== undefined;
  }

  // ── lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Load the stored route and connect if there is one.
   *
   * Idempotent: a second call is ignored, so a remounting React tree cannot open
   * two sessions.
   */
  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    const stored = await this.options.store.read();
    if (stored === undefined) {
      this.setState({ name: 'unpaired', reason: 'fresh' });
      return;
    }
    this.bridge = stored;
    // A user-entered address wins: a bridge that moved on the LAN is the common
    // case, and the stored one would otherwise be a permanent dead end.
    this.baseUrl = this.options.baseUrl ?? stored.baseUrl;
    this.setState({ name: 'paired', bridgeName: stored.bridgeName });
    void this.connect();
  }

  /** Mode A: point at a different address. Reconnects if already paired. */
  setBaseUrl(baseUrl: string): void {
    const normalized = baseUrl.trim().replace(/\/+$/, '');
    if (normalized === this.baseUrl) return;
    this.baseUrl = normalized.length > 0 ? normalized : undefined;
    if (this.bridge?.mode === 'lan' && this.bridge !== undefined) {
      // Persist it, or the next launch dials the old address again.
      const next: StoredBridge = { ...this.bridge, baseUrl: this.baseUrl ?? this.bridge.baseUrl };
      this.bridge = next;
      void this.options.store.write(next).catch(() => undefined);
      void this.reconnectNow('address changed');
    }
  }

  /** Unauthenticated liveness probe, for a "test connection" affordance. */
  async health(baseUrl?: string): Promise<M1Health> {
    const target = (baseUrl ?? this.baseUrl)?.trim().replace(/\/+$/, '');
    if (target === undefined || target.length === 0) throw new Error('no bridge address to check');
    const probe = new LanTransport({
      baseUrl: target,
      ...(this.options.fetchImpl === undefined ? {} : { fetchImpl: this.options.fetchImpl }),
      ...(this.options.webSocketImpl === undefined ? {} : { webSocketImpl: this.options.webSocketImpl }),
    });
    try {
      const response = await probe.request({ method: 'GET', path: M1_PATHS.health });
      if (response.status !== 200) throw new Error(`bridge health check failed (${response.status})`);
      const body = response.body;
      if (typeof body !== 'object' || body === null) throw new Error('bridge health check returned no body');
      return body as M1Health;
    } finally {
      probe.close();
    }
  }

  // ── pairing ───────────────────────────────────────────────────────────────

  /** Move to `scanning`, so the UI can open the camera against a real state. */
  beginScanning(): void {
    if (this.bridge !== undefined) return;
    this.setState({ name: 'scanning' });
  }

  /**
   * Pair from a scanned URI.
   *
   * Drives the state machine through `pairing` → `awaiting-confirmation` → `paired`
   * and then connects. Returns the outcome as a value so a caller can show its own
   * error text without re-deriving it from the state.
   */
  async pair(input: { uri: string; label: string; signal?: { aborted: boolean } }): Promise<PairOutcome> {
    // Same code, run already going: hand back the same promise. See `pairInFlight`.
    const live = this.pairInFlight;
    if (live !== undefined && live.uri === input.uri) return await live.promise;
    const promise = this.runPair(input);
    this.pairInFlight = { uri: input.uri, promise };
    try {
      return await promise;
    } finally {
      // Only clear if this run is still the current one; a superseding `pair()` for
      // a different code has already installed its own.
      if (this.pairInFlight?.promise === promise) this.pairInFlight = undefined;
    }
  }

  private async runPair(input: { uri: string; label: string; signal?: { aborted: boolean } }): Promise<PairOutcome> {
    // A pairing supersedes anything in flight, including a reconnect loop for a
    // previous bridge.
    this.teardown('pairing restarted the session');
    const generation = ++this.generation;

    const hooks: PairFlowHooks = {
      onAwaitingConfirmation: ({ sas, bridgeName, expiresAt }) => {
        if (generation !== this.generation) return;
        this.setState({ name: 'awaiting-confirmation', sas, bridgeName, expiresAt });
      },
      onProgress: (stage) => {
        if (generation !== this.generation) return;
        if (stage === 'awaiting') return;
        if (this.state.name === 'awaiting-confirmation') return;
        this.emit({ type: 'diagnostic', level: 'info', message: `pairing: ${stage}` });
      },
      onDiagnostic: (level, message) => this.emit({ type: 'diagnostic', level, message }),
    };

    const modeGuess = input.uri.includes('relay=') ? 'relay' : 'lan';
    this.setState({ name: 'pairing', mode: modeGuess });

    const outcome = await runPairing({
      uri: input.uri,
      identity: this.options.identity,
      label: input.label.trim().length > 0 ? input.label.trim() : 'Mobile device',
      hooks,
      ...(this.baseUrl === undefined ? {} : { baseUrl: this.baseUrl }),
      ...(this.options.createSocket === undefined ? {} : { createSocket: this.options.createSocket }),
      ...(this.options.fetchImpl === undefined ? {} : { fetchImpl: this.options.fetchImpl }),
      ...(this.options.webSocketImpl === undefined ? {} : { webSocketImpl: this.options.webSocketImpl }),
      ...(input.signal === undefined ? {} : { signal: input.signal }),
      now: this.now,
    });

    // The caller cleared or re-paired while we were polling. Do not adopt a route
    // that no longer belongs to the current intent.
    if (generation !== this.generation) return outcome;

    if (!outcome.ok) {
      this.applyPairFailure(outcome.failure);
      return outcome;
    }

    this.bridge = outcome.bridge;
    this.baseUrl = outcome.bridge.baseUrl ?? this.baseUrl;
    await this.options.store.write(outcome.bridge);
    this.setState({ name: 'paired', bridgeName: outcome.bridge.bridgeName });
    void this.connect();
    return outcome;
  }

  /** Forget the pairing. Terminal until a new pair; wipes the durable route. */
  async clear(): Promise<void> {
    this.teardown('cleared by the user');
    this.generation += 1;
    this.bridge = undefined;
    this.lastBseq = 0;
    // Drop the in-flight pairing handle too. Its result is already stranded by the
    // generation bump, and keeping it would let a re-scan of the same code re-attach
    // to a run whose outcome will be discarded.
    this.pairInFlight = undefined;
    // The device key deliberately survives: it is this phone's identity, not this
    // pairing's, and destroying it buys nothing while breaking re-pairing to a
    // bridge that still lists the device.
    await this.options.store.write(undefined);
    this.setState({ name: 'unpaired', reason: 'cleared' });
  }

  // ── connection ────────────────────────────────────────────────────────────

  /**
   * Build a transport, authenticate, open the stream.
   *
   * Guarded three ways: `connecting` prevents overlap, a terminal state prevents
   * resurrection, and the generation check after every await prevents a stale
   * continuation from taking effect.
   */
  async connect(): Promise<void> {
    if (this.connecting) return;
    if (this.bridge === undefined) return;
    if (isTerminalState(this.state)) return;

    const bridge = this.bridge;
    const generation = this.generation;
    this.connecting = true;
    this.clearRetryTimer();

    try {
      this.setState({
        name: 'connecting',
        attempt: this.attempt,
        phase: bridge.mode === 'relay' ? 'relay' : 'authenticating',
      });

      const transport = this.buildTransport(bridge, generation);
      if (transport === undefined) return;
      this.transport = transport;

      if (bridge.mode === 'relay') {
        this.setState({ name: 'connecting', attempt: this.attempt, phase: 'sealing' });
      }
      await transport.start();
      if (generation !== this.generation || this.transport !== transport) return;

      this.setState({ name: 'connecting', attempt: this.attempt, phase: 'authenticating' });
      await this.authenticate();
      if (generation !== this.generation || this.transport !== transport) return;

      this.setState({ name: 'connecting', attempt: this.attempt, phase: 'streaming' });
      this.openStream(generation, transport);
    } catch (error) {
      if (generation !== this.generation) return;
      this.handleFailure(error);
    } finally {
      this.connecting = false;
    }
  }

  /** Drop the session and reconnect immediately, e.g. on app foreground. */
  async reconnectNow(reason: string): Promise<void> {
    if (this.bridge === undefined || isTerminalState(this.state)) return;
    this.emit({ type: 'diagnostic', level: 'info', message: `reconnecting: ${reason}` });
    this.teardownTransport();
    this.attempt = 0;
    await this.connect();
  }

  private buildTransport(bridge: StoredBridge, generation: number): M1Transport | undefined {
    if (bridge.mode === 'relay') {
      const relayUrl = bridge.relayUrl;
      const bridgeRoutingId = bridge.bridgeRoutingId;
      const deviceRoutingId = bridge.deviceRoutingId;
      const createSocket = this.options.createSocket;
      if (
        relayUrl === undefined ||
        bridgeRoutingId === undefined ||
        deviceRoutingId === undefined ||
        createSocket === undefined
      ) {
        // `validateStoredBridge` rejects an incomplete relay record, so reaching
        // here means no socket factory was supplied — a wiring bug, not bad data.
        this.handleFailure(
          new TransportError('transport', 'relay transport is not configured on this platform'),
        );
        return undefined;
      }
      return new RelayTransport({
        relayUrl,
        routingId: deviceRoutingId,
        bridgeRoutingId,
        bridgeStaticPublicKey: bridge.bridgeKey,
        identity: { publicKey: this.options.identity.publicKey, privateKey: this.options.identity.privateKey },
        createSocket,
        onLost: (failure) => {
          if (generation !== this.generation) return;
          this.handleFailure(failure);
        },
        onDiagnostic: (level, message) => this.emit({ type: 'diagnostic', level, message }),
      });
    }

    const baseUrl = this.baseUrl ?? bridge.baseUrl;
    if (baseUrl === undefined || baseUrl.length === 0) {
      this.handleFailure(new TransportError('offline', 'no bridge address is configured'));
      return undefined;
    }
    return new LanTransport({
      baseUrl,
      ...(this.options.fetchImpl === undefined ? {} : { fetchImpl: this.options.fetchImpl }),
      ...(this.options.webSocketImpl === undefined ? {} : { webSocketImpl: this.options.webSocketImpl }),
      onDiagnostic: (level, message) => this.emit({ type: 'diagnostic', level, message }),
    });
  }

  // ── authentication ────────────────────────────────────────────────────────

  /**
   * Prove the device key and get an access token.
   *
   * Two round trips on one endpoint: a body without `signature` is a challenge
   * request, a body with one is the proof. Concurrent callers share a single
   * in-flight promise, because a second challenge would invalidate the first — the
   * bridge's nonces are single-use per device.
   */
  private async authenticate(): Promise<AuthSession> {
    const existing = this.authInFlight;
    if (existing !== undefined) return existing;
    const attempt = this.runAuthenticate();
    this.authInFlight = attempt;
    try {
      return await attempt;
    } finally {
      this.authInFlight = undefined;
    }
  }

  private async runAuthenticate(): Promise<AuthSession> {
    const bridge = this.bridge;
    const transport = this.transport;
    if (bridge === undefined) throw new M1Error({ code: 'bad-request', message: 'not paired' });
    if (transport === undefined) throw new TransportError('offline', 'no transport');

    const deviceId = this.options.identity.deviceId;
    const challenge = await this.call<AuthChallengeResponse>(transport, {
      method: 'POST',
      path: M1_PATHS.authSession,
      body: { v: 1, deviceId },
    });

    // A different bridge answering is a pin failure even though no key was checked:
    // whatever is at this address is not the bridge we paired with.
    if (challenge.bridgeId !== bridge.bridgeId) {
      throw new TransportError('pin-mismatch', 'the bridge identity does not match the stored pairing', {
        pinDetail: 'bridge-identity',
      });
    }

    const signature = signDomain(this.options.identity, 'auth', challenge.nonce, deviceId, challenge.bridgeId);
    const session = await this.call<AuthSession>(transport, {
      method: 'POST',
      path: M1_PATHS.authSession,
      body: { v: 1, deviceId, nonce: challenge.nonce, signature },
    });

    this.token = session.token;
    this.tokenExpiresAt = session.expiresAt;
    this.session = session;
    // The tier can change at the workstation between sessions, and the UI gates
    // affordances on it.
    if (session.scopeTier !== bridge.scopeTier) {
      const next: StoredBridge = { ...bridge, scopeTier: session.scopeTier };
      this.bridge = next;
      void this.options.store.write(next).catch(() => undefined);
    }
    return session;
  }

  // ── stream ────────────────────────────────────────────────────────────────

  private openStream(generation: number, transport: M1Transport): void {
    const token = this.token;
    if (token === undefined) {
      this.handleFailure(new M1Error({ code: 'unauthenticated', message: 'no token to open a stream' }));
      return;
    }

    this.subscription?.stop();
    this.subscription = transport.subscribe({
      token,
      after: this.lastBseq,
      handlers: {
        onHello: (hello) => {
          if (generation !== this.generation || this.transport !== transport) return;
          this.onHello(hello);
        },
        onEnvelope: (envelope) => {
          if (generation !== this.generation || this.transport !== transport) return;
          this.onEnvelope(envelope);
        },
        onClosed: (reason, status) => {
          if (generation !== this.generation || this.transport !== transport) return;
          this.onStreamClosed(reason, status);
        },
      },
    });
  }

  /**
   * The stream is live.
   *
   * Two things must happen here and nowhere else: adopt the rotated token, and
   * honour `resync`. Missing either leaves the session authenticated with a dead
   * token, or rendering deltas onto a stale baseline.
   */
  private onHello(hello: M1StreamHello): void {
    this.token = hello.token;
    this.tokenExpiresAt = hello.tokenExpiresAt;
    if (this.session !== undefined) {
      this.session = { ...this.session, token: hello.token, expiresAt: hello.tokenExpiresAt };
    }
    this.attempt = 0;
    this.lastBseq = Math.max(this.lastBseq, hello.lastBseq);
    this.emit({ type: 'hello', hello });

    if (hello.resync) {
      void this.runResync('window-overflow');
      return;
    }
    this.setState({ name: 'ready', lastBseq: this.lastBseq, dsh: 'up' });
  }

  private onEnvelope(envelope: M1StreamEnvelope): void {
    if (envelope.bseq > this.lastBseq) this.lastBseq = envelope.bseq;

    // Bridge control frames drive the state machine; everything else is the UI's.
    if (envelope.kind === 'bridge') {
      const frame = envelope.frame as { type?: unknown; reason?: unknown; expiresAt?: unknown } | null;
      const type = typeof frame === 'object' && frame !== null ? frame.type : undefined;
      if (type === 'device-revoked') {
        void this.applyRevocation();
        return;
      }
      if (type === 'resync-required') {
        const reason = frame?.reason === 'dsh-restarted' ? 'dsh-restarted' : 'window-overflow';
        this.emit({ type: 'envelope', envelope });
        void this.runResync(reason);
        return;
      }
      if (type === 'dsh-disconnected') {
        // The bridge is fine, the harness is not. Local history stays rendered.
        this.setState({ name: 'harness-offline' });
        this.emit({ type: 'envelope', envelope });
        return;
      }
      if (type === 'dsh-ready') {
        if (this.state.name === 'harness-offline' || this.state.name === 'ready') {
          this.setState({ name: 'ready', lastBseq: this.lastBseq, dsh: 'up' });
        }
        this.emit({ type: 'envelope', envelope });
        return;
      }
      if (type === 'token-expiring') {
        // Re-auth ahead of the 401 so the next user action does not pay for it.
        void this.refreshToken();
        this.emit({ type: 'envelope', envelope });
        return;
      }
      if (type === 'pong') return;
    }

    if (this.state.name === 'ready') {
      this.setState({ name: 'ready', lastBseq: this.lastBseq, dsh: this.state.dsh });
    }
    this.emit({ type: 'envelope', envelope });
  }

  /**
   * The stream ended.
   *
   * A 401 means the token died — re-auth and reconnect straight away rather than
   * backing off, because nothing is wrong with the path. Everything else is a
   * backed-off reconnect.
   */
  private onStreamClosed(reason: string, status?: number): void {
    this.subscription = undefined;
    if (isTerminalState(this.state)) return;

    if (status === 401 || status === 403) {
      this.token = undefined;
      this.session = undefined;
      if (status === 403) {
        // The bridge refuses this device outright. Revocation is the only cause
        // the contract defines for a paired device.
        void this.applyRevocation();
        return;
      }
      this.emit({ type: 'diagnostic', level: 'info', message: 'stream token expired; re-authenticating' });
      this.attempt = 0;
      this.teardownTransport();
      void this.connect();
      return;
    }

    this.scheduleRetry(reason);
  }

  /**
   * Re-baseline after a resync.
   *
   * The core cannot do this alone — `session.history` is per open session, which
   * only the consumer knows — so it announces, delegates, and then returns to
   * `ready`. A failing handler must not strand the session in `resyncing`.
   */
  private async runResync(reason: 'window-overflow' | 'dsh-restarted'): Promise<void> {
    if (this.resyncInFlight) return;
    this.resyncInFlight = true;
    const generation = this.generation;
    this.setState({ name: 'resyncing' });
    this.emit({ type: 'resync', reason });
    try {
      await this.options.onResync?.(reason);
    } catch (error) {
      this.emit({
        type: 'diagnostic',
        level: 'warn',
        message: `resync handler failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    } finally {
      this.resyncInFlight = false;
    }
    if (generation !== this.generation) return;
    if (this.state.name !== 'resyncing') return;
    this.setState({ name: 'ready', lastBseq: this.lastBseq, dsh: 'up' });
  }

  private async refreshToken(): Promise<void> {
    if (this.transport === undefined || this.bridge === undefined) return;
    try {
      await this.authenticate();
    } catch (error) {
      this.emit({
        type: 'diagnostic',
        level: 'warn',
        message: `pre-emptive re-auth failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  // ── requests ──────────────────────────────────────────────────────────────

  /**
   * One `/m1/rpc` call.
   *
   * Authenticates on demand, refreshes a token that is about to expire, and retries
   * exactly once on a 401 — once, because a second failure means the device key is
   * no longer accepted and looping would hammer the bridge.
   */
  async rpc<T>(method: string, payload: unknown, requestId?: string): Promise<T> {
    return this.authorized<T>({
      path: M1_PATHS.rpc,
      body: { v: 1, method, payload, ...(requestId === undefined ? {} : { requestId }) },
    });
  }

  async respondApproval(rpcId: string, outcome: 'allowed-once' | 'rejected'): Promise<void> {
    await this.authorized<unknown>({
      path: M1_PATHS.respond,
      body: { v: 1, rpcId, kind: 'approval', outcome },
    });
  }

  async respondQuestion(rpcId: string, answers: readonly QuestionAnswer[]): Promise<void> {
    await this.authorized<unknown>({
      path: M1_PATHS.respond,
      body: { v: 1, rpcId, kind: 'question', answers },
    });
  }

  private async authorized<T>(input: { path: string; body: unknown }): Promise<T> {
    const transport = this.transport;
    if (transport === undefined) throw new TransportError('offline', 'not connected');
    // Captured before the first await, like every other async continuation here: a
    // request that outlives its connection must not report on the one that replaced it.
    const generation = this.generation;
    if (this.token === undefined || this.tokenExpiresAt - this.now() < TOKEN_REFRESH_MARGIN_MS) {
      await this.authenticate();
    }

    try {
      return await this.call<T>(transport, { method: 'POST', path: input.path, body: input.body, token: this.token });
    } catch (error) {
      if (!(error instanceof M1Error) || error.status !== 401) {
        if (error instanceof TransportError) this.handleFailure(error);
        // `dsh-unavailable` on a request is a fact about the harness, not about this
        // call: the stream may still be perfectly healthy, so the transport is left
        // alone, but the UI must stop claiming to be connected. `dsh-ready` on the
        // stream is what takes it back.
        if (error instanceof M1Error && error.code === 'dsh-unavailable') this.noteHarnessDown(generation);
        throw error;
      }
      this.token = undefined;
      this.session = undefined;
      await this.authenticate();
      return await this.call<T>(transport, { method: 'POST', path: input.path, body: input.body, token: this.token });
    }
  }

  /**
   * Send a request and unwrap the `m1` envelope.
   *
   * Three outcomes are kept distinct: a bridge error (`ok: false` with a code), a
   * dsh business error (`dshError`, HTTP 200 — the harness said no), and a
   * transport failure (`TransportError` — we do not know what happened). Collapsing
   * them is how a UI ends up telling a user to check their Wi-Fi because a tool call
   * was denied.
   */
  private async call<T>(
    transport: M1Transport,
    input: { method: 'GET' | 'POST'; path: string; body?: unknown; token?: string },
  ): Promise<T> {
    const response = await transport.request(input);
    const body = response.body;

    if (typeof body === 'object' && body !== null) {
      const record = body as Record<string, unknown>;
      const dshError = record.dshError;
      if (record.ok === false && typeof dshError === 'object' && dshError !== null) {
        const fields = dshError as Record<string, unknown>;
        throw new M1Error({
          code: typeof fields.code === 'string' ? fields.code : 'dsh-business-error',
          message: typeof fields.message === 'string' ? fields.message : 'the harness rejected the request',
          status: response.status,
          isDshError: true,
        });
      }
      if (record.ok === false) {
        const error = asBridgeError(record.error);
        // `device-revoked` is a fact about the pairing, not about this call. It has
        // to reach the state machine even if the caller swallows the rejection.
        if (error.code === 'device-revoked') void this.applyRevocation();
        throw new M1Error({
          code: error.code,
          message: error.message,
          status: response.status,
          ...(error.retryAfterMs === undefined ? {} : { retryAfterMs: error.retryAfterMs }),
        });
      }
      if (record.ok === true) return record.value as T;
    }

    if (response.status >= 400) {
      throw new M1Error({
        code: response.status === 401 ? 'unauthenticated' : 'internal',
        message: `bridge request failed (${response.status})`,
        status: response.status,
      });
    }
    // An unenveloped 200 — `/m1/health` is the only such endpoint.
    return body as T;
  }

  // ── failure handling ──────────────────────────────────────────────────────

  /**
   * Turn a failure into a state.
   *
   * The whole taxonomy converges here so a caller cannot half-handle one. The
   * terminal branches (`pin-mismatch`, `routing-collision`, `rendezvous-busy`,
   * `revoked`) explicitly do NOT schedule a retry.
   */
  private handleFailure(error: unknown): void {
    if (isTerminalState(this.state)) return;

    if (error instanceof TransportError) {
      if (error.kind === 'pin-mismatch') {
        this.teardown(error.message);
        this.setState({ name: 'pin-mismatch', detail: error.pinDetail ?? 'bridge-static-key' });
        this.emit({ type: 'diagnostic', level: 'error', message: error.message });
        return;
      }
      const relayCode = error.relayCode;
      if (relayCode === 'routing-id-taken') {
        this.teardown(error.message);
        this.setState({ name: 'routing-collision', routingId: this.bridge?.deviceRoutingId ?? '' });
        return;
      }
      if (relayCode === 'rendezvous-busy') {
        this.teardown(error.message);
        this.setState({ name: 'rendezvous-busy' });
        return;
      }
      if (relayCode !== undefined) {
        // The middle of the path is refusing. The bridge may be perfectly healthy,
        // and saying "relay" rather than "offline" is the difference between a user
        // rebooting their workstation and waiting a minute.
        this.scheduleRetry(error.message, { relayCode });
        return;
      }
      this.scheduleRetry(error.message);
      return;
    }

    if (error instanceof M1Error) {
      if (error.code === 'device-revoked') {
        void this.applyRevocation();
        return;
      }
      if (error.code === 'unauthenticated') {
        // The bridge does not accept this device key. It answers `unauthenticated`
        // for both an unknown and a revoked device on purpose, so this is as far as
        // the phone can distinguish: the pairing is unusable either way.
        void this.applyRevocation();
        return;
      }
      if (error.code === 'dsh-unavailable') {
        this.setState({ name: 'harness-offline' });
        // Still retried: the bridge is up, and the harness usually comes back.
        this.scheduleRetry(error.message);
        return;
      }
      this.scheduleRetry(error.message);
      return;
    }

    this.scheduleRetry(error instanceof Error ? error.message : String(error));
  }

  /**
   * The harness went away while the path to the bridge stayed up.
   *
   * Only meaningful from `ready`: from `connecting` or `reconnecting` the state
   * machine is already working on it, and overwriting that with `harness-offline`
   * would tell the user the wrong thing about which half is broken.
   *
   * `generation` is the connection the failing request belonged to. A request that
   * resolves after a reconnect describes a bridge that is no longer ours, and letting
   * it speak would mark a healthy session offline.
   */
  private noteHarnessDown(generation: number): void {
    if (generation !== this.generation) return;
    if (this.state.name !== 'ready') return;
    this.setState({ name: 'harness-offline' });
  }

  private applyPairFailure(failure: PairFailure): void {
    switch (failure.kind) {
      case 'pairing-rejected':
        this.setState({ name: 'unpaired', reason: 'pairing-rejected' });
        return;
      case 'bad-uri':
      case 'pairing-invalid':
        this.setState({ name: 'unpaired', reason: 'pairing-invalid' });
        return;
      case 'rendezvous-busy':
        this.setState({ name: 'rendezvous-busy' });
        return;
      case 'pin-mismatch':
        this.setState({ name: 'pin-mismatch', detail: failure.detail });
        this.emit({ type: 'diagnostic', level: 'error', message: failure.message });
        return;
      case 'cancelled':
        this.setState({ name: 'unpaired', reason: 'cleared' });
        return;
      case 'relay':
        this.setState({
          name: 'relay-unavailable',
          attempt: 0,
          nextRetryAt: this.now(),
          ...(isRelayCode(failure.code) ? { code: failure.code } : {}),
        });
        this.emit({ type: 'diagnostic', level: 'warn', message: failure.message });
        return;
      default:
        // Timeout, unreachable, bridge-error, protocol: all recoverable by trying
        // again with a fresh QR, so `unpaired` is the honest resting state.
        this.setState({ name: 'unpaired', reason: 'fresh' });
        this.emit({ type: 'diagnostic', level: 'warn', message: failure.message });
    }
  }

  /** Revocation is terminal and wipes the durable route. */
  private async applyRevocation(): Promise<void> {
    if (this.state.name === 'revoked') return;
    this.teardown('device revoked');
    this.generation += 1;
    this.bridge = undefined;
    this.lastBseq = 0;
    this.setState({ name: 'revoked' });
    try {
      await this.options.store.write(undefined);
    } catch (error) {
      this.emit({
        type: 'diagnostic',
        level: 'error',
        message: `could not clear the stored pairing: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  /**
   * Back off and try again.
   *
   * `relay-unavailable` and `reconnecting` share this path because they differ only
   * in what the UI should say — the schedule is the same, and two schedules would
   * be two places to get the cap wrong.
   */
  private scheduleRetry(reason: string, options: { relayCode?: RelayErrorCode } = {}): void {
    if (isTerminalState(this.state)) return;
    this.teardownTransport();

    const attempt = this.attempt + 1;
    this.attempt = attempt;
    const base = BACKOFF_MS[Math.min(attempt - 1, BACKOFF_MS.length - 1)] ?? 30_000;
    const jitter = base * BACKOFF_JITTER * (this.random() * 2 - 1);
    const delay = Math.max(250, Math.round(base + jitter));
    const nextRetryAt = this.now() + delay;

    if (options.relayCode !== undefined) {
      this.setState({ name: 'relay-unavailable', attempt, nextRetryAt, code: options.relayCode });
    } else {
      this.setState({ name: 'reconnecting', attempt, nextRetryAt, reason });
    }

    const generation = this.generation;
    this.clearRetryTimer();
    this.retryTimer = this.setTimer(() => {
      this.retryTimer = undefined;
      if (generation !== this.generation) return;
      void this.connect();
    }, delay);
  }

  // ── teardown ──────────────────────────────────────────────────────────────

  /** Close the transport and stream, keep the pairing and the state. */
  private teardownTransport(): void {
    this.subscription?.stop();
    this.subscription = undefined;
    this.transport?.close();
    this.transport = undefined;
    this.token = undefined;
    this.session = undefined;
    this.authInFlight = undefined;
  }

  /** Everything the transport teardown does, plus any pending retry. */
  private teardown(reason: string): void {
    this.clearRetryTimer();
    this.teardownTransport();
    this.attempt = 0;
    this.emit({ type: 'diagnostic', level: 'info', message: `session ended: ${reason}` });
  }

  /** Release everything. The core is not reusable afterwards. */
  dispose(): void {
    this.generation += 1;
    this.clearRetryTimer();
    this.teardownTransport();
    this.listeners.clear();
  }

  private clearRetryTimer(): void {
    if (this.retryTimer === undefined) return;
    const clear = this.options.clearTimer ?? ((handle: unknown) => clearTimeout(handle as ReturnType<typeof setTimeout>));
    clear(this.retryTimer);
    this.retryTimer = undefined;
  }

  private setTimer(handler: () => void, ms: number): unknown {
    const set = this.options.setTimer ?? ((callback: () => void, delay: number) => setTimeout(callback, delay));
    return set(handler, ms);
  }

  // ── emission ──────────────────────────────────────────────────────────────

  /**
   * Publish a state, unless it is the one already published.
   *
   * The dedupe matters because this feeds React state directly: `connect()` sets
   * `connecting/authenticating` before and after `transport.start()`, which is one
   * transition on the relay path and a no-op repeat on the LAN path. Without the
   * check, every LAN connect renders the same screen twice.
   *
   * Compared by serialization rather than by reference: every state here is a fresh
   * flat object of primitives, so this is both cheap and exact.
   */
  private setState(state: M1ClientState): void {
    if (JSON.stringify(state) === JSON.stringify(this.state)) return;
    this.state = state;
    this.emit({ type: 'state', state });
  }

  private emit(event: M1CoreEvent): void {
    for (const listener of [...this.listeners]) {
      try {
        listener(event);
      } catch {
        // A listener that throws is the consumer's bug, and must not take down the
        // protocol machinery or stop the other listeners from being told.
      }
    }
  }
}

const RELAY_CODES: readonly string[] = [
  'bad-message',
  'routing-id-taken',
  'not-registered',
  'peer-offline',
  'quota-exceeded',
  'rendezvous-busy',
  'internal',
];

function isRelayCode(value: string): value is RelayErrorCode {
  return RELAY_CODES.includes(value);
}

function asBridgeError(value: unknown): BridgeError {
  if (typeof value !== 'object' || value === null) {
    return { code: 'internal', message: 'the bridge refused the request' };
  }
  const record = value as Record<string, unknown>;
  const code = typeof record.code === 'string' ? record.code : 'internal';
  return {
    code: code as BridgeErrorCode,
    message: typeof record.message === 'string' ? record.message : 'the bridge refused the request',
    ...(typeof record.method === 'string' ? { method: record.method } : {}),
    ...(typeof record.retryAfterMs === 'number' ? { retryAfterMs: record.retryAfterMs } : {}),
  };
}

/** Re-exported so consumers do not need a second import for the response envelope. */
export type { M1Response };

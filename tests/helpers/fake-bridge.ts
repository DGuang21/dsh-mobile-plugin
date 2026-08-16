/**
 * A Mode A bridge double: enough of `/m1` to drive `M1Core` end to end.
 *
 * The core's whole job is policy — when to re-auth, when to back off, when to stop
 * for good — and every one of those decisions is triggered by a bridge response.
 * This double exists so a test can produce the *exact* response that triggers the
 * branch under test (a 401 on the third request, a hello with `resync: true`, a
 * `device-revoked` envelope mid-stream) without standing up a real bridge and
 * hoping it can be talked into that state.
 *
 * Mode A rather than Mode B on purpose: `tests/m1-relay.test.ts` already covers the
 * sealed tunnel in detail, and driving the core over `fetch` keeps these tests about
 * the state machine rather than about crypto.
 */

import { verifySignatureB64 } from '../../src/m1/crypto';
import { M1_PATHS } from '../../src/m1/paths';
import type { M1StreamEnvelope, M1StreamHello, ScopeTier } from '../../src/m1/types';

/** One recorded request, so a test can assert on order and auth headers. */
export interface RecordedRequest {
  method: string;
  path: string;
  token: string | undefined;
  body: Record<string, unknown> | undefined;
}

/** What `fetchImpl` should do for the next matching request. */
export type ResponseStep =
  | { kind: 'json'; status: number; body: unknown }
  /** A body that is not JSON at all — a captive portal or proxy error page. */
  | { kind: 'text'; status: number; text: string }
  /** Reject the `fetch` itself: no route to host. */
  | { kind: 'network'; message: string };

export const BRIDGE_ID = 'bridge-under-test';
export const NONCE = 'nonce-aaaaaaaaaaaaaaaaaaaaaaaaaaaa';

export function jsonOk(value: unknown): ResponseStep {
  return { kind: 'json', status: 200, body: { v: 1, ok: true, value } };
}

export function jsonError(
  status: number,
  code: string,
  message = 'refused',
  extra: Record<string, unknown> = {},
): ResponseStep {
  return { kind: 'json', status, body: { v: 1, ok: false, error: { code, message, ...extra } } };
}

/** A `dshError` body: HTTP 200, `ok: false`, the harness said no. */
export function dshBusinessError(code: string, message = 'the harness said no'): ResponseStep {
  return { kind: 'json', status: 200, body: { v: 1, ok: false, dshError: { code, message } } };
}

export function helloFrame(overrides: Partial<M1StreamHello> = {}): M1StreamHello {
  return {
    v: 1,
    kind: 'hello',
    bridgeId: BRIDGE_ID,
    token: 'rotated-token-1',
    tokenExpiresAt: 10_000_000,
    lastBseq: 0,
    resync: false,
    pendingCount: 0,
    ...overrides,
  };
}

export function envelopeFrame(
  bseq: number,
  kind: M1StreamEnvelope['kind'],
  frame: unknown,
  rpcId?: string,
): M1StreamEnvelope {
  return { v: 1, bseq, kind, frame, ...(rpcId === undefined ? {} : { rpcId }) };
}

/**
 * A stream socket double.
 *
 * `LanTransport` drives this through the `onmessage`/`onclose`/`onerror` properties
 * (not `addEventListener`), so the double only needs those three plus `close`.
 */
export class FakeStreamSocket {
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onclose: ((event: { code?: number; reason?: string }) => void) | null = null;
  closed = false;

  constructor(
    readonly url: string,
    readonly protocols: string[] | undefined,
  ) {}

  /** Deliver a frame as the bridge would. */
  deliver(value: unknown): void {
    this.onmessage?.({ data: JSON.stringify(value) });
  }

  /** Deliver a raw string, for malformed-frame tests. */
  deliverRaw(data: string): void {
    this.onmessage?.({ data });
  }

  fireClose(code = 1006, reason = ''): void {
    this.closed = true;
    this.onclose?.({ code, reason });
  }

  fireError(): void {
    this.onerror?.({});
  }

  close(): void {
    this.closed = true;
  }

  /** The `after=` cursor the transport asked for. */
  get after(): number {
    const match = /after=(\d+)/.exec(this.url);
    return match === null ? -1 : Number(match[1]);
  }

  /** The token the transport smuggled into the subprotocol list. */
  get tokenProtocol(): string | undefined {
    return this.protocols?.find((entry) => entry.startsWith('dshm.token.'))?.slice('dshm.token.'.length);
  }
}

export interface FakeBridgeOptions {
  bridgeId?: string;
  /** Tier the auth response reports, so a test can drive the write-back. */
  scopeTier?: ScopeTier;
  /** Token issued by `/m1/auth/session`. Bumped per call so rotation is visible. */
  tokenExpiresAt?: number;
}

/**
 * A scripted `/m1` bridge.
 *
 * Auth is answered automatically (and the device proof is really verified, so a
 * signing regression fails here rather than silently passing); every other path is
 * answered from a per-path queue, falling back to a queue-empty error that names the
 * path — a much better failure than an opaque hang.
 */
export class FakeBridge {
  readonly requests: RecordedRequest[] = [];
  readonly sockets: FakeStreamSocket[] = [];
  private readonly steps = new Map<string, ResponseStep[]>();
  private readonly bridgeId: string;
  private scopeTier: ScopeTier;
  private authCount = 0;
  private tokenExpiresAt: number;
  /** Set to fail the next N auth challenges with this step. */
  private authOverride: ResponseStep[] = [];
  private socketFactoryThrows: string | undefined;

  constructor(
    private readonly devicePublicKey: string,
    options: FakeBridgeOptions = {},
  ) {
    this.bridgeId = options.bridgeId ?? BRIDGE_ID;
    // Matches the tier in the test fixtures, so an unchanged tier does not trigger
    // the write-back path and make every test look like it persisted something.
    this.scopeTier = options.scopeTier ?? 'default';
    this.tokenExpiresAt = options.tokenExpiresAt ?? 10_000_000;
  }

  /** Queue a response for `path`. Consumed in order. */
  queue(path: string, ...steps: ResponseStep[]): this {
    const existing = this.steps.get(path) ?? [];
    existing.push(...steps);
    this.steps.set(path, existing);
    return this;
  }

  /** Queue a response for the *auth* endpoint, ahead of the automatic behaviour. */
  queueAuth(...steps: ResponseStep[]): this {
    this.authOverride.push(...steps);
    return this;
  }

  setScopeTier(tier: ScopeTier): void {
    this.scopeTier = tier;
  }

  setTokenExpiry(at: number): void {
    this.tokenExpiresAt = at;
  }

  /** Make the WebSocket constructor throw, as RN does for a bad URL. */
  failSocketFactory(message: string): void {
    this.socketFactoryThrows = message;
  }

  /** How many tokens have been issued. One per successful auth. */
  get issuedTokens(): number {
    return this.authCount;
  }

  get lastSocket(): FakeStreamSocket | undefined {
    return this.sockets[this.sockets.length - 1];
  }

  requestsTo(path: string): RecordedRequest[] {
    return this.requests.filter((entry) => entry.path === path);
  }

  /** A `fetch` standing in for the bridge. */
  readonly fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    const path = url.replace(/^https?:\/\/[^/]+/, '');
    const method = init?.method ?? 'GET';
    const rawBody = typeof init?.body === 'string' ? init.body : undefined;
    const body = rawBody === undefined ? undefined : (JSON.parse(rawBody) as Record<string, unknown>);
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const auth = headers.authorization;
    this.requests.push({
      method,
      path,
      token: auth?.startsWith('Bearer ') === true ? auth.slice('Bearer '.length) : undefined,
      body,
    });

    const step = this.nextStep(path, body);
    if (step.kind === 'network') throw new Error(step.message);
    const text = step.kind === 'text' ? step.text : JSON.stringify(step.body);
    return {
      status: step.status,
      text: async () => text,
    } as Response;
  };

  /**
   * A `WebSocket` constructor standing in for `/m1/stream`.
   *
   * A `function`, not an arrow: `LanTransport` calls `new this.webSocketImpl(...)`,
   * and an arrow is not constructible. Returning an object from a constructor makes
   * `new` yield that object, which is how the double gets recorded.
   */
  readonly webSocketImpl = ((): typeof WebSocket => {
    const bridge = this;
    function StreamSocketCtor(url: string, protocols?: string[]): FakeStreamSocket {
      if (bridge.socketFactoryThrows !== undefined) throw new Error(bridge.socketFactoryThrows);
      const socket = new FakeStreamSocket(url, protocols);
      bridge.sockets.push(socket);
      return socket;
    }
    return StreamSocketCtor as unknown as typeof WebSocket;
  })();

  private nextStep(path: string, body: Record<string, unknown> | undefined): ResponseStep {
    if (path === M1_PATHS.authSession) {
      const override = this.authOverride.shift();
      if (override !== undefined) return override;
      return this.answerAuth(body);
    }
    const queue = this.steps.get(path);
    const next = queue?.shift();
    if (next !== undefined) return next;
    return jsonError(500, 'internal', `fake bridge has no queued response for ${path}`);
  }

  /**
   * Answer the two-step auth exchange.
   *
   * The proof is verified for real: `signDomain(identity, 'auth', nonce, deviceId,
   * bridgeId)` must check out against the device public key. That makes this double
   * a regression test for the signing path as well as a fixture.
   */
  private answerAuth(body: Record<string, unknown> | undefined): ResponseStep {
    const deviceId = typeof body?.deviceId === 'string' ? body.deviceId : '';
    const signature = body?.signature;
    if (signature === undefined) {
      return jsonOk({ nonce: NONCE, bridgeId: this.bridgeId, expiresAt: this.tokenExpiresAt });
    }
    if (typeof signature !== 'string' || typeof body?.nonce !== 'string') {
      return jsonError(400, 'bad-request', 'malformed proof');
    }
    const message = authMessage(body.nonce, deviceId, this.bridgeId);
    if (!verifySignatureB64(this.devicePublicKey, message, signature)) {
      return jsonError(401, 'unauthenticated', 'device proof did not verify');
    }
    this.authCount += 1;
    return jsonOk({
      token: `access-token-${this.authCount}`,
      expiresAt: this.tokenExpiresAt,
      deviceId,
      scopeTier: this.scopeTier,
      allowedMethods: ['session.list', 'session.history', 'session.send'],
      slashCommandsEnabled: true,
    });
  }
}

/**
 * Rebuild the message `signDomain(identity, 'auth', ...)` signs.
 *
 * Duplicated from `domainMessage` deliberately: if the framing changes, this double
 * stops verifying and the test fails, which is the signal we want. Importing the
 * production helper would make the assertion vacuous.
 */
function authMessage(nonce: string, deviceId: string, bridgeId: string): Uint8Array {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [encoder.encode('dshm/auth')];
  for (const part of [nonce, deviceId, bridgeId]) {
    const bytes = encoder.encode(part);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, bytes.byteLength, false);
    chunks.push(length, bytes);
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

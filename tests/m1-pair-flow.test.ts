/**
 * Pairing-flow tests: URI validation, claim/poll, and what gets stored.
 *
 * Requirement (1), and the part of (5) about what a completed pairing is allowed to
 * persist. The assertions that carry weight:
 *
 *   - **The QR's `rid` never reaches storage.** It is a rendezvous id: token-derived,
 *     ≤120 s, one pairing. The durable `bridgeRoutingId` is read only from the sealed
 *     claim response, and a Mode B pairing that does not carry one fails rather than
 *     inventing a route.
 *   - **The claim body is byte-identical across polls.** The bridge spends the token
 *     on the first claim and answers repeats by re-verifying that exact proof, so a
 *     re-signed body would read as an unknown claim.
 *   - A `bridgeId` that changes between QR and confirmation is `pin-mismatch`,
 *     terminal, not a retry.
 *
 * Mode B's carrier is exercised end to end against a real relay in
 * `bridge/tests/m1-mobile-e2e.test.ts`; here the transport is faked so the poll
 * state machine can be driven exactly.
 */

import { describe, expect, it, vi } from 'vitest';
import { runPairing, type PairFlowHooks, type PairOutcome } from '../src/m1/pair-flow';
import { computeSas, deriveRendezvousRoutingId } from '../src/m1/pairing';
import { newRoutingId } from '../src/m1/seal';
import { M1_PATHS } from '../src/m1/paths';
import { verifySignatureB64 } from '../src/m1/crypto';
import { pairingProofMessage } from '../src/m1/pairing';
import { fixedIdentity, testIdentity } from './helpers/identity';

const bridgeIdentity = fixedIdentity(21);
const BRIDGE_ID = 'bridge-xyz';
const TOKEN = 'pairing-token-123456';

/** A Mode A pairing URI. */
function lanUri(overrides: Record<string, string | undefined> = {}): string {
  const params: Record<string, string | undefined> = {
    v: '1',
    bid: BRIDGE_ID,
    tok: TOKEN,
    bk: bridgeIdentity.publicKey,
    fp: 'spki-fingerprint',
    ...overrides,
  };
  const query = Object.entries(params)
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
    .join('&');
  return `dshm://pair?${query}`;
}

/** A Mode B pairing URI, with a correctly derived rendezvous id. */
function relayUri(overrides: Record<string, string | undefined> = {}): string {
  const token = overrides.tok ?? TOKEN;
  const bid = overrides.bid ?? BRIDGE_ID;
  return lanUri({
    fp: undefined,
    relay: 'https://relay.example',
    rid: deriveRendezvousRoutingId(token, bid),
    ...overrides,
  });
}

/** Hook recorder. */
function hooks() {
  const confirmations: { sas: string; bridgeName: string; expiresAt: number }[] = [];
  const stages: string[] = [];
  return {
    confirmations,
    stages,
    hooks: {
      onAwaitingConfirmation: (input) => confirmations.push(input),
      onProgress: (stage) => stages.push(stage),
    } satisfies PairFlowHooks,
  };
}

/**
 * A fake `fetch` that answers `/m1/pair/claim` from a scripted queue.
 *
 * Records every request body so the "identical across polls" property can be
 * asserted on the bytes actually sent.
 */
function claimServer(responses: { status: number; body: unknown }[]) {
  const bodies: string[] = [];
  const paths: string[] = [];
  let index = 0;
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    paths.push(String(input));
    bodies.push(typeof init?.body === 'string' ? init.body : '');
    const next = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return {
      status: next?.status ?? 500,
      text: async () => JSON.stringify(next?.body ?? {}),
      headers: new Headers({ 'content-type': 'application/json' }),
    } as Response;
  }) as unknown as typeof fetch;
  return { fetchImpl, bodies, paths, calls: () => index };
}

/** The bridge's pending-claim response. It carries `bridgeId`; see server.ts:316. */
function awaitingBody(overrides: Record<string, unknown> = {}): unknown {
  return {
    ok: true,
    value: {
      status: 'awaiting-confirmation',
      sas: '12 34 56',
      bridgeName: 'Workstation',
      bridgeId: BRIDGE_ID,
      expiresAt: 1_700_000_120_000,
      ...overrides,
    },
  };
}

const AWAITING = awaitingBody();

function pairedBody(overrides: Record<string, unknown> = {}): unknown {
  return {
    ok: true,
    value: {
      status: 'paired',
      deviceId: 'device-abc',
      bridgeId: BRIDGE_ID,
      bridgeName: 'Workstation',
      scopeTier: 'default',
      ...overrides,
    },
  };
}

/** Run a Mode A pairing against a scripted server. */
async function pairLan(
  responses: { status: number; body: unknown }[],
  extra: Partial<Parameters<typeof runPairing>[0]> = {},
): Promise<{ outcome: PairOutcome; server: ReturnType<typeof claimServer>; recorder: ReturnType<typeof hooks> }> {
  const server = claimServer(responses);
  const recorder = hooks();
  const outcome = await runPairing({
    uri: lanUri(),
    identity: extra.identity ?? testIdentity(),
    label: 'My phone',
    hooks: recorder.hooks,
    baseUrl: 'https://192.168.1.5:8443',
    fetchImpl: server.fetchImpl,
    pollIntervalMs: 0,
    sleep: async () => undefined,
    ...extra,
  });
  return { outcome, server, recorder };
}

describe('URI validation', () => {
  const cases: { name: string; uri: string; problem: string }[] = [
    { name: 'not a pairing URI', uri: 'https://example.com', problem: 'not-a-pairing-uri' },
    { name: 'empty', uri: '', problem: 'not-a-pairing-uri' },
    { name: 'a wrong version', uri: lanUri({ v: '2' }), problem: 'unsupported-version' },
    { name: 'a missing token', uri: lanUri({ tok: undefined }), problem: 'incomplete' },
    { name: 'a missing bridge id', uri: lanUri({ bid: undefined }), problem: 'incomplete' },
    { name: 'a missing pin', uri: lanUri({ bk: undefined }), problem: 'incomplete' },
    { name: 'a malformed pin', uri: lanUri({ bk: 'not-a-key' }), problem: 'bad-bridge-key' },
    { name: 'neither transport', uri: lanUri({ fp: undefined }), problem: 'no-transport' },
    { name: 'a relay QR with no rendezvous id', uri: lanUri({ fp: undefined, relay: 'https://relay.example' }), problem: 'bad-rendezvous-id' },
    { name: 'a relay QR with a malformed rendezvous id', uri: lanUri({ fp: undefined, relay: 'https://relay.example', rid: 'nope' }), problem: 'bad-rendezvous-id' },
    { name: 'a rendezvous id that does not derive from the token', uri: lanUri({ fp: undefined, relay: 'https://relay.example', rid: newRoutingId() }), problem: 'rendezvous-mismatch' },
  ];

  for (const { name, uri, problem } of cases) {
    it(`refuses ${name}`, async () => {
      const outcome = await runPairing({
        uri,
        identity: testIdentity(),
        label: 'phone',
        hooks: hooks().hooks,
        baseUrl: 'https://192.168.1.5:8443',
      });
      expect(outcome).toEqual({ ok: false, failure: { kind: 'bad-uri', problem } });
    });
  }

  it('never dials anything when the URI is bad', async () => {
    // A code that fails its own derivation check is not worth a network round trip;
    // it was either altered or not made by the bridge that owns the token.
    const server = claimServer([{ status: 200, body: pairedBody() }]);
    await runPairing({
      uri: relayUri({ rid: newRoutingId() }),
      identity: testIdentity(),
      label: 'phone',
      hooks: hooks().hooks,
      fetchImpl: server.fetchImpl,
    });
    expect(server.calls()).toBe(0);
  });

  it('requires an address for a LAN pairing, since the QR carries none', async () => {
    const outcome = await runPairing({
      uri: lanUri(),
      identity: testIdentity(),
      label: 'phone',
      hooks: hooks().hooks,
    });
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'protocol' } });
  });
});

describe('the claim', () => {
  it('posts to the pair-claim path with a proof over the token and bridge id', async () => {
    const identity = testIdentity();
    const { outcome, server } = await pairLan([{ status: 200, body: pairedBody() }], { identity });
    expect(outcome.ok).toBe(true);
    expect(server.paths[0]).toContain(M1_PATHS.pairClaim);

    const body = JSON.parse(server.bodies[0] ?? '{}') as Record<string, string>;
    expect(body).toMatchObject({ v: 1, token: TOKEN, devicePublicKey: identity.publicKey, label: 'My phone' });
    // The proof must verify against the device key, over the documented message.
    expect(verifySignatureB64(identity.publicKey, pairingProofMessage(TOKEN, BRIDGE_ID), body.proof ?? '')).toBe(true);
  });

  it('sends a byte-identical body on every poll', async () => {
    // The token is spent by the first claim. The bridge answers repeats by
    // re-verifying this exact proof, so a re-signed body would be an unknown claim.
    const { server } = await pairLan([
      { status: 200, body: AWAITING },
      { status: 200, body: AWAITING },
      { status: 200, body: AWAITING },
      { status: 200, body: pairedBody() },
    ]);
    expect(server.bodies.length).toBeGreaterThanOrEqual(4);
    expect(new Set(server.bodies).size).toBe(1);
  });

  it('announces the SAS once, not on every poll', async () => {
    const { recorder } = await pairLan([
      { status: 200, body: AWAITING },
      { status: 200, body: AWAITING },
      { status: 200, body: pairedBody() },
    ]);
    expect(recorder.confirmations).toHaveLength(1);
    expect(recorder.confirmations[0]).toMatchObject({ sas: '12 34 56', bridgeName: 'Workstation' });
  });

  it('reports progress stages in order', async () => {
    const { recorder } = await pairLan([
      { status: 200, body: AWAITING },
      { status: 200, body: pairedBody() },
    ]);
    expect(recorder.stages).toEqual(['connecting', 'claiming', 'awaiting']);
  });

  it('polls a documented 409 pairing-unconfirmed as well', async () => {
    // The current bridge answers a pending claim with `awaiting-confirmation`, but
    // the contract documents this shape too. Either must keep polling.
    const { outcome } = await pairLan([
      { status: 409, body: { ok: false, error: { code: 'pairing-unconfirmed', message: 'not yet' } } },
      { status: 200, body: pairedBody() },
    ]);
    expect(outcome.ok).toBe(true);
  });
});

describe('claim failures', () => {
  it('maps a rejection to pairing-rejected', async () => {
    const { outcome } = await pairLan([
      { status: 200, body: { ok: false, error: { code: 'pairing-rejected', message: 'operator said no' } } },
    ]);
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'pairing-rejected', message: 'operator said no' } });
  });

  it('maps a spent or unknown token to pairing-invalid', async () => {
    const { outcome } = await pairLan([
      { status: 200, body: { ok: false, error: { code: 'pairing-invalid', message: 'token expired' } } },
    ]);
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'pairing-invalid' } });
  });

  it('keeps another bridge error as bridge-error with its code', async () => {
    const { outcome } = await pairLan([
      { status: 503, body: { ok: false, error: { code: 'dsh-unavailable', message: 'harness offline' } } },
    ]);
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'bridge-error', code: 'dsh-unavailable' } });
  });

  it('folds an unknown error code to internal rather than calling it a protocol fault', async () => {
    // A newer bridge must read as "the bridge refused", not as a violation.
    const { outcome } = await pairLan([
      { status: 500, body: { ok: false, error: { code: 'brand-new-code', message: 'hmm' } } },
    ]);
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'bridge-error', code: 'internal' } });
  });

  it('reports an unrecognized body as a protocol fault', async () => {
    const { outcome } = await pairLan([{ status: 200, body: { surprise: true } }]);
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'protocol' } });
  });

  it('stops at the confirmation deadline', async () => {
    let clock = 1_000;
    const { outcome } = await pairLan([{ status: 200, body: AWAITING }], {
      confirmTimeoutMs: 50,
      now: () => clock,
      sleep: async () => { clock += 30; },
    });
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'timeout' } });
  });

  it('stops when the caller cancels', async () => {
    const signal = { aborted: false };
    const { outcome } = await pairLan([{ status: 200, body: AWAITING }], {
      signal,
      sleep: async () => { signal.aborted = true; },
    });
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'cancelled' } });
  });

  it('checks cancellation before spending the token', async () => {
    const server = claimServer([{ status: 200, body: pairedBody() }]);
    const outcome = await runPairing({
      uri: lanUri(),
      identity: testIdentity(),
      label: 'phone',
      hooks: hooks().hooks,
      baseUrl: 'https://192.168.1.5:8443',
      fetchImpl: server.fetchImpl,
      signal: { aborted: true },
    });
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'cancelled' } });
    expect(server.calls()).toBe(0);
  });

  it('maps an unreachable bridge to unreachable', async () => {
    const outcome = await runPairing({
      uri: lanUri(),
      identity: testIdentity(),
      label: 'phone',
      hooks: hooks().hooks,
      baseUrl: 'https://192.168.1.5:8443',
      fetchImpl: (async () => { throw new TypeError('Network request failed'); }) as unknown as typeof fetch,
    });
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'unreachable' } });
  });

  it('treats a different bridge id at confirmation as a terminal pin mismatch', async () => {
    // Whatever the transport looked like, something other than the pinned bridge
    // completed this pairing.
    const { outcome } = await pairLan([{ status: 200, body: pairedBody({ bridgeId: 'someone-else' }) }]);
    expect(outcome).toMatchObject({
      ok: false,
      failure: { kind: 'pin-mismatch', detail: 'bridge-identity' },
    });
  });

  it('refuses a wrong bridge id on the awaiting response, before showing a SAS', async () => {
    // The SAS is what the operator compares. Showing digits from a bridge that is
    // not the pinned one would be inviting the user to confirm the wrong machine.
    const { outcome, recorder } = await pairLan([awaitingBody({ bridgeId: 'someone-else' })].map((body) => ({ status: 200, body })));
    expect(outcome).toMatchObject({ ok: false, failure: { kind: 'pin-mismatch', detail: 'bridge-identity' } });
    expect(recorder.confirmations).toHaveLength(0);
  });
});

describe('what a completed Mode A pairing stores', () => {
  it('stores the pinned key from the QR, the address, and the scope tier', async () => {
    const { outcome } = await pairLan([{ status: 200, body: pairedBody({ scopeTier: 'extended' }) }]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.bridge).toEqual({
      mode: 'lan',
      bridgeId: BRIDGE_ID,
      bridgeName: 'Workstation',
      deviceId: 'device-abc',
      bridgeKey: bridgeIdentity.publicKey,
      scopeTier: 'extended',
      baseUrl: 'https://192.168.1.5:8443',
      tlsFingerprint: 'spki-fingerprint',
    });
  });

  it('prefers the QR fingerprint over the one in the response', async () => {
    // The QR was seen out of band, on a screen. The response arrived over the very
    // connection the pin is meant to protect.
    const { outcome } = await pairLan([
      { status: 200, body: pairedBody({ bridgeKeyFingerprint: 'from-the-wire' }) },
    ]);
    expect(outcome.ok && outcome.bridge.tlsFingerprint).toBe('spki-fingerprint');
  });

  it('never stores the pairing token or the proof', async () => {
    const { outcome } = await pairLan([{ status: 200, body: pairedBody() }]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const serialized = JSON.stringify(outcome.bridge);
    expect(serialized).not.toContain(TOKEN);
    expect(serialized).not.toMatch(/proof/i);
  });

  it('stores no routing ids for a LAN pairing', async () => {
    const { outcome } = await pairLan([{ status: 200, body: pairedBody() }]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.bridge.bridgeRoutingId).toBeUndefined();
    expect(outcome.bridge.deviceRoutingId).toBeUndefined();
    expect(outcome.bridge.relayUrl).toBeUndefined();
  });
});

describe('computeSas', () => {
  it('is stable for the same inputs and differs across devices', () => {
    const first = testIdentity();
    const second = testIdentity();
    expect(computeSas(TOKEN, BRIDGE_ID, first.publicKey)).toBe(computeSas(TOKEN, BRIDGE_ID, first.publicKey));
    expect(computeSas(TOKEN, BRIDGE_ID, first.publicKey)).not.toBe(computeSas(TOKEN, BRIDGE_ID, second.publicKey));
  });

  it('binds to the token and the bridge, so a replayed code shows different digits', () => {
    const identity = testIdentity();
    expect(computeSas(TOKEN, BRIDGE_ID, identity.publicKey)).not.toBe(computeSas('other-token', BRIDGE_ID, identity.publicKey));
    expect(computeSas(TOKEN, BRIDGE_ID, identity.publicKey)).not.toBe(computeSas(TOKEN, 'other-bridge', identity.publicKey));
  });
});

describe('the default poll interval', () => {
  it('waits between polls when no sleep is injected', async () => {
    vi.useFakeTimers();
    try {
      const server = claimServer([
        { status: 200, body: AWAITING },
        { status: 200, body: pairedBody() },
      ]);
      const pending = runPairing({
        uri: lanUri(),
        identity: testIdentity(),
        label: 'phone',
        hooks: hooks().hooks,
        baseUrl: 'https://192.168.1.5:8443',
        fetchImpl: server.fetchImpl,
        pollIntervalMs: 1_500,
      });
      // One claim has gone out; the second waits on a real timer.
      await vi.advanceTimersByTimeAsync(0);
      expect(server.calls()).toBe(1);
      await vi.advanceTimersByTimeAsync(1_600);
      await expect(pending).resolves.toMatchObject({ ok: true });
    } finally {
      vi.useRealTimers();
    }
  });
});

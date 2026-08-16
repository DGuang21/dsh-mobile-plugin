import { describe, expect, it } from 'vitest';
import { DshApiClient } from '../src/dsh/client.ts';
import { DshRpcError, DshRpcIdMismatchError, DshTransportError } from '../src/dsh/errors.ts';
import { FakeDsh } from './fake-dsh.ts';

const BASE = 'http://127.0.0.1:3080';

function clientFor(fake: FakeDsh, rpcId = 'rpc-1'): DshApiClient {
  return new DshApiClient({ baseUrl: BASE, fetchImpl: fake.fetch, rpcIdFactory: () => rpcId });
}

describe('DshApiClient unary contract', () => {
  it('posts the ClientRequest full form with the JSON media type', async () => {
    const fake = new FakeDsh({ methods: { 'session.list': () => ({ items: [] }) } });
    const client = clientFor(fake);

    await client.callOrThrow('session.list', {});

    expect(fake.requests).toHaveLength(1);
    const request = fake.requests[0]!;
    expect(request.path).toBe('/api/session.list');
    expect(request.contentType).toBe('application/json');
    expect(request.body).toEqual({
      type: 'client-request',
      rpcId: 'rpc-1',
      method: 'session.list',
      payload: {},
    });
  });

  it('sends a loopback Host header so the upstream trust fence passes', async () => {
    const fake = new FakeDsh({ methods: { 'host.describe': () => ({ canOpenPath: false }) } });
    await clientFor(fake).describeHost();
    expect(fake.requests[0]!.host).toBe('127.0.0.1:3080');
  });

  it('returns the business value on ok results', async () => {
    const fake = new FakeDsh({ methods: { 'session.create': () => ({ sessionId: 's1' }) } });
    await expect(clientFor(fake).callOrThrow('session.create', {})).resolves.toEqual({ sessionId: 's1' });
  });

  it('folds result.ok === false into a typed DshRpcError, not a transport error', async () => {
    const fake = new FakeDsh({
      errors: {
        'session.prompt': {
          code: 'session-not-found',
          message: 'no such session',
          details: { sessionId: 'ghost' },
        },
      },
    });

    await expect(clientFor(fake).callOrThrow('session.prompt', { sessionId: 'ghost' })).rejects.toThrowError(
      DshRpcError,
    );

    // The closed error code and its details survive the fold, so our own
    // protocol can forward them verbatim.
    const result = await clientFor(fake).call('session.prompt', { sessionId: 'ghost' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('session-not-found');
      expect(result.error.details).toEqual({ sessionId: 'ghost' });
    }
  });

  it('throws on an rpcId mismatch instead of trusting the response', async () => {
    const fake = new FakeDsh({
      methods: { 'session.list': () => ({ items: [] }) },
      forceRpcId: 'someone-elses-id',
    });

    await expect(clientFor(fake).call('session.list', {})).rejects.toThrowError(DshRpcIdMismatchError);
  });

  it('treats an unknown method (404) as a non-retryable transport failure', async () => {
    const fake = new FakeDsh({ methods: {} });
    const error = await clientFor(fake)
      .call('session.doesNotExist', {})
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(DshTransportError);
    expect((error as DshTransportError).detail.status).toBe(404);
    expect((error as DshTransportError).retryable).toBe(false);
  });

  it('classifies a 5xx as retryable and a 415 as not', () => {
    expect(new DshTransportError('x', { status: 503 }).retryable).toBe(true);
    expect(new DshTransportError('x', { status: 415 }).retryable).toBe(false);
    // No status at all means a socket-level failure: reachability may return.
    expect(new DshTransportError('x').retryable).toBe(true);
  });

  it('surfaces a method/path disagreement as the upstream bad-request error', async () => {
    const fake = new FakeDsh({ methods: { 'session.list': () => ({}) } });
    const client = new DshApiClient({
      baseUrl: BASE,
      fetchImpl: async (input, init) => {
        // Rewrite the envelope method so it no longer matches the path.
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        body.method = 'session.search';
        return fake.fetch(input, { ...init, body: JSON.stringify(body) });
      },
    });

    const result = await client.call('session.list', {});
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('bad-request');
  });
});

describe('DshApiClient respond', () => {
  it('echoes the frame rpcId verbatim and never mints a new one', async () => {
    const fake = new FakeDsh();
    const client = new DshApiClient({
      baseUrl: BASE,
      fetchImpl: fake.fetch,
      rpcIdFactory: () => 'freshly-minted-must-not-appear',
    });

    await client.respond('rpc-from-frame', { sessionId: 's1', approvalId: 'a1', outcome: 'allowed-once' });

    const request = fake.requests[0]!;
    expect(request.path).toBe('/api/respond');
    expect(request.body).toEqual({
      type: 'client-response',
      rpcId: 'rpc-from-frame',
      result: {
        ok: true,
        value: { sessionId: 's1', approvalId: 'a1', outcome: 'allowed-once' },
      },
    });
  });

  it('returns not-pending as a value, because a late answer is not an error', async () => {
    const fake = new FakeDsh({ respondReceipt: { accepted: false, reason: 'not-pending' } });
    const client = new DshApiClient({ baseUrl: BASE, fetchImpl: fake.fetch });

    await expect(client.respond('rpc-1', {})).resolves.toEqual({
      accepted: false,
      reason: 'not-pending',
    });
  });
});

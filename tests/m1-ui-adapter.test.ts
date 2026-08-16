/**
 * The translation layer between the protocol core and the screens.
 *
 * `useDsh.tsx` is where a bridge frame becomes something a React component can render,
 * and the part of it that carries real risk is `rpcId` propagation. An approval or a
 * question that arrives without its `rpcId` is one the user can never answer: the reply
 * has nowhere to go, and the harness stays blocked on the workstation until it times
 * out. So these tests are mostly about that one field surviving.
 *
 * The React wiring itself is not exercised here — no renderer is installed, and the
 * hook is delegation rather than logic. What is testable without one is the pure frame →
 * UI mapping, which is where the bugs would be.
 */

import { describe, expect, it, vi } from 'vitest';
import type { M1StreamEnvelope } from '../src/m1/types';

// The hook module pulls in the core, which pulls in expo. Neither is reachable here and
// neither is needed: only the pure exports are under test.
vi.mock('expo-secure-store', () => ({
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'whenUnlockedThisDeviceOnly',
  getItemAsync: async () => null,
  setItemAsync: async () => undefined,
  deleteItemAsync: async () => undefined,
}));
vi.mock('expo-crypto', () => ({
  getRandomBytes: (length: number) => new Uint8Array(length).fill(7),
  getRandomBytesAsync: async (length: number) => new Uint8Array(length).fill(7),
}));

import { describePairFailure, eventForEnvelope, messagesFromHistory, sessionFromSummary } from '../src/useDsh';

function envelope(frame: Record<string, unknown>, rpcId?: string): M1StreamEnvelope {
  return { v: 1, bseq: 7, kind: 'mux', frame, ...(rpcId === undefined ? {} : { rpcId }) };
}

describe('frames the UI has to act on', () => {
  it('carries the rpcId of an approval request through to the approval', () => {
    const event = eventForEnvelope(
      envelope({ type: 'approval/requested', sessionId: 's-1', approvalId: 'a-1', toolName: 'shell', reason: 'rm -rf' }, 'rpc-9'),
    );

    expect(event).toMatchObject({ type: 'approval.requested', sessionId: 's-1' });
    const approval = (event as { approval: Record<string, unknown> }).approval;
    // Without this the "Approve" button posts a reply the bridge cannot route.
    expect(approval.rpcId).toBe('rpc-9');
    expect(approval).toMatchObject({ id: 'a-1', toolName: 'shell', reason: 'rm -rf' });
  });

  it('carries the rpcId of a question through to both the event and the question', () => {
    const event = eventForEnvelope(
      envelope(
        {
          type: 'question/requested',
          sessionId: 's-2',
          questionId: 'q-1',
          question: 'Which branch?',
          options: [{ id: 'main', label: 'main' }, { id: 'dev', label: 'dev' }, { bad: 'shape' }],
        },
        'rpc-10',
      ),
    );

    expect(event).toMatchObject({ type: 'question.requested', rpcId: 'rpc-10' });
    const question = (event as { question: Record<string, unknown> }).question;
    expect(question.rpcId).toBe('rpc-10');
    // The malformed third option is dropped rather than rendered as a blank row.
    expect(question.options).toEqual([{ id: 'main', label: 'main' }, { id: 'dev', label: 'dev' }]);
  });

  it('falls back to the envelope rpcId when the frame has no id of its own', () => {
    const approval = eventForEnvelope(envelope({ type: 'approval/requested', sessionId: 's-3' }, 'rpc-11'));
    expect((approval as { approval: { id: string } }).approval.id).toBe('rpc-11');

    const question = eventForEnvelope(envelope({ type: 'question/requested', sessionId: 's-3' }, 'rpc-12'));
    expect((question as { question: { id: string } }).question.id).toBe('rpc-12');
  });

  it('maps a session status frame to a running or idle session', () => {
    expect(eventForEnvelope(envelope({ type: 'host/session-status', sessionId: 's-4', running: true }))).toMatchObject({
      type: 'session.updated',
      status: 'running',
    });
    // Anything other than an explicit `true` is idle: a missing field must not be
    // rendered as a session that is doing work.
    expect(eventForEnvelope(envelope({ type: 'host/session-status', sessionId: 's-4' }))).toMatchObject({
      status: 'idle',
    });
  });

  it('reports a stream error with its text, and a default when there is none', () => {
    expect(eventForEnvelope(envelope({ type: 'stream/error', error: 'upstream closed' }))).toMatchObject({
      type: 'error',
      error: 'upstream closed',
    });
    expect(eventForEnvelope(envelope({ type: 'stream/error' }))).toMatchObject({ error: 'Stream error' });
  });

  it('ignores a frame it has no mapping for, rather than inventing one', () => {
    expect(eventForEnvelope(envelope({ type: 'something/unknown' }))).toBeUndefined();
    expect(eventForEnvelope(envelope({}))).toBeUndefined();
    // A frame that is not an object at all must not throw on the stream path.
    expect(eventForEnvelope({ v: 1, bseq: 1, kind: 'mux', frame: null } as unknown as M1StreamEnvelope)).toBeUndefined();
  });
});

describe('session summaries', () => {
  it('normalizes a summary from the bridge', () => {
    expect(sessionFromSummary({ sessionId: 's-1', title: 'Work', cwd: '/tmp', running: true, updatedAt: 1_700_000_000_000 })).toMatchObject({
      id: 's-1',
      title: 'Work',
      status: 'running',
    });
  });

  it('survives a summary with nothing usable in it', () => {
    const session = sessionFromSummary(undefined);
    expect(session.status).toBe('idle');
    expect(session.title).toBe('Untitled session');
  });
});

describe('history flattening', () => {
  /**
   * `loadHistory` and the resync handler both call this, and a resync that rebuilt
   * history differently would show the user their conversation changing shape.
   */
  it('produces the same messages from the wrapped and unwrapped event shapes', () => {
    const wrapped = messagesFromHistory('s-1', [
      { event: { type: 'session/user-message', time: 1_700_000_000_000, data: { messageId: 'm-1', text: 'hello' } } },
    ]);
    const flat = messagesFromHistory('s-1', [
      { type: 'session/user-message', time: 1_700_000_000_000, data: { messageId: 'm-1', text: 'hello' } },
    ]);

    expect(wrapped).toEqual(flat);
    expect(wrapped[0]).toMatchObject({ id: 'm-1', role: 'user', content: 'hello' });
  });

  it('assigns a role from the event type and reads either text field', () => {
    const messages = messagesFromHistory('s-1', [
      { type: 'session/user-message', data: { id: '1', text: 'ask' } },
      { type: 'session/assistant-message', data: { id: '2', content: 'answer' } },
      { type: 'session/tool-result', data: { id: '3', text: 'output' } },
    ]);

    expect(messages.map((message) => message.role)).toEqual(['user', 'assistant', 'tool']);
    expect(messages[1]?.content).toBe('answer');
  });

  it('drops entries with no text instead of rendering empty bubbles', () => {
    expect(messagesFromHistory('s-1', [{ type: 'session/started' }, { type: 'noise' }, null, 42])).toEqual([]);
  });

  it('synthesizes an id when the event has none, so React keys stay stable per index', () => {
    const messages = messagesFromHistory('s-9', [{ type: 'session/user-message', data: { text: 'a' } }]);
    expect(messages[0]?.id).toBe('s-9-0');
  });
});

describe('pairing failure copy', () => {
  it('has operator-readable text for every failure kind the core can report', () => {
    // The list is `PairFailure['kind']` in src/m1/pair-flow.ts. A kind added there and
    // not here would reach the user as a raw internal message.
    const kinds = [
      'bad-uri',
      'pairing-rejected',
      'pairing-invalid',
      'timeout',
      'rendezvous-busy',
      'pin-mismatch',
      'relay',
      'cancelled',
      'unreachable',
      'bridge-error',
      'protocol',
    ];

    for (const kind of kinds) {
      const text = describePairFailure({ kind, message: 'internal detail' });
      expect(text.length).toBeGreaterThan(0);
      // No routing ids, tokens, or key material in anything shown to a user.
      expect(text).not.toMatch(/token|routingId|[A-Za-z0-9_-]{40,}/);
    }
  });

  it('distinguishes a rendezvous mismatch, which is a tampered QR', () => {
    const mismatch = describePairFailure({ kind: 'bad-uri', problem: 'rendezvous-mismatch' });
    const ordinary = describePairFailure({ kind: 'bad-uri' });
    expect(mismatch).not.toBe(ordinary);
    expect(mismatch).toMatch(/inconsistent/i);
  });

  it('tells the user not to continue after a pin mismatch', () => {
    // The one failure that is a security event rather than an inconvenience.
    expect(describePairFailure({ kind: 'pin-mismatch' })).toMatch(/do not continue/i);
  });

  it('falls back to the failure message for a kind it does not know', () => {
    expect(describePairFailure({ kind: 'brand-new-kind', message: 'something specific' })).toBe('something specific');
    expect(describePairFailure({ kind: 'brand-new-kind' })).toBe('Pairing failed.');
  });
});

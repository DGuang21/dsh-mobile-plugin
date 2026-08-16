import { describe, expect, it } from 'vitest';
import { sessionReducer, type SessionState } from './sessionReducer';

const empty: SessionState = { messages: [], approvals: [], questions: [], status: 'idle' };

describe('sessionReducer', () => {
  it('merges stream deltas into one message', () => {
    const first = sessionReducer(empty, { type: 'event', event: { type: 'message.delta', messageId: 'm1', delta: 'Hello' } });
    const next = sessionReducer(first, { type: 'event', event: { type: 'message.delta', messageId: 'm1', delta: ' world' } });
    expect(next.messages).toHaveLength(1);
    expect(next.messages[0]?.content).toBe('Hello world');
  });

  it('adds and resolves approvals', () => {
    const waiting = sessionReducer(empty, { type: 'event', event: { type: 'approval.requested', approval: { id: 'a1', sessionId: 's1', toolName: 'Bash', createdAt: 'now' } } });
    expect(waiting.status).toBe('waiting_approval');
    expect(sessionReducer(waiting, { type: 'resolve', id: 'a1' }).approvals).toHaveLength(0);
  });
});

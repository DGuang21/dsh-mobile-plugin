import { describe, expect, it } from 'vitest';
import { normalizeSession, parseEvent } from './normalize';

describe('protocol normalization', () => {
  it('accepts run-shaped sessions', () => {
    expect(normalizeSession({ runId: 'r1', name: 'Build', state: 'active', workingDirectory: '/app' })).toMatchObject({ id: 'r1', title: 'Build', status: 'running', cwd: '/app' });
  });

  it('accepts event/kind aliases', () => {
    expect(parseEvent({ event: 'message.delta', session_id: 's1', data: { message_id: 'm1', text: 'hi' } })).toMatchObject({ type: 'message.delta', sessionId: 's1', messageId: 'm1', delta: 'hi' });
  });
});

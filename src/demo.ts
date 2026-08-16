import type { ApprovalRequest, ChatMessage, Session } from './protocol/types';

const now = Date.now();
export const demoSessions: Session[] = [
  { id: 'demo-live', title: 'Refactor authentication flow', cwd: '~/projects/atlas', branch: 'feat/mobile-auth', model: 'deepseek-reasoner', status: 'waiting_approval', updatedAt: new Date(now - 90_000).toISOString(), unread: 1 },
  { id: 'demo-api', title: 'Add usage metrics endpoint', cwd: '~/projects/gateway', branch: 'main', model: 'deepseek-chat', status: 'running', updatedAt: new Date(now - 640_000).toISOString() },
  { id: 'demo-tests', title: 'Fix flaky integration tests', cwd: '~/projects/console', branch: 'fix/ci-timeouts', model: 'deepseek-reasoner', status: 'idle', updatedAt: new Date(now - 7_200_000).toISOString() },
];

export const demoMessages: Record<string, ChatMessage[]> = {
  'demo-live': [
    { id: 'm1', role: 'user', content: 'Inspect the auth refresh flow and remove the race when two requests return 401 together.', createdAt: new Date(now - 900_000).toISOString() },
    { id: 'm2', role: 'assistant', content: 'I traced the refresh path through `apiClient.ts` and `sessionStore.ts`. Both failed requests create a refresh request because the in-flight promise is scoped inside the interceptor.\n\nI will move the shared promise to module scope, add a bounded retry, and cover concurrent 401 responses.', createdAt: new Date(now - 780_000).toISOString() },
    { id: 'm3', role: 'tool', toolName: 'Edit', content: 'Modified src/network/apiClient.ts\n+18 - 3 lines', createdAt: new Date(now - 300_000).toISOString() },
  ],
  'demo-api': [{ id: 'm4', role: 'assistant', content: 'Scanning the existing metrics registry and route conventions…', createdAt: new Date(now - 60_000).toISOString(), streaming: true }],
};

export const demoApprovals: Record<string, ApprovalRequest[]> = {
  'demo-live': [{ id: 'approval-1', sessionId: 'demo-live', toolName: 'Bash', command: 'npm test -- --runInBand auth', reason: 'Run the focused authentication test suite after the refactor.', createdAt: new Date(now - 100_000).toISOString() }],
};

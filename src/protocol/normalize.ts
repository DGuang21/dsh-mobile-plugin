import type { ApprovalRequest, ChatMessage, DshEvent, Session, SessionStatus } from './types';

const value = (obj: Record<string, unknown>, ...keys: string[]) => keys.map((key) => obj[key]).find((item) => item !== undefined);
const makeId = () => `local-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

export function normalizeSession(input: unknown): Session {
  const item = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>;
  return {
    id: String(value(item, 'id', 'sessionId', 'runId') ?? makeId()),
    title: String(value(item, 'title', 'name') ?? 'Untitled session'),
    cwd: typeof value(item, 'cwd', 'workdir', 'workingDirectory') === 'string' ? String(value(item, 'cwd', 'workdir', 'workingDirectory')) : undefined,
    model: typeof value(item, 'model', 'modelId') === 'string' ? String(value(item, 'model', 'modelId')) : undefined,
    status: normalizeStatus(value(item, 'status', 'state')),
    updatedAt: String(value(item, 'updatedAt', 'updated_at', 'lastActivityAt') ?? new Date().toISOString()),
    unread: typeof value(item, 'unread', 'unreadCount') === 'number' ? Number(value(item, 'unread', 'unreadCount')) : undefined,
    branch: typeof item.branch === 'string' ? item.branch : undefined,
  };
}

export function normalizeStatus(status: unknown): SessionStatus {
  const normalized = String(status ?? 'idle').toLowerCase().replace('-', '_');
  if (['running', 'working', 'active', 'streaming'].includes(normalized)) return 'running';
  if (['waiting_approval', 'awaiting_approval', 'approval'].includes(normalized)) return 'waiting_approval';
  if (['error', 'failed'].includes(normalized)) return 'error';
  if (['completed', 'done', 'success'].includes(normalized)) return 'completed';
  return 'idle';
}

export function normalizeMessage(input: unknown, fallbackRole: ChatMessage['role'] = 'assistant'): ChatMessage {
  const item = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>;
  const content = value(item, 'content', 'text', 'delta') ?? '';
  return {
    id: String(value(item, 'id', 'messageId') ?? makeId()),
    role: (['user', 'assistant', 'tool', 'system'].includes(String(item.role)) ? item.role : fallbackRole) as ChatMessage['role'],
    content: typeof content === 'string' ? content : JSON.stringify(content),
    createdAt: String(value(item, 'createdAt', 'created_at', 'timestamp') ?? new Date().toISOString()),
    streaming: Boolean(item.streaming),
    toolName: typeof item.toolName === 'string' ? item.toolName : undefined,
  };
}

export function normalizeApproval(input: unknown, sessionId = ''): ApprovalRequest {
  const item = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>;
  return {
    id: String(value(item, 'id', 'approvalId', 'requestId') ?? makeId()),
    sessionId: String(value(item, 'sessionId') ?? sessionId),
    toolName: String(value(item, 'toolName', 'tool', 'name') ?? 'Tool request'),
    command: typeof value(item, 'command', 'input', 'preview') === 'string' ? String(value(item, 'command', 'input', 'preview')) : undefined,
    reason: typeof item.reason === 'string' ? item.reason : undefined,
    createdAt: String(value(item, 'createdAt', 'created_at', 'timestamp') ?? new Date().toISOString()),
    expiresAt: typeof item.expiresAt === 'string' ? item.expiresAt : undefined,
  };
}

export function parseEvent(input: unknown): DshEvent {
  const item = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>;
  const type = String(value(item, 'type', 'event', 'kind') ?? 'unknown');
  const sessionId = typeof value(item, 'sessionId', 'session_id', 'runId') === 'string' ? String(value(item, 'sessionId', 'session_id', 'runId')) : undefined;
  const payload = (item.data && typeof item.data === 'object' ? item.data : item) as Record<string, unknown>;
  const messagePayload = payload.message ?? payload;
  const approvalPayload = payload.approval ?? payload.request;
  return {
    type,
    sessionId,
    messageId: typeof value(payload, 'messageId', 'message_id') === 'string' ? String(value(payload, 'messageId', 'message_id')) : undefined,
    delta: typeof value(payload, 'delta', 'text', 'content') === 'string' ? String(value(payload, 'delta', 'text', 'content')) : undefined,
    message: messagePayload ? normalizeMessage(messagePayload) : undefined,
    approval: approvalPayload ? normalizeApproval(approvalPayload, sessionId) : undefined,
    status: value(payload, 'status', 'state') ? normalizeStatus(value(payload, 'status', 'state')) : undefined,
    error: typeof value(payload, 'error', 'message') === 'string' && type === 'error' ? String(value(payload, 'error', 'message')) : undefined,
    raw: input,
  };
}

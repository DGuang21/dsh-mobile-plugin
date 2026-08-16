export type SessionStatus = 'idle' | 'running' | 'waiting_approval' | 'error' | 'completed';

export type Session = {
  id: string;
  title: string;
  cwd?: string;
  model?: string;
  status: SessionStatus;
  updatedAt: string;
  unread?: number;
  branch?: string;
};

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant' | 'tool' | 'system';
  content: string;
  createdAt: string;
  streaming?: boolean;
  toolName?: string;
};

export type ApprovalRequest = {
  id: string;
  /** Original dsh server-request rpcId; required verbatim for /m1/respond. */
  rpcId?: string;
  sessionId: string;
  toolName: string;
  command?: string;
  reason?: string;
  createdAt: string;
  expiresAt?: string;
};

export type QuestionRequest = {
  id: string;
  rpcId?: string;
  sessionId: string;
  question: string;
  options?: { id: string; label: string }[];
  createdAt: string;
};

export type DshEvent = {
  type: string;
  sessionId?: string;
  messageId?: string;
  delta?: string;
  message?: Partial<ChatMessage>;
  approval?: Partial<ApprovalRequest>;
  question?: Partial<QuestionRequest>;
  status?: SessionStatus;
  error?: string;
  raw?: unknown;
  rpcId?: string;
};

export type DshPaths = {
  health: string;
  sessions: string;
  session: (id: string) => string;
  messages: (id: string) => string;
  approvals: (id: string, approvalId: string) => string;
};

export type DshClientConfig = {
  baseUrl: string;
  wsUrl?: string;
  token?: string;
  timeoutMs?: number;
  paths?: Partial<DshPaths>;
  fetchImpl?: typeof fetch;
  webSocketImpl?: typeof WebSocket;
};

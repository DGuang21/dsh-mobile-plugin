import { normalizeApproval, normalizeMessage, normalizeSession, parseEvent } from './normalize';
import type { ApprovalRequest, ChatMessage, DshClientConfig, DshEvent, DshPaths, Session } from './types';

const defaults: DshPaths = {
  health: '/health',
  sessions: '/v1/sessions',
  session: (id) => `/v1/sessions/${encodeURIComponent(id)}`,
  messages: (id) => `/v1/sessions/${encodeURIComponent(id)}/messages`,
  approvals: (id, approvalId) => `/v1/sessions/${encodeURIComponent(id)}/approvals/${encodeURIComponent(approvalId)}`,
};

export class DshError extends Error {
  constructor(message: string, public readonly status?: number) { super(message); this.name = 'DshError'; }
}

export class DshClient {
  private readonly config: Required<Pick<DshClientConfig, 'baseUrl' | 'timeoutMs'>> & DshClientConfig;
  private readonly paths: DshPaths;

  constructor(config: DshClientConfig) {
    this.config = { timeoutMs: 15000, ...config, baseUrl: config.baseUrl.replace(/\/$/, '') };
    this.paths = { ...defaults, ...config.paths } as DshPaths;
  }

  private headers() {
    return { Accept: 'application/json', 'Content-Type': 'application/json', ...(this.config.token ? { Authorization: `Bearer ${this.config.token}` } : {}) };
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const response = await (this.config.fetchImpl ?? fetch)(`${this.config.baseUrl}${path}`, { ...init, headers: { ...this.headers(), ...init.headers }, signal: controller.signal });
      const text = await response.text();
      let body: unknown = undefined;
      try { body = text ? JSON.parse(text) : undefined; } catch { body = text; }
      if (!response.ok) throw new DshError(typeof body === 'object' && body && 'error' in body ? String((body as { error: unknown }).error) : `Request failed (${response.status})`, response.status);
      return body as T;
    } catch (error) {
      if (error instanceof DshError) throw error;
      throw new DshError(error instanceof Error && error.name === 'AbortError' ? 'Request timed out' : error instanceof Error ? error.message : 'Network request failed');
    } finally { clearTimeout(timeout); }
  }

  async health(): Promise<{ ok: boolean; version?: string }> { return this.request(this.paths.health); }

  async listSessions(): Promise<Session[]> {
    const body = await this.request<unknown>(this.paths.sessions);
    const list = Array.isArray(body) ? body : (body && typeof body === 'object' && Array.isArray((body as { sessions?: unknown[] }).sessions) ? (body as { sessions: unknown[] }).sessions : []);
    return list.map(normalizeSession);
  }

  async createSession(input: { title?: string; cwd?: string; model?: string } = {}): Promise<Session> {
    return normalizeSession(await this.request(this.paths.sessions, { method: 'POST', body: JSON.stringify(input) }));
  }

  async sendMessage(sessionId: string, content: string, attachments?: unknown[]): Promise<ChatMessage> {
    const body = await this.request<unknown>(this.paths.messages(sessionId), { method: 'POST', body: JSON.stringify({ content, attachments }) });
    const payload = body && typeof body === 'object' && 'message' in body ? (body as { message: unknown }).message : body;
    return normalizeMessage(payload);
  }

  async resolveApproval(sessionId: string, approvalId: string, decision: 'approve' | 'deny'): Promise<void> {
    await this.request(this.paths.approvals(sessionId, approvalId), { method: 'POST', body: JSON.stringify({ decision }) });
  }

  subscribe(sessionId: string, onEvent: (event: DshEvent) => void, onError?: (error: Error) => void): () => void {
    const WebSocketImpl = this.config.webSocketImpl ?? WebSocket;
    const base = this.config.wsUrl ?? this.config.baseUrl.replace(/^http/, 'ws') + '/ws';
    const url = `${base}${base.includes('?') ? '&' : '?'}sessionId=${encodeURIComponent(sessionId)}`;
    const socket = new WebSocketImpl(url, this.config.token ? [`bearer.${this.config.token}`] : undefined);
    socket.onmessage = (message) => {
      try { onEvent(parseEvent(JSON.parse(String(message.data)))); } catch (error) { onError?.(error instanceof Error ? error : new Error('Invalid event')); }
    };
    socket.onerror = () => onError?.(new Error('WebSocket connection failed'));
    return () => socket.close();
  }
}

export { normalizeApproval, normalizeSession, parseEvent };

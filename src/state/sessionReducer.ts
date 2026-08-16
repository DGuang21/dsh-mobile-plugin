import type { ApprovalRequest, ChatMessage, DshEvent, QuestionRequest, SessionStatus } from '../protocol/types';

export type SessionState = { messages: ChatMessage[]; approvals: ApprovalRequest[]; questions: QuestionRequest[]; status: SessionStatus; error?: string };
export type SessionAction = { type: 'event'; event: DshEvent } | { type: 'send'; message: ChatMessage } | { type: 'resolve'; id: string } | { type: 'answer'; id: string } | { type: 'reset'; state: SessionState };

export function sessionReducer(state: SessionState, action: SessionAction): SessionState {
  if (action.type === 'reset') return action.state;
  if (action.type === 'send') return { ...state, messages: [...state.messages, action.message], status: 'running' };
  if (action.type === 'resolve') return { ...state, approvals: state.approvals.filter((item) => item.id !== action.id), status: 'running' };
  if (action.type === 'answer') return { ...state, questions: state.questions.filter((item) => item.id !== action.id), status: 'running' };
  const event = action.event;
  if (event.type === 'message.delta') {
    const id = event.messageId ?? event.message?.id ?? 'stream';
    const index = state.messages.findIndex((item) => item.id === id);
    if (index < 0) return { ...state, status: 'running', messages: [...state.messages, { id, role: 'assistant', content: event.delta ?? '', createdAt: new Date().toISOString(), streaming: true }] };
    return { ...state, messages: state.messages.map((item, i) => i === index ? { ...item, content: item.content + (event.delta ?? ''), streaming: true } : item) };
  }
  if (event.type === 'message.completed' && event.message) {
    const message = event.message as ChatMessage;
    const exists = state.messages.some((item) => item.id === message.id);
    return { ...state, messages: exists ? state.messages.map((item) => item.id === message.id ? { ...item, ...message, streaming: false } : item) : [...state.messages, { ...message, streaming: false }] };
  }
  if (event.type === 'approval.requested' && event.approval) return { ...state, approvals: [...state.approvals.filter((item) => item.id !== event.approval?.id), event.approval as ApprovalRequest], status: 'waiting_approval' };
  if (event.type === 'approval.resolved' && event.approval?.id) return { ...state, approvals: state.approvals.filter((item) => item.id !== event.approval?.id), status: 'running' };
  if (event.type === 'question.requested' && event.question) return { ...state, questions: [...state.questions.filter((item) => item.id !== event.question?.id), event.question as QuestionRequest], status: 'waiting_approval' };
  if (event.type === 'question.resolved' && event.question?.id) return { ...state, questions: state.questions.filter((item) => item.id !== event.question?.id), status: 'running' };
  if (event.type === 'error') return { ...state, status: 'error', error: event.error ?? 'Unknown agent error' };
  if (event.type === 'session.updated' && event.status) return { ...state, status: event.status };
  return state;
}

/**
 * The React seam over the protocol core.
 *
 * Everything with a decision in it lives in `src/m1/core.ts`. This file does three
 * things and nothing else:
 *
 *   1. Wires the platform in — `expo-secure-store` via `identity`/`storage`, RN's
 *      `WebSocket` adapted to the relay's `WebSocketLike`, `AsyncStorage` for the
 *      user-entered LAN address (not a secret, and not part of the protocol).
 *   2. Mirrors core state and events into React state.
 *   3. Translates stream envelopes into the UI's `DshEvent` vocabulary and keeps
 *      the per-session caches the screens read.
 *
 * The returned object's shape is a contract with `app/`, which this core does not
 * own. Keys are preserved exactly, including `demo`, `token` and `wsUrl`, which are
 * inert: `token` is deliberately always `''` because the access token is
 * memory-only inside the core and must not be handed to the view layer.
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import { createContext, type PropsWithChildren, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { M1Client } from './m1/client';
import { M1Core } from './m1/core';
import { loadOrCreateIdentity } from './m1/identity';
import type { WebSocketLike } from './m1/relay';
import type { M1ClientState, M1StreamEnvelope, PairClaimResult, QuestionAnswer } from './m1/types';
import { readBridge, writeBridge, type StoredBridge } from './storage';
import type { ApprovalRequest, ChatMessage, DshEvent, QuestionRequest, Session } from './protocol/types';
import { normalizeSession } from './protocol/normalize';

const URL_KEY = 'dshm.lan-url.v1';
type SessionEventListener = (event: DshEvent) => void;

export type ActivityItem = { id: string; title: string; detail: string; time: string; kind: 'session' | 'approval' | 'message' | 'bridge' | 'error' };

/**
 * The three functions below are exported for tests, not for `app/`.
 *
 * They are the frame → UI translation, and the part of it that matters is `rpcId`
 * propagation: an approval or question that loses its `rpcId` is one the user can never
 * answer, and the harness stays blocked. Screens should use the hook.
 */
export function sessionFromSummary(value: unknown): Session {
  const item = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return normalizeSession({ id: item.sessionId, title: item.title ?? 'Untitled session', cwd: item.cwd, status: item.running === true ? 'running' : 'idle', updatedAt: typeof item.updatedAt === 'number' ? new Date(item.updatedAt).toISOString() : item.updatedAt });
}

export function eventForEnvelope(envelope: M1StreamEnvelope): DshEvent | undefined {
  const frame = envelope.frame && typeof envelope.frame === 'object' ? envelope.frame as Record<string, unknown> : {};
  const type = typeof frame.type === 'string' ? frame.type : 'unknown';
  const sessionId = typeof frame.sessionId === 'string' ? frame.sessionId : undefined;
  if (type === 'approval/requested') return { type: 'approval.requested', sessionId, approval: { id: String(frame.approvalId ?? envelope.rpcId ?? ''), sessionId: sessionId ?? '', toolName: String(frame.toolName ?? 'Tool request'), reason: typeof frame.reason === 'string' ? frame.reason : undefined, createdAt: new Date().toISOString(), rpcId: envelope.rpcId } as ApprovalRequest & { rpcId?: string } };
  if (type === 'approval/resolved') return { type: 'approval.resolved', sessionId, approval: { id: String(frame.approvalId ?? ''), sessionId: sessionId ?? '', toolName: '', createdAt: new Date().toISOString() } };
  if (type === 'question/requested') return { type: 'question.requested', sessionId, question: { id: String(frame.questionId ?? envelope.rpcId ?? ''), rpcId: envelope.rpcId, sessionId: sessionId ?? '', question: String(frame.question ?? frame.prompt ?? 'Agent needs an answer'), options: Array.isArray(frame.options) ? frame.options.flatMap((option) => { const value = option && typeof option === 'object' ? option as Record<string, unknown> : {}; return typeof value.id === 'string' && typeof value.label === 'string' ? [{ id: value.id, label: value.label }] : []; }) : undefined, createdAt: new Date().toISOString() } as QuestionRequest, raw: frame, rpcId: envelope.rpcId };
  if (type === 'host/session-status') return { type: 'session.updated', sessionId, status: frame.running === true ? 'running' : 'idle' };
  if (type === 'stream/error') return { type: 'error', sessionId, error: typeof frame.error === 'string' ? frame.error : 'Stream error' };
  if (type === 'session/event') { const event = frame.event && typeof frame.event === 'object' ? frame.event as Record<string, unknown> : {}; const data = event.data && typeof event.data === 'object' ? event.data as Record<string, unknown> : event; const content = typeof data.text === 'string' ? data.text : typeof data.content === 'string' ? data.content : typeof data.delta === 'string' ? data.delta : undefined; return { type: typeof event.type === 'string' ? event.type : 'unknown', sessionId, ...(content === undefined ? {} : { delta: content }), raw: envelope }; }
  if (envelope.kind === 'bridge') { if (type === 'dsh-disconnected') return { type: 'error', error: 'Harness offline on workstation' }; if (type === 'resync-required') return { type: 'resync-required', error: 'History needs to be refreshed' }; if (type === 'device-revoked') return { type: 'device-revoked', error: 'This device was revoked' }; }
  return sessionId ? { type, sessionId, raw: envelope } : undefined;
}

/**
 * Adapt RN's `WebSocket` to the relay's `WebSocketLike`.
 *
 * The relay client takes a factory rather than constructing a socket itself so the
 * protocol layer stays free of platform globals and can be driven by `ws` under
 * Node in tests.
 */
function createRelaySocket(url: string, subprotocols: readonly string[]): WebSocketLike {
  const socket = new WebSocket(url, [...subprotocols]);
  return {
    send: (data: string) => socket.send(data),
    close: (code?: number, reason?: string) => socket.close(code, reason),
    addEventListener: (type: string, listener: (event: never) => void) => {
      socket.addEventListener(type as 'open' | 'message' | 'close' | 'error', listener as (event: unknown) => void);
    },
  } as WebSocketLike;
}

function useDshState() {
  const [core, setCore] = useState<M1Core>();
  const [client, setClient] = useState<M1Client>();
  const [bridge, setBridge] = useState<StoredBridge>();
  const [baseUrl, setBaseUrl] = useState('');
  const [identityReady, setIdentityReady] = useState(false);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [state, setState] = useState<M1ClientState>({ name: 'unpaired', reason: 'fresh' });
  const [lastBseq, setLastBseq] = useState(0);
  const lastBseqRef = useRef(0);
  const [pairing, setPairing] = useState<PairClaimResult>();
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const listeners = useRef(new Map<string, Set<SessionEventListener>>());
  const history = useRef(new Map<string, ChatMessage[]>());
  const approvals = useRef(new Map<string, ApprovalRequest[]>());
  const questions = useRef(new Map<string, QuestionRequest[]>());
  /** Read by the resync handler, which must see the live client, not a closure copy. */
  const clientRef = useRef<M1Client>();

  const pushActivity = useCallback((item: Omit<ActivityItem, 'time'>) => {
    setActivity((current) => [{ ...item, time: new Date().toISOString() }, ...current].slice(0, 80));
  }, []);

  const emit = useCallback((envelope: M1StreamEnvelope) => {
    setLastBseq((current) => { const next = Math.max(current, envelope.bseq); lastBseqRef.current = next; return next; });
    const event = eventForEnvelope(envelope);
    if (!event) return;
    const now = new Date().toISOString();
    if (event.type === 'message.delta' && event.sessionId && event.delta) {
      const current = history.current.get(event.sessionId) ?? [];
      const messageId = event.messageId ?? 'stream';
      const index = current.findIndex((item) => item.id === messageId);
      history.current.set(event.sessionId, index < 0
        ? [...current, { id: messageId, role: 'assistant', content: event.delta, createdAt: now, streaming: true }]
        : current.map((item, itemIndex) => itemIndex === index ? { ...item, content: item.content + event.delta, streaming: true } : item));
    }
    if (event.type === 'message.completed' && event.sessionId && event.message) {
      const message = event.message as ChatMessage;
      const current = history.current.get(event.sessionId) ?? [];
      history.current.set(event.sessionId, current.some((item) => item.id === message.id) ? current.map((item) => item.id === message.id ? { ...item, ...message, streaming: false } : item) : [...current, { ...message, streaming: false }]);
    }
    if (event.type === 'approval.requested' && event.sessionId && event.approval) {
      const approval = event.approval as ApprovalRequest;
      approvals.current.set(event.sessionId, [...(approvals.current.get(event.sessionId) ?? []).filter((item) => item.id !== approval.id), approval]);
    }
    if (event.type === 'question.requested' && event.sessionId && event.question) {
      const question = event.question as QuestionRequest;
      questions.current.set(event.sessionId, [...(questions.current.get(event.sessionId) ?? []).filter((item) => item.id !== question.id), question]);
    }
    if ((event.type === 'approval.resolved' || event.type === 'question.resolved') && event.sessionId) {
      if (event.approval?.id) approvals.current.set(event.sessionId, (approvals.current.get(event.sessionId) ?? []).filter((item) => item.id !== event.approval?.id));
      if (event.question?.id) questions.current.set(event.sessionId, (questions.current.get(event.sessionId) ?? []).filter((item) => item.id !== event.question?.id));
    }
    const detail = event.error ?? event.delta ?? event.type;
    const kind: ActivityItem['kind'] = event.type.includes('approval') ? 'approval' : event.type === 'error' ? 'error' : event.type === 'session/event' ? 'message' : event.sessionId ? 'session' : 'bridge';
    setActivity((current) => [{ id: `${envelope.bseq}-${event.type}`, title: event.type.replace(/[./_-]/g, ' '), detail, time: now, kind }, ...current].slice(0, 80));
    if (event.sessionId) listeners.current.get(event.sessionId)?.forEach((listener) => listener(event));
  }, []);

  /**
   * Build the core once, on mount.
   *
   * The core owns the connection lifecycle from here: `start()` loads the stored
   * route and connects, and every later transition arrives through the event
   * subscription. There is deliberately no reconnect `useEffect` — that policy used
   * to live here and is now in one place.
   */
  useEffect(() => {
    let active = true;
    let created: M1Core | undefined;

    const boot = async (): Promise<void> => {
      const [identity, stored, savedUrl] = await Promise.all([
        loadOrCreateIdentity(),
        readBridge(),
        AsyncStorage.getItem(URL_KEY),
      ]);
      if (!active) return;
      const url = savedUrl ?? stored?.baseUrl ?? '';

      const instance = new M1Core({
        identity,
        store: { read: readBridge, write: writeBridge },
        ...(url.length > 0 ? { baseUrl: url } : {}),
        createSocket: createRelaySocket,
        // Re-baseline on resync. The core cannot do this itself: only this layer
        // knows which sessions are open and therefore which histories to refetch.
        onResync: async () => {
          const active_ = clientRef.current;
          if (active_ === undefined) return;
          const summaries = await active_.listSessions();
          if (!active) return;
          setSessions(summaries.map(sessionFromSummary));
          const openIds = [...history.current.keys()];
          for (const id of openIds) {
            try {
              const events = await active_.history(id);
              if (!active) return;
              history.current.set(id, messagesFromHistory(id, events));
            } catch {
              // A session that has gone away should not block the rest of the
              // re-baseline; the next `session.list` will drop it.
            }
          }
        },
      });
      created = instance;
      const wrapper = new M1Client(instance);
      clientRef.current = wrapper;

      instance.subscribe((event) => {
        if (!active) return;
        switch (event.type) {
          case 'state':
            setState(event.state);
            setBridge(instance.getBridge());
            if (event.state.name === 'awaiting-confirmation') {
              setPairing({
                status: 'awaiting-confirmation',
                sas: event.state.sas,
                bridgeName: event.state.bridgeName,
                bridgeId: instance.getBridge()?.bridgeId ?? '',
                expiresAt: event.state.expiresAt,
              });
            }
            if (event.state.name === 'unpaired' || event.state.name === 'revoked') {
              setPairing(undefined);
              setSessions([]);
            }
            return;
          case 'envelope':
            emit(event.envelope);
            return;
          case 'hello':
            lastBseqRef.current = Math.max(lastBseqRef.current, event.hello.lastBseq);
            setLastBseq(lastBseqRef.current);
            // The session list is the phone's baseline, and a reconnect may have
            // missed changes even without a resync.
            void wrapper.listSessions().then((summaries) => {
              if (active) setSessions(summaries.map(sessionFromSummary));
            }).catch(() => undefined);
            return;
          case 'resync':
            pushActivity({ id: `resync-${Date.now()}`, title: 'resync required', detail: event.reason, kind: 'bridge' });
            return;
          case 'diagnostic':
            if (event.level === 'info') return;
            pushActivity({ id: `diag-${Date.now()}-${event.message.length}`, title: event.level, detail: event.message, kind: event.level === 'error' ? 'error' : 'bridge' });
            return;
        }
      });

      setCore(instance);
      setClient(wrapper);
      setBridge(stored);
      setBaseUrl(url);
      setIdentityReady(true);
      await instance.start();
    };

    void boot().catch(() => {
      // Identity creation is the only thing that can fail here, and it means the
      // keystore is unavailable. Reporting ready with no core lets the UI render
      // its unpaired state instead of hanging on a spinner.
      if (active) setIdentityReady(true);
    });

    return () => {
      active = false;
      created?.dispose();
      clientRef.current = undefined;
    };
  }, [emit, pushActivity]);

  const refresh = useCallback(async () => {
    if (!client) return;
    const values = await client.listSessions();
    setSessions(values.map(sessionFromSummary));
  }, [client]);

  const saveConnection = useCallback(async (nextUrl: string) => {
    const normalized = nextUrl.trim().replace(/\/$/, '');
    setBaseUrl(normalized);
    await AsyncStorage.setItem(URL_KEY, normalized);
    core?.setBaseUrl(normalized);
  }, [core]);

  const checkConnection = useCallback(async (nextUrl: string) => {
    if (!core) throw new Error('Device identity is still initializing');
    return await core.health(nextUrl.trim().replace(/\/$/, ''));
  }, [core]);

  /**
   * Claim a pairing code and see it through to confirmation.
   *
   * This resolves only once the operator has confirmed at the workstation (or the
   * window closes), and the SAS is published through `pairing` while it waits — so
   * a caller can show the digits without driving the poll itself. Rejects on
   * failure, so an existing `catch` still surfaces a message.
   */
  const pair = useCallback(async (uri: string, label: string): Promise<PairClaimResult> => {
    if (!core) throw new Error('Device identity is still initializing');
    const outcome = await core.pair({ uri, label });
    if (!outcome.ok) throw new Error(describePairFailure(outcome.failure));
    const stored = outcome.bridge;
    setBridge(stored);
    const result: PairClaimResult = {
      status: 'paired',
      deviceId: stored.deviceId,
      bridgeId: stored.bridgeId,
      bridgeName: stored.bridgeName,
      scopeTier: stored.scopeTier,
      ...(stored.tlsFingerprint === undefined ? {} : { bridgeKeyFingerprint: stored.tlsFingerprint }),
      ...(stored.bridgeRoutingId === undefined || stored.deviceRoutingId === undefined
        ? {}
        : { relay: { bridgeRoutingId: stored.bridgeRoutingId, peerRoutingId: stored.deviceRoutingId } }),
    };
    setPairing(result);
    return result;
  }, [core]);

  const subscribe = useCallback((id: string, listener: SessionEventListener) => {
    const set = listeners.current.get(id) ?? new Set<SessionEventListener>();
    set.add(listener);
    listeners.current.set(id, set);
    return () => { set.delete(listener); };
  }, []);

  const getMessages = useCallback((id: string) => history.current.get(id) ?? [], []);
  const getApprovals = useCallback((id: string) => approvals.current.get(id) ?? [], []);
  const getQuestions = useCallback((id: string) => questions.current.get(id) ?? [], []);

  const loadHistory = useCallback(async (id: string) => {
    if (!client) return;
    const events = await client.history(id);
    history.current.set(id, messagesFromHistory(id, events));
  }, [client]);

  const send = useCallback(async (id: string, content: string, mode: 'queue' | 'steer' = 'queue') => {
    if (!client) throw new Error('Bridge is not connected');
    await client.prompt(id, content, mode);
  }, [client]);

  const cancel = useCallback(async (id: string) => {
    if (!client) throw new Error('Bridge is not connected');
    await client.cancel(id);
  }, [client]);

  const resolve = useCallback(async (_sessionId: string, rpcId: string, decision: 'approve' | 'deny') => {
    if (!client) throw new Error('Bridge is not connected');
    await client.respondApproval(rpcId, decision === 'approve' ? 'allowed-once' : 'rejected');
  }, [client]);

  const answer = useCallback(async (rpcId: string, answers: QuestionAnswer[]) => {
    if (!client) throw new Error('Bridge is not connected');
    await client.respondQuestion(rpcId, answers);
  }, [client]);

  const create = useCallback(async (title: string) => {
    if (!client) throw new Error('Bridge is not connected');
    const result = await client.createSession({});
    await refresh();
    return { ...sessionFromSummary(result), title };
  }, [client, refresh]);

  const clear = useCallback(async () => {
    setPairing(undefined);
    setSessions([]);
    setActivity([]);
    history.current.clear();
    approvals.current.clear();
    questions.current.clear();
    lastBseqRef.current = 0;
    setLastBseq(0);
    if (core) {
      await core.clear();
      return;
    }
    // No core means identity setup failed. The record still has to go, or the app
    // relaunches into a pairing it cannot use.
    setBridge(undefined);
    await writeBridge(undefined);
  }, [core]);

  return { baseUrl, bridge, identityReady, sessions, connected: state.name === 'ready', state, pairing, activity, lastBseq, demo: false, token: '', wsUrl: '', saveConnection, checkConnection, refresh, pair, clear, getMessages, getApprovals, getQuestions, loadHistory, send, cancel, resolve, answer, subscribe, create };
}

/**
 * Flatten a `session.history` result into chat messages.
 *
 * Shared by `loadHistory` and the resync handler, which must produce identical
 * output — a resync that rebuilt history differently would show the user their
 * conversation changing shape for no visible reason.
 */
export function messagesFromHistory(sessionId: string, events: readonly unknown[]): ChatMessage[] {
  const messages: ChatMessage[] = [];
  for (const item of events) {
    const entry = item && typeof item === 'object' ? item as Record<string, unknown> : {};
    const event = entry.event && typeof entry.event === 'object' ? entry.event as Record<string, unknown> : entry;
    const data = event.data && typeof event.data === 'object' ? event.data as Record<string, unknown> : event;
    const type = typeof event.type === 'string' ? event.type : '';
    const text = typeof data.text === 'string' ? data.text : typeof data.content === 'string' ? data.content : undefined;
    if (!text) continue;
    const role: ChatMessage['role'] = type.includes('user') ? 'user' : type.includes('tool') ? 'tool' : 'assistant';
    messages.push({
      id: String(data.messageId ?? data.id ?? `${sessionId}-${messages.length}`),
      role,
      content: text,
      createdAt: typeof event.time === 'number' ? new Date(event.time).toISOString() : new Date().toISOString(),
    });
  }
  return messages;
}

/** Operator-readable text for a pairing failure. No secrets, no routing ids. */
export function describePairFailure(failure: { kind: string; message?: string; problem?: string }): string {
  switch (failure.kind) {
    case 'bad-uri':
      return failure.problem === 'rendezvous-mismatch'
        ? 'This pairing code is inconsistent and was refused. Generate a new one.'
        : 'That is not a valid dshm pairing code.';
    case 'pairing-rejected':
      return 'The workstation rejected this pairing.';
    case 'pairing-invalid':
      return 'This pairing code has expired or was already used. Generate a new one.';
    case 'timeout':
      return 'The workstation did not confirm in time. Try again with a new code.';
    case 'rendezvous-busy':
      return 'Too many phones are trying to pair right now. Generate a new code.';
    case 'pin-mismatch':
      return 'The workstation did not prove its identity. Do not continue; generate a new code on a trusted network.';
    case 'relay':
      return 'The relay is not available right now.';
    case 'cancelled':
      return 'Pairing was cancelled.';
    default:
      return failure.message ?? 'Pairing failed.';
  }
}

export type DshContextValue = ReturnType<typeof useDshState>;
const DshContext = createContext<DshContextValue | null>(null);
export function DshProvider({ children }: PropsWithChildren) { return <DshContext.Provider value={useDshState()}>{children}</DshContext.Provider>; }
export function useDsh() { const value = useContext(DshContext); if (!value) throw new Error('useDsh must be used inside DshProvider'); return value; }

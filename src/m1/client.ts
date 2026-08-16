/**
 * [OUR DESIGN] Typed dsh method helpers over {@link M1Core}.
 *
 * The core knows how to make an authenticated `/m1/rpc` call. It deliberately does
 * not know what `session.prompt` wants, because the dsh method vocabulary is
 * upstream's and changes on a different schedule from the transport. This is where
 * that vocabulary lives, and it is the only place a payload shape is spelled out.
 *
 * Signatures are the ones verified in `docs/DSH_CORE_RESEARCH.md` §3.1. Anything
 * not listed there is reachable with `core.rpc(method, payload)` directly — this
 * class is a convenience, never a gate.
 */

import type { M1Core } from './core';
import type { QuestionAnswer } from './types';

/** `SessionSummary` as the phone needs it. Fields beyond these are ignored. */
export interface SessionSummaryLike {
  sessionId?: unknown;
  title?: unknown;
  cwd?: unknown;
  running?: unknown;
  updatedAt?: unknown;
}

export class M1Client {
  private readonly core: M1Core;

  constructor(core: M1Core) {
    this.core = core;
  }

  get deviceId(): string {
    return this.core.deviceId;
  }

  /** `session.list` — everything, `updatedAt` descending. `cursor` is unimplemented upstream. */
  async listSessions(): Promise<SessionSummaryLike[]> {
    const result = await this.core.rpc<{ items?: unknown }>('session.list', {});
    return Array.isArray(result.items) ? (result.items as SessionSummaryLike[]) : [];
  }

  /**
   * `session.history`.
   *
   * Capped at 200 messages: this is the re-baseline path after a resync, and an
   * unbounded history on a phone is both slow and pointless.
   */
  async history(sessionId: string, options: { maxMessages?: number; beforeSeq?: number } = {}): Promise<unknown[]> {
    const result = await this.core.rpc<{ events?: unknown }>('session.history', {
      sessionId,
      maxMessages: options.maxMessages ?? 200,
      ...(options.beforeSeq === undefined ? {} : { beforeSeq: options.beforeSeq }),
    });
    return Array.isArray(result.events) ? result.events : [];
  }

  async createSession(input: { cwd?: string; workspaceId?: string; agentPreset?: string } = {}): Promise<unknown> {
    return await this.core.rpc('session.create', input);
  }

  /**
   * `session.prompt`.
   *
   * `clientTimeZone` is sent because the agent uses it for date reasoning, and a
   * phone is the one client likely to be in a different zone from the workstation.
   */
  async prompt(sessionId: string, content: string, mode: 'queue' | 'steer' = 'queue'): Promise<unknown> {
    return await this.core.rpc('session.prompt', {
      sessionId,
      mode,
      content: [{ type: 'text', text: content }],
      clientTimeZone: resolveTimeZone(),
    });
  }

  async cancel(sessionId: string): Promise<unknown> {
    return await this.core.rpc('session.cancel', { sessionId });
  }

  async listWorkspaces(): Promise<unknown[]> {
    const result = await this.core.rpc<{ items?: unknown }>('workspace.list', {});
    return Array.isArray(result.items) ? result.items : [];
  }

  /** Approvals are `allowed-once` or `rejected` only — there is no "always" on mobile. */
  async respondApproval(rpcId: string, outcome: 'allowed-once' | 'rejected'): Promise<void> {
    await this.core.respondApproval(rpcId, outcome);
  }

  /** Answer a whole `ask()` batch: dsh has no per-question response. */
  async respondQuestion(rpcId: string, answers: readonly QuestionAnswer[]): Promise<void> {
    await this.core.respondQuestion(rpcId, answers);
  }
}

/**
 * The device's IANA time zone, or undefined where `Intl` is unavailable.
 *
 * Guarded because RN on older Android ships a Hermes build without full ICU, and a
 * throw here would fail a prompt for a field that is only a hint.
 */
function resolveTimeZone(): string | undefined {
  try {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return typeof zone === 'string' && zone.length > 0 ? zone : undefined;
  } catch {
    return undefined;
  }
}

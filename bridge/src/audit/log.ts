/**
 * [OUR DESIGN] Append-only audit log.
 *
 * The question this exists to answer is "what did my phone do while I was away."
 * That means every gated decision and every answer delivered from a phone is
 * recorded with enough context to reconstruct intent, and nothing more.
 *
 * What is NEVER written, by construction rather than by discipline:
 * - payload text (prompts, file contents, tool arguments) — only a SHA-256 digest
 * - tokens, nonces, signatures, pairing tokens, private keys
 * - question answers or approval reasons in free-text form
 *
 * The digest lets you prove two requests were identical without revealing what
 * either said. `bytes` lets you spot exfiltration-shaped traffic.
 */

import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';

export type AuditDecision = 'allowed' | 'denied' | 'rate-limited' | 'failed';

export interface AuditEntry {
  /** ISO-8601 with milliseconds, so ordering survives log merging. */
  at: string;
  event:
    | 'rpc'
    | 'respond'
    | 'pair-claim'
    | 'pair-confirm'
    | 'pair-reject'
    | 'auth-challenge'
    | 'auth-success'
    | 'auth-failure'
    | 'token-rotate'
    | 'stream-attach'
    | 'stream-detach'
    | 'device-revoke'
    | 'bridge-start'
    | 'bridge-stop';
  /** Absent for pre-auth events (a pairing claim has no device yet). */
  deviceId?: string;
  deviceLabel?: string;
  method?: string;
  sessionId?: string;
  /** dsh `rpcId`, so an approval can be traced to the frame that asked. */
  rpcId?: string;
  decision?: AuditDecision;
  /** Why a request was refused. Never contains payload content. */
  reason?: string;
  /** SHA-256 of the canonical payload, truncated to 16 hex chars. */
  payloadDigest?: string;
  payloadBytes?: number;
  peer?: string;
  /** Set on a resync, so window overflow is visible after the fact. */
  resync?: boolean;
}

/** Digest a payload without ever retaining it. */
export function payloadDigest(payload: unknown): { digest: string; bytes: number } {
  let serialized: string;
  try {
    serialized = JSON.stringify(payload) ?? 'undefined';
  } catch {
    // Circular or non-serializable: still record the shape decision.
    serialized = '<unserializable>';
  }
  const bytes = Buffer.byteLength(serialized, 'utf8');
  return { digest: createHash('sha256').update(serialized, 'utf8').digest('hex').slice(0, 16), bytes };
}

export interface AuditLogOptions {
  /** Directory for `audit.jsonl`. When absent the log is memory-only. */
  stateDir?: string;
  /** Retained in-memory entries for `status` output. */
  memoryLimit?: number;
  now?: () => number;
  /** Mirror entries to stderr. Useful when running in the foreground. */
  echo?: boolean;
}

/**
 * JSONL writer.
 *
 * Writes are synchronous appends. That is a deliberate trade: an audit record
 * that loses the race with a crash is worse than a few hundred microseconds of
 * latency on a request a human initiated.
 */
export class AuditLog {
  private readonly file: string | undefined;
  private readonly memoryLimit: number;
  private readonly now: () => number;
  private readonly echo: boolean;
  private recent: AuditEntry[] = [];
  private writeFailed = false;

  constructor(options: AuditLogOptions = {}) {
    this.memoryLimit = options.memoryLimit ?? 200;
    this.now = options.now ?? Date.now;
    this.echo = options.echo ?? false;
    if (options.stateDir !== undefined) {
      this.file = join(options.stateDir, 'audit.jsonl');
      mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 });
    }
  }

  record(entry: Omit<AuditEntry, 'at'>): AuditEntry {
    const full: AuditEntry = { at: new Date(this.now()).toISOString(), ...entry };
    this.recent.push(full);
    if (this.recent.length > this.memoryLimit) this.recent.shift();
    if (this.echo) console.error(`[audit] ${JSON.stringify(full)}`);

    if (this.file !== undefined && !this.writeFailed) {
      try {
        appendFileSync(this.file, `${JSON.stringify(full)}\n`, { mode: 0o600 });
      } catch (error) {
        // Report once and keep serving. A full disk must not take the bridge
        // down, but it must be loud, because the audit trail is now incomplete.
        this.writeFailed = true;
        console.error('[audit] write failed; audit trail is incomplete:', error);
      }
    }
    return full;
  }

  /** Most recent entries, newest last. */
  tail(count = 20): readonly AuditEntry[] {
    return this.recent.slice(Math.max(0, this.recent.length - count));
  }

  path(): string | undefined {
    return this.file;
  }

  /** Bytes on disk, for `status`. */
  sizeBytes(): number | undefined {
    if (this.file === undefined) return undefined;
    try {
      return statSync(this.file).size;
    } catch {
      return undefined;
    }
  }
}

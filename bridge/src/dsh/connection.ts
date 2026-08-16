/**
 * Connection generations against dsh, mirroring the official client's posture.
 *
 * Verified semantics implemented here:
 *   - Readiness requires BOTH downlink sockets open AND a successful
 *     `host.describe`. Only then is the generation connected.
 *   - If either socket ends, the whole generation fails and BOTH streams are
 *     rebuilt. Streams are never repaired independently.
 *   - The `host.describe` value is published per generation and cleared on
 *     generation loss, so capability answers are never retained while
 *     disconnected.
 *   - Recovery is the official procedure. There is no `since` resume: that field
 *     is an unimplemented seat upstream and is never sent.
 *
 * Rebaseline is the documented procedure: reopen, take `session/subscribed`
 * `lastSeq` per session as the watermark, refetch `session.history`, re-baseline
 * `session.list` / `workspace.list` / history-tail `projections`, and re-surface
 * replayed answerable frames (which arrive with their original `rpcId`).
 */

import type { DshApiClient } from './client.ts';
import type { DshDownlink, DownlinkEnvelope } from './downlink.ts';
import type { HostFrame, MuxFrame } from './types.ts';

export type DshConnectionState = 'idle' | 'connecting' | 'connected' | 'reconnecting';

export interface DshConnectionSinks {
  /** Fires once per generation, after the full readiness handshake. */
  onConnected?: (description: unknown) => void;
  /** Fires when a connected generation is lost. */
  onDisconnected?: (reason: string) => void;
  onStateChange?: (state: DshConnectionState) => void;
  onMuxFrame?: (envelope: DownlinkEnvelope<MuxFrame>) => void;
  onHostFrame?: (envelope: DownlinkEnvelope<HostFrame>) => void;
}

export interface DshConnectionOptions {
  client: DshApiClient;
  downlink: DshDownlink;
  sinks?: DshConnectionSinks;
  /** Cap on waiting for both sockets to open before failing the handshake. */
  streamOpenTimeoutMs?: number;
  /** Backoff base; delay is base * 2^(attempt-1), capped. */
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  /** Injectable sleep so tests do not wait in real time. */
  sleepImpl?: (ms: number, signal: AbortSignal) => Promise<void>;
}

function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

/** Resolves as soon as `signal` aborts (or immediately if it already has). */
function aborted(signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    signal.addEventListener('abort', () => resolve(), { once: true });
  });
}

export class DshConnection {
  private readonly client: DshApiClient;
  private readonly downlink: DshDownlink;
  private readonly sinks: DshConnectionSinks;
  private readonly streamOpenTimeoutMs: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly sleep: (ms: number, signal: AbortSignal) => Promise<void>;

  private running = false;
  private generation = 0;
  private attempt = 0;
  private current: AbortController | undefined;
  /** Aborts the backoff sleep so `stop()` never waits out a retry delay. */
  private backoff: AbortController | undefined;
  private state: DshConnectionState = 'idle';
  private description: unknown;
  private loopPromise: Promise<void> | undefined;

  constructor(options: DshConnectionOptions) {
    this.client = options.client;
    this.downlink = options.downlink;
    this.sinks = options.sinks ?? {};
    this.streamOpenTimeoutMs = options.streamOpenTimeoutMs ?? 5_000;
    this.backoffBaseMs = options.backoffBaseMs ?? 500;
    this.backoffMaxMs = options.backoffMaxMs ?? 15_000;
    this.sleep = options.sleepImpl ?? defaultSleep;
  }

  /** Current coarse state, for `/m1/health`. */
  getState(): DshConnectionState {
    return this.state;
  }

  /**
   * The connected generation's `host.describe` value, or `undefined` while
   * disconnected. Never retained across generation loss.
   */
  getDescription(): unknown {
    return this.description;
  }

  isConnected(): boolean {
    return this.state === 'connected';
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.loopPromise = this.loop();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.current?.abort();
    // Interrupt an in-flight backoff too, or stop() would wait out the delay.
    this.backoff?.abort();
    await this.loopPromise;
    this.description = undefined;
    this.setState('idle');
  }

  private setState(next: DshConnectionState): void {
    if (this.state === next) return;
    this.state = next;
    this.sinks.onStateChange?.(next);
  }

  private backoffDelay(attempt: number): number {
    return Math.min(this.backoffBaseMs * 2 ** (attempt - 1), this.backoffMaxMs);
  }

  private async loop(): Promise<void> {
    while (this.running) {
      const gen = ++this.generation;
      const ac = new AbortController();
      this.current = ac;
      this.setState(this.attempt === 0 ? 'connecting' : 'reconnecting');

      let muxOpened = (): void => {};
      let hostOpened = (): void => {};
      const streamsOpen = Promise.all([
        new Promise<void>((resolve) => {
          muxOpened = resolve;
        }),
        new Promise<void>((resolve) => {
          hostOpened = resolve;
        }),
      ]);

      let failureReason = 'stream ended';
      // Either stream ending fails the whole generation; both are then rebuilt.
      const failed = new Promise<void>((resolve) => {
        const settle = (reason: string): void => {
          failureReason = reason;
          if (gen === this.generation && !ac.signal.aborted) ac.abort();
          resolve();
        };
        void this.pump(this.downlink.openMux(ac.signal, muxOpened), (e) => this.sinks.onMuxFrame?.(e), settle, 'mux');
        void this.pump(this.downlink.openHost(ac.signal, hostOpened), (e) => this.sinks.onHostFrame?.(e), settle, 'host');
      });

      try {
        // Strict handshake: describe proves unary reachability while onOpen proves
        // each socket is physically established. Only then may onConnected fire,
        // so a rebaseline it triggers cannot outrun the subscribed baseline.
        const timeoutAc = new AbortController();
        const description = await Promise.all([
          this.client.describeHost(ac.signal),
          // The open-timeout guards a carrier that never fires onOpen. Losing the
          // generation also releases this wait, so a hung socket cannot pin it.
          Promise.race([
            streamsOpen,
            this.sleep(this.streamOpenTimeoutMs, timeoutAc.signal),
            aborted(ac.signal),
          ]),
        ]);
        timeoutAc.abort();
        if (ac.signal.aborted) throw new Error('generation aborted during readiness handshake');
        this.attempt = 0;
        this.description = description[0];
        this.setState('connected');
        this.sinks.onConnected?.(description[0]);
      } catch (error) {
        failureReason = error instanceof Error ? error.message : String(error);
        if (!ac.signal.aborted) ac.abort();
      }

      await failed;
      const wasConnected = this.state === 'connected';
      // Capability answers must never survive the generation that produced them.
      this.description = undefined;
      if (wasConnected) this.sinks.onDisconnected?.(failureReason);
      if (!this.running) return;
      this.setState('reconnecting');
      this.attempt += 1;
      const idle = new AbortController();
      this.backoff = idle;
      // Raced against the abort rather than trusting the sleep to honor its
      // signal: an injected sleep that ignores it must not be able to wedge
      // shutdown of a long-running bridge process.
      await Promise.race([this.sleep(this.backoffDelay(this.attempt), idle.signal), aborted(idle.signal)]);
      this.backoff = undefined;
    }
  }

  private async pump<F>(
    frames: AsyncGenerator<DownlinkEnvelope<F>>,
    sink: (envelope: DownlinkEnvelope<F>) => void,
    settle: (reason: string) => void,
    label: string,
  ): Promise<void> {
    try {
      for await (const envelope of frames) {
        try {
          sink(envelope);
        } catch (error) {
          // A throwing sink must not take down the carrier.
          console.error(`[bridge:dsh] ${label} sink threw:`, error);
        }
      }
      settle(`${label} stream ended`);
    } catch (error) {
      settle(`${label} stream failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

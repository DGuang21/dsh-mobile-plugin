/**
 * Downlink reader for `events.mux` and `events.host`.
 *
 * Why WebSocket and not SSE: `toFetchHandler` does implement an SSE codec, but
 * the shipped Web composition intercepts `GET /api/events.mux` and
 * `GET /api/events.host` and answers **426 Upgrade Required** with
 * `connection: Upgrade, upgrade: websocket`. The SSE codec serves only the
 * in-process (Electron) carrier. A network client therefore MUST upgrade.
 * Verified in packages/client/connection/src/index.ts.
 *
 * The socket is downlink-only: upstream treats any client message as a protocol
 * violation, so we never send application data on it.
 *
 * A frame that fails validation is reported and skipped. One corrupt frame must
 * not kill the stream — that is upstream's documented posture, and our own gap
 * detection (bseq) covers whatever the frame carried.
 */

import { DshTransportError } from './errors.ts';
import { validateHostFrame, validateMuxFrame, validateServerRequest } from './validate.ts';
import type { HostFrame, MuxFrame } from './types.ts';
import { HOST_EVENTS_PATH, MUX_EVENTS_PATH } from './types.ts';
import type { Validated } from './validate.ts';

/** One frame with the correlation id that answerable frames echo. */
export interface DownlinkEnvelope<F> {
  rpcId: string;
  frame: F;
}

/** The slice of the WebSocket API this reader needs, so tests can fake it. */
export interface WebSocketLike {
  readyState: number;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (event: any) => void, options?: { once?: boolean }): void;
  removeEventListener(type: string, listener: (event: any) => void): void;
}

export type WebSocketFactory = (url: string) => WebSocketLike;

const OPEN = 1;
const CONNECTING = 0;

export interface DownlinkOptions {
  /** dsh web origin, e.g. `http://127.0.0.1:3080`. */
  baseUrl: string;
  webSocketFactory?: WebSocketFactory;
  /** Reports a dropped frame. Defaults to `console.error`. */
  onMalformedFrame?: (path: string, reason: string) => void;
}

type Item<F> = { kind: 'frame'; envelope: DownlinkEnvelope<F> } | { kind: 'end' } | { kind: 'error'; error: Error };

/** Opens and reads the two dsh downlinks. */
export class DshDownlink {
  private readonly baseUrl: string;
  private readonly factory: WebSocketFactory;
  private readonly onMalformed: (path: string, reason: string) => void;

  constructor(options: DownlinkOptions) {
    this.baseUrl = new URL(options.baseUrl).origin;
    this.factory =
      options.webSocketFactory ?? ((url) => new WebSocket(url) as unknown as WebSocketLike);
    this.onMalformed =
      options.onMalformedFrame ??
      ((path, reason) => {
        console.error(`[bridge:dsh] dropping malformed frame on ${path}: ${reason}`);
      });
  }

  /** All-session aggregated mux stream. */
  openMux(signal: AbortSignal, onOpen?: () => void): AsyncGenerator<DownlinkEnvelope<MuxFrame>> {
    return this.read(MUX_EVENTS_PATH, signal, validateMuxFrame, onOpen);
  }

  /** Host-level stream. */
  openHost(signal: AbortSignal, onOpen?: () => void): AsyncGenerator<DownlinkEnvelope<HostFrame>> {
    return this.read(HOST_EVENTS_PATH, signal, validateHostFrame, onOpen);
  }

  private wsUrl(path: string): string {
    const url = new URL(path, this.baseUrl);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    return url.toString();
  }

  private async *read<F>(
    path: string,
    signal: AbortSignal,
    validate: (value: unknown) => Validated<F>,
    onOpen?: () => void,
  ): AsyncGenerator<DownlinkEnvelope<F>> {
    const socket = this.factory(this.wsUrl(path));
    const inbox: Item<F>[] = [];
    let wake: (() => void) | undefined;

    const push = (item: Item<F>): void => {
      inbox.push(item);
      wake?.();
      wake = undefined;
    };

    const handleOpen = (): void => onOpen?.();
    const handleMessage = (event: { data: unknown }): void => {
      if (typeof event.data !== 'string') {
        this.onMalformed(path, 'binary WebSocket frame');
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(event.data);
      } catch (error) {
        this.onMalformed(path, `body is not JSON: ${String(error)}`);
        return;
      }
      const envelope = validateServerRequest(parsed);
      if (!envelope.ok) {
        this.onMalformed(path, envelope.reason);
        return;
      }
      const frame = validate(envelope.value.payload);
      if (!frame.ok) {
        this.onMalformed(path, frame.reason);
        return;
      }
      push({ kind: 'frame', envelope: { rpcId: envelope.value.rpcId, frame: frame.value } });
    };
    const handleClose = (): void => push({ kind: 'end' });
    const handleError = (): void => {
      // The `error` event carries no useful detail in the WHATWG API; a close
      // always follows, so this only records that the end was not graceful.
      push({ kind: 'error', error: new DshTransportError(`downlink socket failed: ${path}`, { method: path }) });
    };
    const handleAbort = (): void => {
      if (socket.readyState === CONNECTING || socket.readyState === OPEN) socket.close();
    };

    socket.addEventListener('open', handleOpen);
    socket.addEventListener('message', handleMessage);
    socket.addEventListener('close', handleClose, { once: true });
    socket.addEventListener('error', handleError);
    signal.addEventListener('abort', handleAbort, { once: true });
    if (signal.aborted) handleAbort();

    try {
      for (;;) {
        while (inbox.length > 0) {
          const item = inbox.shift() as Item<F>;
          if (item.kind === 'end') return;
          if (item.kind === 'error') {
            // Surface the failure instead of ending silently: a silent end reads
            // as a normal disconnect and would hide a broken carrier.
            if (inbox.some((next) => next.kind === 'end')) throw item.error;
            throw item.error;
          }
          yield item.envelope;
        }
        await new Promise<void>((resolve) => {
          wake = resolve;
        });
      }
    } finally {
      signal.removeEventListener('abort', handleAbort);
      socket.removeEventListener('open', handleOpen);
      socket.removeEventListener('message', handleMessage);
      socket.removeEventListener('close', handleClose);
      socket.removeEventListener('error', handleError);
      handleAbort();
    }
  }
}

/** Controllable WebSocket double for downlink tests. */

import type { WebSocketLike } from '../src/dsh/downlink.ts';

export class FakeSocket implements WebSocketLike {
  readyState = 0;
  closed = false;
  private readonly listeners = new Map<string, ((event: any) => void)[]>();

  constructor(readonly url: string) {}

  addEventListener(type: string, listener: (event: any) => void): void {
    const existing = this.listeners.get(type) ?? [];
    existing.push(listener);
    this.listeners.set(type, existing);
  }

  removeEventListener(type: string, listener: (event: any) => void): void {
    const existing = this.listeners.get(type) ?? [];
    this.listeners.set(
      type,
      existing.filter((entry) => entry !== listener),
    );
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.readyState = 3;
    this.emit('close', {});
  }

  private emit(type: string, event: unknown): void {
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener(event);
  }

  /** Simulate the socket becoming established. */
  open(): void {
    this.readyState = 1;
    this.emit('open', {});
  }

  /** Deliver a raw text message, exactly as dsh would. */
  deliver(data: string): void {
    this.emit('message', { data });
  }

  /** Deliver a ServerRequest-wrapped frame. */
  deliverFrame(rpcId: string, payload: unknown): void {
    this.deliver(JSON.stringify({ type: 'server-request', rpcId, method: (payload as { type: string }).type, payload }));
  }

  fail(): void {
    this.emit('error', {});
  }
}

/** Factory that records every socket it creates, keyed by path. */
export function socketRecorder(): {
  factory: (url: string) => WebSocketLike;
  sockets: FakeSocket[];
  byPath: (fragment: string) => FakeSocket | undefined;
} {
  const sockets: FakeSocket[] = [];
  return {
    factory: (url: string) => {
      const socket = new FakeSocket(url);
      sockets.push(socket);
      return socket;
    },
    sockets,
    byPath: (fragment) => sockets.find((socket) => socket.url.includes(fragment)),
  };
}

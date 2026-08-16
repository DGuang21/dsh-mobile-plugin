/**
 * Local control socket.
 *
 * `pair`, `list`, `revoke`, and `status` must act on the *running* bridge: a
 * pairing window lives in memory, and a revocation has to terminate live streams
 * rather than only fail the next request. A second CLI process therefore needs a way
 * in, and this is it.
 *
 * Security model, stated plainly: authorization is filesystem permissions. The
 * socket lives in the state directory at mode 0600 inside a 0700 directory, so the
 * caller must already be the workstation user — the same user the bridge runs as and
 * the same user who could read the bridge's private key or attach a debugger to it.
 * Adding a token here would protect nothing that is not already lost.
 *
 * What this does NOT do: it is not reachable over TCP, it is not exposed to a phone,
 * and it is never proxied through the relay. Those are all deliberate; every
 * command here is privileged.
 *
 * `[NOT INTEGRATION-TESTED]` on Windows: named pipes need a different path shape and
 * a different permission story.
 */

import { createServer, connect as netConnect, type Server, type Socket } from 'node:net';
import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

export const CONTROL_SOCKET_NAME = 'control.sock';

export function controlSocketPath(stateDir: string): string {
  return join(stateDir, CONTROL_SOCKET_NAME);
}

/** CLI → running bridge. */
export type ControlRequest =
  | { type: 'status' }
  | { type: 'list' }
  | { type: 'revoke'; deviceId: string }
  /**
   * Open a pairing window and stream its progress on this connection.
   *
   * `relay` mode needs no routing id: the rendezvous id is derived from the pairing
   * token, so both sides compute it independently. See relay/rendezvous.ts.
   */
  | { type: 'pair'; tier?: 'default' | 'extended'; relay?: boolean }
  /** Operator's answer to the SAS prompt. */
  | { type: 'pair-confirm'; accept: boolean }
  | { type: 'pair-cancel' };

/** Running bridge → CLI. Multiple messages may follow one request. */
export type ControlResponse =
  | { type: 'ok'; value: unknown }
  | { type: 'error'; message: string }
  /** A pairing window opened; `uri` is the QR payload. */
  | { type: 'pair-open'; uri: string; token: string; expiresAt: number }
  /** A phone claimed the token; the operator must compare `sas`. */
  | { type: 'pair-claimed'; sas: string; deviceId: string; label: string; expiresAt: number }
  | { type: 'pair-done'; deviceId: string; label: string; tier: string }
  | { type: 'pair-failed'; reason: string };

export interface ControlHandlers {
  status(): unknown;
  list(): unknown;
  revoke(deviceId: string): { ok: boolean; message: string };
  /**
   * Begin pairing. `emit` pushes progress to this CLI connection; the returned
   * disposer is called when the connection drops so an abandoned `pair` cannot leave
   * a pairing window open.
   */
  beginPair(
    input: { tier: 'default' | 'extended'; relay: boolean },
    emit: (message: ControlResponse) => void,
  ): { confirm(accept: boolean): void; cancel(): void };
}

export class ControlServer {
  private readonly server: Server;
  private readonly path: string;

  constructor(stateDir: string, handlers: ControlHandlers) {
    this.path = controlSocketPath(stateDir);
    this.server = createServer((socket) => this.handleConnection(socket, handlers));
  }

  async listen(): Promise<string> {
    // A socket left behind by a crashed bridge would block binding. Removing it is
    // safe only because a live bridge holds an exclusive listen on the same path,
    // which makes the second `listen` fail below.
    if (existsSync(this.path)) {
      try {
        await probe(this.path);
        throw new Error(`another bridge is already listening on ${this.path}`);
      } catch (error) {
        if (error instanceof Error && error.message.startsWith('another bridge')) throw error;
        unlinkSync(this.path);
      }
    }
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.path, () => {
        this.server.removeListener('error', reject);
        resolve();
      });
    });
    // Owner-only. This is the authorization boundary, so it is set explicitly
    // rather than left to the process umask.
    chmodSync(this.path, 0o600);
    return this.path;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    if (existsSync(this.path)) {
      try {
        unlinkSync(this.path);
      } catch {
        // Already gone.
      }
    }
  }

  private handleConnection(socket: Socket, handlers: ControlHandlers): void {
    let buffer = '';
    let pairing: { confirm(accept: boolean): void; cancel(): void } | undefined;

    const send = (message: ControlResponse): void => {
      if (socket.destroyed) return;
      socket.write(`${JSON.stringify(message)}\n`);
    };

    socket.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      // A control message that never terminates is a bug or an attempt to grow the
      // buffer without bound.
      if (buffer.length > 64 * 1024) {
        send({ type: 'error', message: 'control message too large' });
        socket.destroy();
        return;
      }
      for (;;) {
        const newline = buffer.indexOf('\n');
        if (newline === -1) break;
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line.trim().length === 0) continue;

        let request: ControlRequest;
        try {
          request = JSON.parse(line) as ControlRequest;
        } catch {
          send({ type: 'error', message: 'control request must be JSON' });
          continue;
        }

        try {
          switch (request.type) {
            case 'status':
              send({ type: 'ok', value: handlers.status() });
              break;
            case 'list':
              send({ type: 'ok', value: handlers.list() });
              break;
            case 'revoke': {
              if (typeof request.deviceId !== 'string' || request.deviceId.length === 0) {
                send({ type: 'error', message: 'revoke requires a deviceId' });
                break;
              }
              const result = handlers.revoke(request.deviceId);
              if (result.ok) send({ type: 'ok', value: { message: result.message } });
              else send({ type: 'error', message: result.message });
              break;
            }
            case 'pair': {
              if (pairing !== undefined) {
                send({ type: 'error', message: 'a pairing is already in flight on this connection' });
                break;
              }
              pairing = handlers.beginPair(
                {
                  tier: request.tier === 'extended' ? 'extended' : 'default',
                  relay: request.relay === true,
                },
                send,
              );
              break;
            }
            case 'pair-confirm': {
              if (pairing === undefined) {
                send({ type: 'error', message: 'no pairing in flight' });
                break;
              }
              pairing.confirm(request.accept === true);
              break;
            }
            case 'pair-cancel': {
              pairing?.cancel();
              pairing = undefined;
              send({ type: 'ok', value: { cancelled: true } });
              break;
            }
            default:
              send({ type: 'error', message: 'unknown control request' });
          }
        } catch (error) {
          send({ type: 'error', message: error instanceof Error ? error.message : String(error) });
        }
      }
    });

    // A dropped CLI must not leave a pairing window open: an abandoned QR that
    // stays claimable is exactly the thing the 120-second TTL exists to prevent.
    socket.on('close', () => pairing?.cancel());
    socket.on('error', () => pairing?.cancel());
  }
}

/** Connect to a running bridge, or report that there is none. */
export function connectControl(
  stateDir: string,
): Promise<{ ok: true; socket: Socket } | { ok: false; reason: string }> {
  const path = controlSocketPath(stateDir);
  if (!existsSync(path)) return Promise.resolve({ ok: false, reason: 'no bridge is running (control socket absent)' });
  return new Promise((resolve) => {
    const socket = netConnect({ path });
    socket.once('connect', () => resolve({ ok: true, socket }));
    socket.once('error', (error: Error) => {
      resolve({ ok: false, reason: `control socket present but not accepting: ${error.message}` });
    });
  });
}

/** Read newline-delimited responses until `done` returns true. */
export function readResponses(
  socket: Socket,
  onMessage: (message: ControlResponse) => boolean,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let buffer = '';
    socket.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      for (;;) {
        const newline = buffer.indexOf('\n');
        if (newline === -1) break;
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (line.trim().length === 0) continue;
        let message: ControlResponse;
        try {
          message = JSON.parse(line) as ControlResponse;
        } catch {
          reject(new Error('bridge sent a malformed control response'));
          return;
        }
        if (onMessage(message)) {
          resolve();
          return;
        }
      }
    });
    socket.on('error', reject);
    socket.on('close', () => resolve());
  });
}

/** Is something listening on this socket right now? */
function probe(path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ path });
    socket.once('connect', () => {
      socket.destroy();
      resolve();
    });
    socket.once('error', reject);
  });
}

/**
 * Minimal RFC 6455 server-side WebSocket, hand-rolled.
 *
 * Why not `ws`: this package shares a tree with an Expo app. Every Node-only
 * dependency added here is one more thing Metro can be tricked into resolving,
 * and the server side of RFC 6455 that we need — text frames, close, ping/pong,
 * fragmentation — is small and fully specified. Node 22 gives us a client
 * `WebSocket` for the dsh downlink, but no server.
 *
 * Protocol rules enforced (RFC 6455 §5):
 * - Client-to-server frames MUST be masked. Unmasked → close 1002.
 * - Server-to-client frames MUST NOT be masked.
 * - Control frames: payload ≤ 125 bytes, never fragmented.
 * - RSV bits must be zero (we negotiate no extensions).
 * - Reserved/unknown opcodes → close 1002.
 * - Text payloads must be valid UTF-8 → close 1007 otherwise.
 * - Close codes are validated; a bad code is itself a protocol error.
 *
 * Limits are enforced on the *accumulated* message, not just the frame, so
 * fragmentation cannot be used to sneak past the cap.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';

/** RFC 6455 §1.3. Fixed by the spec, not a configurable value. */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export const OPCODE = {
  continuation: 0x0,
  text: 0x1,
  binary: 0x2,
  close: 0x8,
  ping: 0x9,
  pong: 0xa,
} as const;

export const CLOSE = {
  normal: 1000,
  goingAway: 1001,
  protocolError: 1002,
  unsupportedData: 1003,
  invalidPayload: 1007,
  policyViolation: 1008,
  messageTooBig: 1009,
  internalError: 1011,
} as const;

export type CloseCode = (typeof CLOSE)[keyof typeof CLOSE];

/** Accept value for a `sec-websocket-key`. */
export function computeAcceptKey(key: string): string {
  return createHash('sha1')
    .update(key + WS_GUID, 'utf8')
    .digest('base64');
}

export interface UpgradeCheck {
  ok: boolean;
  /** Set when `ok` is false: the HTTP status to answer with. */
  status?: number;
  reason?: string;
  key?: string;
  subprotocols?: string[];
}

/**
 * Validate an HTTP upgrade request.
 *
 * Returns a failure rather than throwing so the caller can answer with a real
 * HTTP status; a client that got the handshake wrong deserves a diagnosable
 * response, not a dropped socket.
 */
export function checkUpgrade(request: IncomingMessage): UpgradeCheck {
  const headers = request.headers;
  if ((request.method ?? 'GET').toUpperCase() !== 'GET') {
    return { ok: false, status: 405, reason: 'websocket upgrade must be GET' };
  }
  const upgrade = headers.upgrade;
  if (typeof upgrade !== 'string' || upgrade.toLowerCase() !== 'websocket') {
    return { ok: false, status: 400, reason: 'missing upgrade: websocket' };
  }
  const connection = headers.connection;
  if (typeof connection !== 'string' || !/(^|,)\s*upgrade\s*(,|$)/i.test(connection)) {
    return { ok: false, status: 400, reason: 'missing connection: upgrade' };
  }
  if (headers['sec-websocket-version'] !== '13') {
    return { ok: false, status: 426, reason: 'unsupported websocket version' };
  }
  const key = headers['sec-websocket-key'];
  if (typeof key !== 'string' || Buffer.from(key, 'base64').byteLength !== 16) {
    return { ok: false, status: 400, reason: 'invalid sec-websocket-key' };
  }
  const rawProtocols = headers['sec-websocket-protocol'];
  const subprotocols =
    typeof rawProtocols === 'string'
      ? rawProtocols
          .split(',')
          .map((value) => value.trim())
          .filter((value) => value.length > 0)
      : [];
  return { ok: true, key, subprotocols };
}

/** Write the 101 response. `protocol`, when given, MUST be one the client offered. */
export function writeHandshake(socket: Duplex, key: string, protocol?: string): void {
  const lines = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${computeAcceptKey(key)}`,
  ];
  if (protocol !== undefined) lines.push(`Sec-WebSocket-Protocol: ${protocol}`);
  socket.write(`${lines.join('\r\n')}\r\n\r\n`);
}

/**
 * Encode a frame.
 *
 * Server frames are never masked and client frames always are (RFC 6455 §5.1), so
 * `mask` is set by the role of whoever is sending, not by choice. The mask is
 * cryptographically random rather than a counter: masking exists to defeat
 * cache-poisoning intermediaries, and a predictable key weakens that.
 */
export function encodeFrame(opcode: number, payload: Buffer, fin = true, mask = false): Buffer {
  const length = payload.byteLength;
  const headerBytes = length < 126 ? 2 : length < 65_536 ? 4 : 10;
  const header = Buffer.allocUnsafe(headerBytes + (mask ? 4 : 0));
  if (length < 126) {
    header[1] = length;
  } else if (length < 65_536) {
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header[1] = 127;
    // High 32 bits are always zero: we never send a frame ≥ 4 GiB.
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(length, 6);
  }
  header[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0f);
  if (!mask) return Buffer.concat([header, payload]);

  header[1] = (header[1] as number) | 0x80;
  const key = randomBytes(4);
  key.copy(header, headerBytes);
  const masked = Buffer.allocUnsafe(length);
  for (let i = 0; i < length; i += 1) {
    masked[i] = (payload[i] as number) ^ (key[i % 4] as number);
  }
  return Buffer.concat([header, masked]);
}

export function encodeCloseFrame(code: CloseCode | number, reason = '', mask = false): Buffer {
  const reasonBytes = Buffer.from(reason, 'utf8');
  // Close reason is capped so the control frame stays within 125 bytes.
  const payload = Buffer.allocUnsafe(2 + Math.min(reasonBytes.byteLength, 123));
  payload.writeUInt16BE(code, 0);
  reasonBytes.copy(payload, 2, 0, payload.byteLength - 2);
  return encodeFrame(OPCODE.close, payload, true, mask);
}

/** A close code a client is allowed to send (RFC 6455 §7.4). */
function isValidCloseCode(code: number): boolean {
  if (code >= 3000 && code <= 4999) return true;
  return (
    code === 1000 ||
    code === 1001 ||
    code === 1002 ||
    code === 1003 ||
    code === 1007 ||
    code === 1008 ||
    code === 1009 ||
    code === 1010 ||
    code === 1011
  );
}

export type DecodedMessage =
  | { kind: 'text'; data: string }
  | { kind: 'binary'; data: Buffer }
  | { kind: 'ping'; data: Buffer }
  | { kind: 'pong'; data: Buffer }
  | { kind: 'close'; code: number; reason: string };

export type DecodeOutcome =
  | { ok: true; messages: DecodedMessage[] }
  | { ok: false; code: CloseCode; reason: string };

export interface DecoderLimits {
  /** Cap on a single accumulated message. Fragments are summed. */
  maxMessageBytes: number;
  /**
   * Whether incoming frames must be masked.
   *
   * True when decoding client→server traffic, false when decoding server→client.
   * Defaults to true so the server side — the one exposed to hostile input — gets
   * the strict behaviour without having to ask for it.
   */
  requireMask?: boolean;
}

/**
 * Incremental frame decoder.
 *
 * Buffers partial frames across TCP reads and yields whole messages. It never
 * throws on malformed input: a protocol violation is returned as a close code so
 * the caller can respond correctly instead of unwinding the connection handler.
 */
export class FrameDecoder {
  private buffer: Buffer = Buffer.alloc(0);
  private fragments: Buffer[] = [];
  private fragmentOpcode: number | undefined;
  private fragmentBytes = 0;
  private failed = false;

  private readonly limits: DecoderLimits;

  constructor(limits: DecoderLimits) {
    this.limits = limits;
  }

  push(chunk: Buffer): DecodeOutcome {
    if (this.failed) return { ok: true, messages: [] };
    this.buffer = this.buffer.byteLength === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const messages: DecodedMessage[] = [];

    for (;;) {
      const frame = this.readFrame();
      if (frame === undefined) break;
      if ('error' in frame) {
        this.failed = true;
        return { ok: false, code: frame.error.code, reason: frame.error.reason };
      }

      const { fin, opcode, payload } = frame.frame;

      // Control frames may be interleaved between fragments and are never
      // themselves fragmented.
      if (opcode >= 0x8) {
        if (!fin) return this.fail('control frame must not be fragmented');
        if (payload.byteLength > 125) return this.fail('control frame payload too long');
        if (opcode === OPCODE.ping) {
          messages.push({ kind: 'ping', data: payload });
          continue;
        }
        if (opcode === OPCODE.pong) {
          messages.push({ kind: 'pong', data: payload });
          continue;
        }
        if (opcode === OPCODE.close) {
          if (payload.byteLength === 1) return this.fail('close payload must be 0 or >= 2 bytes');
          if (payload.byteLength === 0) {
            messages.push({ kind: 'close', code: CLOSE.normal, reason: '' });
            return { ok: true, messages };
          }
          const code = payload.readUInt16BE(0);
          if (!isValidCloseCode(code)) return this.fail(`invalid close code ${code}`);
          const reasonBytes = payload.subarray(2);
          const reason = reasonBytes.toString('utf8');
          if (!isValidUtf8(reasonBytes, reason)) {
            this.failed = true;
            return { ok: false, code: CLOSE.invalidPayload, reason: 'close reason is not valid utf-8' };
          }
          messages.push({ kind: 'close', code, reason });
          return { ok: true, messages };
        }
        return this.fail(`reserved control opcode 0x${opcode.toString(16)}`);
      }

      if (opcode === OPCODE.continuation) {
        if (this.fragmentOpcode === undefined) return this.fail('continuation without an initial frame');
      } else if (opcode === OPCODE.text || opcode === OPCODE.binary) {
        if (this.fragmentOpcode !== undefined) return this.fail('new data frame while a message is fragmented');
        this.fragmentOpcode = opcode;
      } else {
        return this.fail(`reserved data opcode 0x${opcode.toString(16)}`);
      }

      this.fragmentBytes += payload.byteLength;
      // Enforced on the accumulated total, so fragmentation cannot bypass it.
      if (this.fragmentBytes > this.limits.maxMessageBytes) {
        this.failed = true;
        return { ok: false, code: CLOSE.messageTooBig, reason: 'message exceeds limit' };
      }
      this.fragments.push(payload);

      if (!fin) continue;

      const complete = this.fragments.length === 1 ? (this.fragments[0] as Buffer) : Buffer.concat(this.fragments);
      const messageOpcode = this.fragmentOpcode;
      this.fragments = [];
      this.fragmentOpcode = undefined;
      this.fragmentBytes = 0;

      if (messageOpcode === OPCODE.text) {
        const text = complete.toString('utf8');
        if (!isValidUtf8(complete, text)) {
          this.failed = true;
          return { ok: false, code: CLOSE.invalidPayload, reason: 'text frame is not valid utf-8' };
        }
        messages.push({ kind: 'text', data: text });
      } else {
        messages.push({ kind: 'binary', data: complete });
      }
    }

    return { ok: true, messages };
  }

  private fail(reason: string): DecodeOutcome {
    this.failed = true;
    return { ok: false, code: CLOSE.protocolError, reason };
  }

  /**
   * Pull one frame off the buffer.
   *
   * `undefined` means "need more bytes" — the common case on a partial read.
   */
  private readFrame():
    | { frame: { fin: boolean; opcode: number; payload: Buffer } }
    | { error: { code: CloseCode; reason: string } }
    | undefined {
    const buffer = this.buffer;
    if (buffer.byteLength < 2) return undefined;

    const first = buffer[0] as number;
    const second = buffer[1] as number;
    const fin = (first & 0x80) !== 0;
    if ((first & 0x70) !== 0) {
      return { error: { code: CLOSE.protocolError, reason: 'RSV bits must be zero' } };
    }
    const opcode = first & 0x0f;
    const masked = (second & 0x80) !== 0;
    const requireMask = this.limits.requireMask !== false;
    // Every client frame must be masked. An unmasked frame is either a broken
    // client or a cross-protocol attack attempt; both get closed.
    if (requireMask && !masked) {
      return { error: { code: CLOSE.protocolError, reason: 'client frames must be masked' } };
    }
    // Symmetrically, a masked server frame is a protocol violation.
    if (!requireMask && masked) {
      return { error: { code: CLOSE.protocolError, reason: 'server frames must not be masked' } };
    }

    let length = second & 0x7f;
    let offset = 2;
    if (length === 126) {
      if (buffer.byteLength < offset + 2) return undefined;
      length = buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (buffer.byteLength < offset + 8) return undefined;
      const high = buffer.readUInt32BE(offset);
      const low = buffer.readUInt32BE(offset + 4);
      // Reject rather than silently truncate: a 64-bit length beyond 2^32 is
      // orders of magnitude past any limit we would accept anyway.
      if (high !== 0) return { error: { code: CLOSE.messageTooBig, reason: 'frame length too large' } };
      length = low;
      offset += 8;
    }
    if (length > this.limits.maxMessageBytes) {
      return { error: { code: CLOSE.messageTooBig, reason: 'frame exceeds limit' } };
    }

    const maskBytes = masked ? 4 : 0;
    if (buffer.byteLength < offset + maskBytes + length) return undefined;
    const mask = masked ? buffer.subarray(offset, offset + 4) : undefined;
    offset += maskBytes;
    const payload = Buffer.allocUnsafe(length);
    buffer.copy(payload, 0, offset, offset + length);
    if (mask !== undefined) {
      for (let i = 0; i < length; i += 1) {
        payload[i] = (payload[i] as number) ^ (mask[i % 4] as number);
      }
    }
    this.buffer = buffer.subarray(offset + length);
    return { frame: { fin, opcode, payload } };
  }
}

/** Build the client handshake request line and headers for `path`. */
export function clientHandshakeRequest(input: {
  path: string;
  host: string;
  key: string;
  protocols?: string[];
}): string {
  const lines = [
    `GET ${input.path} HTTP/1.1`,
    `Host: ${input.host}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${input.key}`,
    'Sec-WebSocket-Version: 13',
  ];
  if (input.protocols !== undefined && input.protocols.length > 0) {
    lines.push(`Sec-WebSocket-Protocol: ${input.protocols.join(', ')}`);
  }
  return `${lines.join('\r\n')}\r\n\r\n`;
}

export type ClientHandshakeResult =
  | { ok: true; protocol: string | undefined; rest: Buffer }
  | { ok: false; reason: string }
  | { pending: true };

/**
 * Parse a server handshake response.
 *
 * Verifies `Sec-WebSocket-Accept` rather than trusting the 101: that check is what
 * proves the peer actually understood the WebSocket handshake and is not an
 * unrelated service that happens to answer 101.
 */
export function readClientHandshake(buffer: Buffer, key: string): ClientHandshakeResult {
  const end = buffer.indexOf('\r\n\r\n');
  if (end === -1) {
    // A response header block this large is not a WebSocket server.
    if (buffer.byteLength > 16 * 1024) return { ok: false, reason: 'handshake response too large' };
    return { pending: true };
  }
  const head = buffer.subarray(0, end).toString('latin1');
  const [statusLine = '', ...headerLines] = head.split('\r\n');
  const status = Number(statusLine.split(' ')[1] ?? 0);
  if (status !== 101) return { ok: false, reason: `expected 101, got ${status || 'no status'}` };

  const headers = new Map<string, string>();
  for (const line of headerLines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    headers.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim());
  }
  if ((headers.get('upgrade') ?? '').toLowerCase() !== 'websocket') {
    return { ok: false, reason: 'missing upgrade: websocket' };
  }
  const accept = headers.get('sec-websocket-accept');
  if (accept !== computeAcceptKey(key)) return { ok: false, reason: 'bad Sec-WebSocket-Accept' };
  return { ok: true, protocol: headers.get('sec-websocket-protocol'), rest: buffer.subarray(end + 4) };
}

export interface ClientSocketOptions {
  maxMessageBytes?: number;
}

/**
 * A client-side WebSocket over an already-connected duplex.
 *
 * Exists so the bridge can consume its own `/m1/stream` endpoint over a loopback
 * carrier without adding a WebSocket dependency to a tree shared with an Expo app.
 * It masks what it sends, refuses masked frames from the server, and does not
 * initiate keepalive — the server side already does, and this end only has to answer.
 */
export class ClientWebSocket {
  private readonly decoder: FrameDecoder;
  private sinks: ServerSocketSinks;
  private closed = false;
  private closeSent = false;

  private readonly socket: Duplex;

  constructor(socket: Duplex, options: ClientSocketOptions = {}, sinks: ServerSocketSinks = {}) {
    this.socket = socket;
    this.decoder = new FrameDecoder({
      maxMessageBytes: options.maxMessageBytes ?? 1024 * 1024,
      requireMask: false,
    });
    this.sinks = { ...sinks };
    socket.on('data', (chunk: Buffer) => this.onData(chunk));
    socket.on('error', (error: Error) => {
      this.sinks.onError?.(error);
      this.teardown(CLOSE.internalError, 'socket error');
    });
    socket.on('close', () => this.teardown(CLOSE.goingAway, 'socket closed'));
  }

  get isOpen(): boolean {
    return !this.closed;
  }

  setSinks(sinks: ServerSocketSinks): void {
    this.sinks = { ...sinks };
    if (this.closed) sinks.onClose?.(CLOSE.goingAway, 'closed before sinks were attached');
  }

  /** Feed bytes that arrived in the same read as the handshake response. */
  pushInitial(chunk: Buffer): void {
    if (chunk.byteLength > 0) this.onData(chunk);
  }

  send(text: string): boolean {
    if (this.closed || this.closeSent) return false;
    try {
      this.socket.write(encodeFrame(OPCODE.text, Buffer.from(text, 'utf8'), true, true));
      return true;
    } catch (error) {
      this.sinks.onError?.(error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  sendJson(value: unknown): boolean {
    return this.send(JSON.stringify(value));
  }

  close(code: CloseCode | number = CLOSE.normal, reason = ''): void {
    if (this.closeSent) return;
    this.closeSent = true;
    try {
      this.socket.write(encodeCloseFrame(code, reason, true));
    } catch {
      // Ignore: closing anyway.
    }
    this.socket.end();
    this.teardown(code, reason);
  }

  destroy(): void {
    this.closeSent = true;
    this.socket.destroy();
    this.teardown(CLOSE.goingAway, 'destroyed');
  }

  private onData(chunk: Buffer): void {
    if (this.closed) return;
    const outcome = this.decoder.push(chunk);
    if (!outcome.ok) {
      this.close(outcome.code, outcome.reason);
      return;
    }
    for (const message of outcome.messages) {
      switch (message.kind) {
        case 'text':
          this.sinks.onMessage?.(message.data);
          break;
        case 'binary':
          this.sinks.onBinary?.(message.data);
          break;
        case 'ping':
          // Pong must echo the payload and, from a client, must be masked.
          if (!this.closeSent) this.socket.write(encodeFrame(OPCODE.pong, message.data, true, true));
          break;
        case 'pong':
          break;
        case 'close':
          this.close(message.code === CLOSE.normal ? CLOSE.normal : message.code, '');
          break;
      }
    }
  }

  private teardown(code: number, reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.sinks.onClose?.(code, reason);
  }
}

/**
 * UTF-8 validation by round-trip.
 *
 * `Buffer.toString('utf8')` replaces invalid sequences with U+FFFD instead of
 * failing, so comparing the re-encoded bytes is what actually detects bad input.
 * RFC 6455 requires closing with 1007 on invalid UTF-8, and autobahn tests it.
 */
function isValidUtf8(bytes: Buffer, decoded: string): boolean {
  return Buffer.byteLength(decoded, 'utf8') === bytes.byteLength && Buffer.from(decoded, 'utf8').equals(bytes);
}

export interface ServerSocketOptions {
  maxMessageBytes?: number;
  /** Interval for server-initiated pings. 0 disables. */
  keepAliveMs?: number;
  /** How long to wait for a pong before treating the peer as gone. */
  pongTimeoutMs?: number;
}

export interface ServerSocketSinks {
  onMessage?: (text: string) => void;
  onBinary?: (data: Buffer) => void;
  onClose?: (code: number, reason: string) => void;
  onError?: (error: Error) => void;
}

/**
 * A server-side WebSocket over an upgraded `Duplex`.
 *
 * Kept deliberately small: text send, close, and liveness. Binary is decoded but
 * our protocol is JSON text, so nothing here produces binary frames.
 */
export class ServerWebSocket {
  private readonly decoder: FrameDecoder;
  private sinks: ServerSocketSinks;
  private readonly keepAliveMs: number;
  private readonly pongTimeoutMs: number;
  private keepAliveTimer: NodeJS.Timeout | undefined;
  private pongTimer: NodeJS.Timeout | undefined;
  private closed = false;
  private closeSent = false;

  private readonly socket: Duplex;

  constructor(socket: Duplex, options: ServerSocketOptions = {}, sinks: ServerSocketSinks = {}) {
    this.socket = socket;
    this.decoder = new FrameDecoder({ maxMessageBytes: options.maxMessageBytes ?? 1024 * 1024 });
    this.sinks = { ...sinks };
    this.keepAliveMs = options.keepAliveMs ?? 30_000;
    this.pongTimeoutMs = options.pongTimeoutMs ?? 10_000;

    socket.on('data', (chunk: Buffer) => this.onData(chunk));
    socket.on('error', (error: Error) => {
      this.sinks.onError?.(error);
      this.teardown(CLOSE.internalError, 'socket error');
    });
    socket.on('close', () => this.teardown(CLOSE.goingAway, 'socket closed'));
    this.armKeepAlive();
  }

  get isOpen(): boolean {
    return !this.closed;
  }

  /**
   * Attach or replace sinks after construction.
   *
   * The server needs the socket object before it can build handlers that close
   * over it (the close handler must detach the subscriber it just created), and
   * data cannot be processed before then anyway: Node does not deliver `data`
   * until the current tick yields.
   *
   * If the socket already closed during setup, `onClose` fires immediately so a
   * subscriber is never left attached to a dead socket.
   */
  setSinks(sinks: ServerSocketSinks): void {
    this.sinks = { ...sinks };
    if (this.closed) sinks.onClose?.(CLOSE.goingAway, 'closed before sinks were attached');
  }

  /** Send a text frame. Returns false when the socket is no longer usable. */
  send(text: string): boolean {
    if (this.closed || this.closeSent) return false;
    try {
      this.socket.write(encodeFrame(OPCODE.text, Buffer.from(text, 'utf8')));
      return true;
    } catch (error) {
      this.sinks.onError?.(error instanceof Error ? error : new Error(String(error)));
      return false;
    }
  }

  sendJson(value: unknown): boolean {
    return this.send(JSON.stringify(value));
  }

  ping(): void {
    if (this.closed || this.closeSent) return;
    try {
      this.socket.write(encodeFrame(OPCODE.ping, randomBytes(4)));
    } catch {
      // A failed ping write means the socket is gone; the close handler follows.
    }
  }

  /** Send close and end the socket. Idempotent. */
  close(code: CloseCode | number = CLOSE.normal, reason = ''): void {
    if (this.closeSent) return;
    this.closeSent = true;
    try {
      this.socket.write(encodeCloseFrame(code, reason));
    } catch {
      // Ignore: we are closing anyway.
    }
    // Half-close rather than destroy, so the close frame is actually flushed.
    this.socket.end();
    this.teardown(code, reason);
  }

  /** Drop the connection without a close handshake (revocation, shutdown). */
  destroy(): void {
    this.closeSent = true;
    this.socket.destroy();
    this.teardown(CLOSE.goingAway, 'destroyed');
  }

  private onData(chunk: Buffer): void {
    if (this.closed) return;
    const outcome = this.decoder.push(chunk);
    if (!outcome.ok) {
      this.close(outcome.code, outcome.reason);
      return;
    }
    for (const message of outcome.messages) {
      switch (message.kind) {
        case 'text':
          this.sinks.onMessage?.(message.data);
          break;
        case 'binary':
          this.sinks.onBinary?.(message.data);
          break;
        case 'ping':
          // Echo the payload verbatim, per RFC 6455 §5.5.3.
          if (!this.closeSent) this.socket.write(encodeFrame(OPCODE.pong, message.data));
          break;
        case 'pong':
          this.clearPongTimer();
          break;
        case 'close':
          this.close(message.code === CLOSE.normal ? CLOSE.normal : message.code, '');
          break;
      }
    }
  }

  private armKeepAlive(): void {
    if (this.keepAliveMs <= 0) return;
    this.keepAliveTimer = setInterval(() => {
      if (this.closed) return;
      this.ping();
      if (this.pongTimer) return;
      this.pongTimer = setTimeout(() => {
        // No pong: a backgrounded phone on a dead radio looks exactly like this,
        // and holding the socket open would leak a subscriber slot.
        this.destroy();
      }, this.pongTimeoutMs);
      this.pongTimer.unref?.();
    }, this.keepAliveMs);
    this.keepAliveTimer.unref?.();
  }

  private clearPongTimer(): void {
    if (!this.pongTimer) return;
    clearTimeout(this.pongTimer);
    this.pongTimer = undefined;
  }

  private teardown(code: number, reason: string): void {
    if (this.closed) return;
    this.closed = true;
    if (this.keepAliveTimer) clearInterval(this.keepAliveTimer);
    this.clearPongTimer();
    this.sinks.onClose?.(code, reason);
  }
}

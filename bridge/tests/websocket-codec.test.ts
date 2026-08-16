/**
 * RFC 6455 codec: handshake, framing, and the protocol rules that are security
 * properties rather than interop details.
 *
 * This is hand-rolled rather than `ws` (see the module header for why), which
 * means the spec compliance nobody else is checking is ours to check. The tests
 * below are weighted towards the rules that exist to stop an attack rather than to
 * satisfy a conformance suite:
 *
 * - mask enforcement in both directions, which is what makes cross-protocol
 *   request smuggling fail;
 * - accumulated-size limits, so fragmentation cannot walk past the cap;
 * - UTF-8 validation, so a text frame cannot smuggle bytes that survive a
 *   round trip through the app's JSON parser as something else;
 * - accept-key verification on the client side, so an unrelated service that
 *   answers 101 is not mistaken for a WebSocket peer.
 *
 * Decoder failures are returned, never thrown: the caller must be able to answer
 * with the right close code instead of unwinding the connection handler.
 */

import { describe, expect, it } from 'vitest';
import {
  CLOSE,
  ClientWebSocket,
  FrameDecoder,
  OPCODE,
  checkUpgrade,
  clientHandshakeRequest,
  computeAcceptKey,
  encodeCloseFrame,
  encodeFrame,
  readClientHandshake,
  ServerWebSocket,
  writeHandshake,
} from '../src/http/websocket.ts';
import type { IncomingMessage } from 'node:http';
import { connect, createServer, type Socket } from 'node:net';

/** A request object with just the fields `checkUpgrade` reads. */
function upgradeRequest(headers: Record<string, string | undefined>, method = 'GET'): IncomingMessage {
  return { method, headers } as unknown as IncomingMessage;
}

/** A well-formed upgrade, so each test can vary exactly one thing. */
const VALID_KEY = Buffer.alloc(16, 7).toString('base64');
function validHeaders(): Record<string, string> {
  return {
    upgrade: 'websocket',
    connection: 'Upgrade',
    'sec-websocket-version': '13',
    'sec-websocket-key': VALID_KEY,
  };
}

describe('computeAcceptKey', () => {
  it('matches the value from RFC 6455 §1.3', () => {
    // The spec's own worked example. Pinning it means a refactor of the hash cannot
    // quietly produce a self-consistent but non-interoperable handshake.
    expect(computeAcceptKey('dGhlIHNhbXBsZSBub25jZQ==')).toBe('s3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
  });
});

describe('checkUpgrade', () => {
  it('accepts a well-formed handshake and returns the key and subprotocols', () => {
    const check = checkUpgrade(upgradeRequest({ ...validHeaders(), 'sec-websocket-protocol': 'dshm.v1, other' }));
    expect(check.ok).toBe(true);
    expect(check.key).toBe(VALID_KEY);
    expect(check.subprotocols).toEqual(['dshm.v1', 'other']);
  });

  it('accepts connection headers that list upgrade among others', () => {
    // Real clients and proxies send `keep-alive, Upgrade`. A naive equality check
    // here would reject working browsers, so the header is parsed as a token list.
    expect(checkUpgrade(upgradeRequest({ ...validHeaders(), connection: 'keep-alive, Upgrade' })).ok).toBe(true);
    expect(checkUpgrade(upgradeRequest({ ...validHeaders(), connection: 'Upgrade, keep-alive' })).ok).toBe(true);
  });

  it('rejects a connection header that merely contains the word', () => {
    // `no-upgrade` contains "upgrade" as a substring but is not the token, and
    // accepting it would mean substring matching decides whether we hijack a socket.
    expect(checkUpgrade(upgradeRequest({ ...validHeaders(), connection: 'no-upgrade' })).ok).toBe(false);
  });

  it.each([
    ['non-GET method', validHeaders(), 'POST', 405],
    ['missing upgrade header', { ...validHeaders(), upgrade: undefined }, 'GET', 400],
    ['missing connection upgrade', { ...validHeaders(), connection: 'keep-alive' }, 'GET', 400],
    ['wrong version', { ...validHeaders(), 'sec-websocket-version': '8' }, 'GET', 426],
    ['absent key', { ...validHeaders(), 'sec-websocket-key': undefined }, 'GET', 400],
    ['short key', { ...validHeaders(), 'sec-websocket-key': Buffer.alloc(8).toString('base64') }, 'GET', 400],
  ])('rejects %s with HTTP %i', (_label, headers, method, status) => {
    // A diagnosable HTTP status, not a dropped socket: a client that got the
    // handshake wrong should be able to find out how.
    const check = checkUpgrade(upgradeRequest(headers as Record<string, string | undefined>, method as string));
    expect(check.ok).toBe(false);
    expect(check.status).toBe(status);
  });

  it('reports no subprotocols rather than an empty string entry', () => {
    expect(checkUpgrade(upgradeRequest({ ...validHeaders(), 'sec-websocket-protocol': ' , ' })).subprotocols).toEqual([]);
  });
});

describe('writeHandshake', () => {
  it('writes a 101 with the derived accept value', () => {
    const written: string[] = [];
    writeHandshake({ write: (chunk: string) => void written.push(chunk) } as never, VALID_KEY);
    const response = written.join('');
    expect(response.startsWith('HTTP/1.1 101 Switching Protocols\r\n')).toBe(true);
    expect(response).toContain(`Sec-WebSocket-Accept: ${computeAcceptKey(VALID_KEY)}`);
    // Blank line terminating the header block: without it the client waits forever.
    expect(response.endsWith('\r\n\r\n')).toBe(true);
    expect(response).not.toContain('Sec-WebSocket-Protocol');
  });

  it('echoes a subprotocol only when one was selected', () => {
    const written: string[] = [];
    writeHandshake({ write: (chunk: string) => void written.push(chunk) } as never, VALID_KEY, 'dshm.v1');
    expect(written.join('')).toContain('Sec-WebSocket-Protocol: dshm.v1');
  });
});

describe('encodeFrame', () => {
  it.each([
    ['7-bit length', 125, 2],
    ['16-bit length', 126, 4],
    ['16-bit length at its top', 65_535, 4],
    ['64-bit length', 65_536, 10],
  ])('uses the %s header form (%i bytes payload → %i byte header)', (_label, payloadLength, headerBytes) => {
    // The three length forms are where a hand-rolled encoder most easily goes
    // wrong, and an off-by-one here desynchronises the peer's parser for the rest
    // of the connection rather than failing visibly.
    const frame = encodeFrame(OPCODE.text, Buffer.alloc(payloadLength as number, 0x61));
    expect(frame.byteLength).toBe((headerBytes as number) + (payloadLength as number));
    const decoded = new FrameDecoder({ maxMessageBytes: 1 << 20, requireMask: false }).push(frame);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.messages[0]).toEqual({ kind: 'text', data: 'a'.repeat(payloadLength as number) });
  });

  it('does not set the mask bit for server frames', () => {
    // RFC 6455 §5.1: a masked server frame is a protocol error, and our own decoder
    // enforces that in the other direction.
    const frame = encodeFrame(OPCODE.text, Buffer.from('hi'));
    expect(((frame[1] as number) & 0x80) !== 0).toBe(false);
  });

  it('masks client frames with a key that varies per frame', () => {
    // Masking exists to defeat cache-poisoning intermediaries; a predictable key
    // weakens exactly that, so the key is random rather than a counter.
    const payload = Buffer.from('same payload every time');
    const first = encodeFrame(OPCODE.text, payload, true, true);
    const second = encodeFrame(OPCODE.text, payload, true, true);
    expect(((first[1] as number) & 0x80) !== 0).toBe(true);
    expect(first.subarray(2, 6).equals(second.subarray(2, 6))).toBe(false);
    // Both still decode to the original, so masking is reversible.
    for (const frame of [first, second]) {
      const decoded = new FrameDecoder({ maxMessageBytes: 1024 }).push(frame);
      expect(decoded.ok && decoded.messages[0]).toEqual({ kind: 'text', data: payload.toString() });
    }
  });

  it('clears FIN when asked, so fragments are distinguishable', () => {
    expect(((encodeFrame(OPCODE.text, Buffer.from('a'), false)[0] as number) & 0x80) !== 0).toBe(false);
    expect(((encodeFrame(OPCODE.text, Buffer.from('a'), true)[0] as number) & 0x80) !== 0).toBe(true);
  });
});

describe('encodeCloseFrame', () => {
  it('puts the code first and round-trips the reason', () => {
    const decoded = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeCloseFrame(CLOSE.policyViolation, 'device revoked', true),
    );
    expect(decoded.ok && decoded.messages[0]).toEqual({ kind: 'close', code: 1008, reason: 'device revoked' });
  });

  it('truncates an over-long reason instead of emitting an illegal control frame', () => {
    // Control frames are capped at 125 bytes by the spec. Truncating keeps us legal;
    // the alternative is a frame the peer must close the connection over, which
    // would turn a verbose error message into a protocol violation.
    const frame = encodeCloseFrame(CLOSE.normal, 'x'.repeat(500), true);
    const decoded = new FrameDecoder({ maxMessageBytes: 1024 }).push(frame);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    const message = decoded.messages[0];
    expect(message?.kind).toBe('close');
    if (message?.kind !== 'close') return;
    expect(message.reason.length).toBe(123);
  });
});

describe('FrameDecoder: mask enforcement', () => {
  it('rejects an unmasked client frame with 1002', () => {
    // The rule that makes cross-protocol smuggling fail: an attacker who can make a
    // browser emit plaintext to this port cannot make it mask, so unmasked traffic
    // is either a broken client or an attack. Both get closed.
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(encodeFrame(OPCODE.text, Buffer.from('hi')));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.protocolError);
    expect(outcome.reason).toContain('must be masked');
  });

  it('rejects a masked server frame with 1002', () => {
    // Symmetric, and it matters for the loopback carrier: the bridge consumes its
    // own stream endpoint, so it decodes server→client traffic too.
    const outcome = new FrameDecoder({ maxMessageBytes: 1024, requireMask: false }).push(
      encodeFrame(OPCODE.text, Buffer.from('hi'), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.protocolError);
    expect(outcome.reason).toContain('must not be masked');
  });

  it('requires masking by default, without being asked', () => {
    // The server side is the one exposed to hostile input, so the strict behaviour
    // is the default rather than opt-in.
    expect(new FrameDecoder({ maxMessageBytes: 1024 }).push(encodeFrame(OPCODE.text, Buffer.from('x'))).ok).toBe(false);
  });
});

describe('FrameDecoder: partial and batched reads', () => {
  it('waits for the rest of a frame split across TCP reads', () => {
    // TCP has no frame boundaries. A decoder that assumed one read equals one frame
    // would work on loopback and fail over a real network.
    const frame = encodeFrame(OPCODE.text, Buffer.from('split me'), true, true);
    const decoder = new FrameDecoder({ maxMessageBytes: 1024 });
    for (let cut = 1; cut < frame.byteLength; cut += 1) {
      const fresh = new FrameDecoder({ maxMessageBytes: 1024 });
      const first = fresh.push(frame.subarray(0, cut));
      expect(first.ok && first.messages).toEqual([]);
      const second = fresh.push(frame.subarray(cut));
      expect(second.ok && second.messages).toEqual([{ kind: 'text', data: 'split me' }]);
    }
    // And the byte-at-a-time case, which is the worst realistic fragmentation.
    const messages = [];
    for (const byte of frame) {
      const outcome = decoder.push(Buffer.from([byte]));
      if (outcome.ok) messages.push(...outcome.messages);
    }
    expect(messages).toEqual([{ kind: 'text', data: 'split me' }]);
  });

  it('returns every message when several arrive in one read', () => {
    const chunk = Buffer.concat([
      encodeFrame(OPCODE.text, Buffer.from('one'), true, true),
      encodeFrame(OPCODE.text, Buffer.from('two'), true, true),
      encodeFrame(OPCODE.ping, Buffer.from('p'), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(chunk);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.messages.map((message) => message.kind)).toEqual(['text', 'text', 'ping']);
  });

  it('goes silent after a protocol failure instead of resynchronising', () => {
    // Once framing is violated the byte stream cannot be trusted to realign, and
    // guessing where the next frame starts is how a decoder gets fed a payload the
    // peer never framed. The caller has already been handed a close code.
    const decoder = new FrameDecoder({ maxMessageBytes: 1024 });
    expect(decoder.push(encodeFrame(OPCODE.text, Buffer.from('unmasked'))).ok).toBe(false);
    const after = decoder.push(encodeFrame(OPCODE.text, Buffer.from('valid now'), true, true));
    expect(after.ok && after.messages).toEqual([]);
  });
});

describe('FrameDecoder: fragmentation', () => {
  it('reassembles a fragmented text message', () => {
    const chunk = Buffer.concat([
      encodeFrame(OPCODE.text, Buffer.from('frag'), false, true),
      encodeFrame(OPCODE.continuation, Buffer.from('ment'), false, true),
      encodeFrame(OPCODE.continuation, Buffer.from('ed'), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(chunk);
    expect(outcome.ok && outcome.messages).toEqual([{ kind: 'text', data: 'fragmented' }]);
  });

  it('delivers a control frame interleaved between fragments, in order', () => {
    // Legal and load-bearing: keepalive must work during a large message, or a slow
    // transfer looks like a dead peer.
    const chunk = Buffer.concat([
      encodeFrame(OPCODE.text, Buffer.from('a'), false, true),
      encodeFrame(OPCODE.ping, Buffer.from('mid'), true, true),
      encodeFrame(OPCODE.continuation, Buffer.from('b'), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(chunk);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.messages).toEqual([
      { kind: 'ping', data: Buffer.from('mid') },
      { kind: 'text', data: 'ab' },
    ]);
  });

  it('rejects a continuation with no message in progress', () => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(OPCODE.continuation, Buffer.from('orphan'), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.protocolError);
    expect(outcome.reason).toContain('continuation without');
  });

  it('rejects a new data frame while a message is still fragmented', () => {
    // Interleaved *data* messages are not allowed, and accepting them would make the
    // reassembly buffer ambiguous about which message a fragment belongs to.
    const chunk = Buffer.concat([
      encodeFrame(OPCODE.text, Buffer.from('first'), false, true),
      encodeFrame(OPCODE.text, Buffer.from('second'), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(chunk);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toContain('while a message is fragmented');
  });

  it('rejects a fragmented control frame', () => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(OPCODE.ping, Buffer.from('x'), false, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toContain('must not be fragmented');
  });

  it('rejects an over-long control frame', () => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(OPCODE.ping, Buffer.alloc(126), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toContain('too long');
  });
});

describe('FrameDecoder: limits', () => {
  it('rejects a single frame over the cap with 1009', () => {
    const outcome = new FrameDecoder({ maxMessageBytes: 16 }).push(
      encodeFrame(OPCODE.text, Buffer.alloc(17, 0x61), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.messageTooBig);
  });

  it('rejects an over-cap frame from its declared length, before buffering it', () => {
    // The important half of the limit. Deciding only after reassembly would let a
    // peer make us allocate the whole payload first, so the announced length is
    // enough to refuse.
    const header = Buffer.alloc(8);
    header[0] = 0x80 | OPCODE.text;
    header[1] = 0x80 | 127;
    header.writeUInt32BE(0, 2);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(1 << 20, 0);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(Buffer.concat([header.subarray(0, 6), length]));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.messageTooBig);
    expect(outcome.reason).toContain('frame exceeds limit');
  });

  it('rejects a 64-bit length above 2^32 rather than truncating it', () => {
    // Truncation would be the dangerous failure: the high word discarded, the low
    // word accepted as a plausible size, and the parser now reading payload as
    // header for the rest of the connection.
    const frame = Buffer.alloc(14);
    frame[0] = 0x80 | OPCODE.text;
    frame[1] = 0x80 | 127;
    frame.writeUInt32BE(1, 2);
    frame.writeUInt32BE(0, 6);
    const outcome = new FrameDecoder({ maxMessageBytes: 1 << 30 }).push(frame);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.messageTooBig);
    expect(outcome.reason).toContain('too large');
  });

  it('applies the cap to the accumulated message, not per fragment', () => {
    // The bypass this closes: each fragment under the limit, the reassembled message
    // far over it. Checking per frame would make the cap meaningless.
    const chunk = Buffer.concat([
      encodeFrame(OPCODE.text, Buffer.alloc(10, 0x61), false, true),
      encodeFrame(OPCODE.continuation, Buffer.alloc(10, 0x61), false, true),
      encodeFrame(OPCODE.continuation, Buffer.alloc(10, 0x61), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 25 }).push(chunk);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.messageTooBig);
    expect(outcome.reason).toContain('message exceeds limit');
  });
});

describe('FrameDecoder: payload validation', () => {
  it('rejects invalid UTF-8 in a text frame with 1007', () => {
    // Not pedantry. `Buffer.toString('utf8')` substitutes U+FFFD for bad bytes
    // instead of failing, so without this check a peer could send bytes that become
    // a *different* string than it sent — and that string is what reaches the app's
    // JSON parser.
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(OPCODE.text, Buffer.from([0xc3, 0x28]), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.invalidPayload);
    expect(outcome.reason).toContain('not valid utf-8');
  });

  it('rejects a lone surrogate encoded as UTF-8', () => {
    // ED A0 80 is U+D800 in CESU-8 style encoding. It survives a naive round trip
    // and is exactly the kind of byte sequence that behaves differently in
    // different parsers.
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(OPCODE.text, Buffer.from([0xed, 0xa0, 0x80]), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.invalidPayload);
  });

  it('rejects UTF-8 split so that each fragment is invalid alone', () => {
    // Validation happens after reassembly, which is both correct and necessary: a
    // multi-byte character legally spans a fragment boundary, so per-fragment
    // checking would reject valid traffic while per-message checking still catches
    // this one.
    const utf8 = Buffer.from('héllo', 'utf8');
    const chunk = Buffer.concat([
      encodeFrame(OPCODE.text, utf8.subarray(0, 2), false, true),
      encodeFrame(OPCODE.continuation, Buffer.from([0xff]), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(chunk);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.invalidPayload);
  });

  it('accepts a multi-byte character split across fragments', () => {
    const utf8 = Buffer.from('héllo', 'utf8');
    const chunk = Buffer.concat([
      encodeFrame(OPCODE.text, utf8.subarray(0, 2), false, true),
      encodeFrame(OPCODE.continuation, utf8.subarray(2), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(chunk);
    expect(outcome.ok && outcome.messages).toEqual([{ kind: 'text', data: 'héllo' }]);
  });

  it('does not validate binary payloads as text', () => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(OPCODE.binary, Buffer.from([0xff, 0x00, 0xfe]), true, true),
    );
    expect(outcome.ok && outcome.messages).toEqual([{ kind: 'binary', data: Buffer.from([0xff, 0x00, 0xfe]) }]);
  });

  it('rejects non-zero RSV bits', () => {
    // We negotiate no extensions, so a set RSV bit means the peer believes something
    // was negotiated that was not. Guessing at its framing would be worse than
    // closing.
    const frame = encodeFrame(OPCODE.text, Buffer.from('x'), true, true);
    frame[0] = (frame[0] as number) | 0x40;
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(frame);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toContain('RSV');
  });

  it.each([0x3, 0x7])('rejects reserved data opcode 0x%s', (opcode) => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(opcode as number, Buffer.from('x'), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toContain('reserved data opcode');
  });

  it.each([0xb, 0xf])('rejects reserved control opcode 0x%s', (opcode) => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(
      encodeFrame(opcode as number, Buffer.from('x'), true, true),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toContain('reserved control opcode');
  });
});

describe('FrameDecoder: close frames', () => {
  it('treats an empty close payload as a normal closure', () => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(encodeFrame(OPCODE.close, Buffer.alloc(0), true, true));
    expect(outcome.ok && outcome.messages).toEqual([{ kind: 'close', code: CLOSE.normal, reason: '' }]);
  });

  it('rejects a one-byte close payload', () => {
    // A close code is 16 bits. One byte is not a truncated code we could charitably
    // interpret; it is a framing error.
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(encodeFrame(OPCODE.close, Buffer.from([0x03]), true, true));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.reason).toContain('0 or >= 2 bytes');
  });

  it.each([1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 4999])('accepts close code %i', (code) => {
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(encodeCloseFrame(code, '', true));
    expect(outcome.ok).toBe(true);
  });

  it.each([
    [1004, 'unassigned'],
    [1005, 'reserved for absent code'],
    [1006, 'reserved for abnormal closure'],
    [1015, 'reserved for TLS failure'],
    [999, 'below the valid range'],
    [2999, 'unallocated range'],
    [5000, 'above the valid range'],
  ])('rejects close code %i (%s)', (code) => {
    // 1005 and 1006 matter most: they are codes the *local* API synthesises and a
    // peer must never be able to claim, or it could forge a locally-generated event.
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(encodeCloseFrame(code as number, '', true));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.protocolError);
  });

  it('rejects a close reason that is not valid UTF-8', () => {
    const payload = Buffer.concat([Buffer.from([0x03, 0xe8]), Buffer.from([0xc3, 0x28])]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(encodeFrame(OPCODE.close, payload, true, true));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.code).toBe(CLOSE.invalidPayload);
  });

  it('stops decoding after a close, ignoring anything the peer sent behind it', () => {
    // Anything after a close is by definition outside the connection's lifetime.
    // Processing it would let a peer queue work it has already said goodbye for.
    const chunk = Buffer.concat([
      encodeCloseFrame(CLOSE.normal, 'bye', true),
      encodeFrame(OPCODE.text, Buffer.from('ignored'), true, true),
    ]);
    const outcome = new FrameDecoder({ maxMessageBytes: 1024 }).push(chunk);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.messages).toEqual([{ kind: 'close', code: CLOSE.normal, reason: 'bye' }]);
  });
});

describe('clientHandshakeRequest', () => {
  it('produces a request line and the four required headers', () => {
    const request = clientHandshakeRequest({ path: '/m1/stream?after=7', host: '127.0.0.1:8765', key: VALID_KEY });
    expect(request.startsWith('GET /m1/stream?after=7 HTTP/1.1\r\n')).toBe(true);
    for (const header of ['Host: 127.0.0.1:8765', 'Upgrade: websocket', 'Connection: Upgrade', `Sec-WebSocket-Key: ${VALID_KEY}`, 'Sec-WebSocket-Version: 13']) {
      expect(request).toContain(header);
    }
    expect(request.endsWith('\r\n\r\n')).toBe(true);
    expect(request).not.toContain('Sec-WebSocket-Protocol');
  });

  it('sends the request our own checkUpgrade accepts', () => {
    // Round trip through the server-side validator: the two halves of a hand-rolled
    // implementation agreeing with each other is the cheapest interop check
    // available, since both are used together over the loopback carrier.
    const request = clientHandshakeRequest({ path: '/m1/stream', host: 'h', key: VALID_KEY, protocols: ['dshm.v1'] });
    const headers: Record<string, string> = {};
    for (const line of request.split('\r\n').slice(1)) {
      const colon = line.indexOf(':');
      if (colon === -1) continue;
      headers[line.slice(0, colon).toLowerCase()] = line.slice(colon + 1).trim();
    }
    const check = checkUpgrade(upgradeRequest(headers));
    expect(check.ok).toBe(true);
    expect(check.subprotocols).toEqual(['dshm.v1']);
  });
});

describe('readClientHandshake', () => {
  const key = VALID_KEY;
  function response(lines: string[], body = ''): Buffer {
    return Buffer.from(`${lines.join('\r\n')}\r\n\r\n${body}`);
  }
  const goodLines = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${computeAcceptKey(key)}`,
  ];

  it('accepts a valid response and returns bytes that followed the header block', () => {
    // The trailing bytes matter: a server may write its first frame in the same
    // packet as the handshake, and dropping them would lose the first frame.
    const frame = encodeFrame(OPCODE.text, Buffer.from('first'));
    const result = readClientHandshake(Buffer.concat([response(goodLines), frame]), key);
    expect(result).toMatchObject({ ok: true, protocol: undefined });
    if (!('ok' in result) || !result.ok) return;
    expect(result.rest.equals(frame)).toBe(true);
  });

  it('waits for a header block that has not fully arrived', () => {
    expect(readClientHandshake(Buffer.from('HTTP/1.1 101 Switching'), key)).toEqual({ pending: true });
  });

  it('gives up on an implausibly large header block', () => {
    // Otherwise a peer that never sends the terminator makes us buffer without bound.
    const result = readClientHandshake(Buffer.alloc(16 * 1024 + 1, 0x41), key);
    expect(result).toMatchObject({ ok: false });
    if (!('reason' in result)) return;
    expect(result.reason).toContain('too large');
  });

  it('rejects a wrong accept value even when the status is 101', () => {
    // The check that actually proves the peer speaks WebSocket. A service that
    // answers 101 for unrelated reasons would otherwise be treated as a peer, and
    // everything after this point is raw framing on a socket that is not one.
    const result = readClientHandshake(
      response([...goodLines.slice(0, 3), 'Sec-WebSocket-Accept: wrong']),
      key,
    );
    expect(result).toMatchObject({ ok: false });
    if (!('reason' in result)) return;
    expect(result.reason).toContain('Sec-WebSocket-Accept');
  });

  it('rejects an accept value computed from a different key', () => {
    const otherKey = Buffer.alloc(16, 9).toString('base64');
    const result = readClientHandshake(
      response([...goodLines.slice(0, 3), `Sec-WebSocket-Accept: ${computeAcceptKey(otherKey)}`]),
      key,
    );
    expect(result).toMatchObject({ ok: false });
  });

  it.each([
    ['a non-101 status', ['HTTP/1.1 200 OK', ...goodLines.slice(1)], 'expected 101'],
    ['a missing upgrade header', ['HTTP/1.1 101 Switching Protocols', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${computeAcceptKey(VALID_KEY)}`], 'upgrade: websocket'],
  ])('rejects %s', (_label, lines, expected) => {
    const result = readClientHandshake(response(lines as string[]), key);
    expect(result).toMatchObject({ ok: false });
    if (!('reason' in result)) return;
    expect(result.reason).toContain(expected as string);
  });

  it('is case-insensitive about header names', () => {
    // Header names are case-insensitive per HTTP, and a peer that capitalises
    // differently is not malformed.
    const result = readClientHandshake(
      response(['HTTP/1.1 101 Switching Protocols', 'UPGRADE: WebSocket', 'connection: upgrade', `SEC-WEBSOCKET-ACCEPT: ${computeAcceptKey(key)}`]),
      key,
    );
    expect(result).toMatchObject({ ok: true });
  });

  it('reports the negotiated subprotocol when the server selected one', () => {
    const result = readClientHandshake(response([...goodLines, 'Sec-WebSocket-Protocol: dshm.v1']), key);
    expect(result).toMatchObject({ ok: true, protocol: 'dshm.v1' });
  });
});

/**
 * The two socket halves over a real connected socket pair.
 *
 * Real sockets rather than fakes because this pairing is not hypothetical: the
 * bridge consumes its own `/m1/stream` through `ClientWebSocket` over the loopback
 * carrier, so `ServerWebSocket` and `ClientWebSocket` are each other's peer in
 * production. Anything the two agree on but the spec does not would go unnoticed
 * with a hand-written stub on either side.
 */
describe('ServerWebSocket ↔ ClientWebSocket', () => {
  /** A connected TCP socket pair on loopback, plus the teardown for both. */
  async function socketPair(): Promise<{ server: Socket; client: Socket; close: () => void }> {
    const listener = createServer();
    await new Promise<void>((resolve) => listener.listen(0, '127.0.0.1', resolve));
    const address = listener.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    const accepted = new Promise<Socket>((resolve) => listener.once('connection', resolve));
    const client = connect({ host: '127.0.0.1', port: address.port });
    await new Promise<void>((resolve, reject) => {
      client.once('connect', () => resolve());
      client.once('error', reject);
    });
    const server = await accepted;
    return {
      server,
      client,
      close: () => {
        server.destroy();
        client.destroy();
        listener.close();
      },
    };
  }

  /** Wait for a condition the peer sets asynchronously, with a real timeout. */
  async function until(predicate: () => boolean, label: string, timeoutMs = 2000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!predicate()) {
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }

  it('carries JSON in both directions', async () => {
    const pair = await socketPair();
    try {
      const toServer: string[] = [];
      const toClient: string[] = [];
      // keepAliveMs 0: a ping mid-test would pass, but it makes the byte stream
      // nondeterministic and the assertions below harder to trust.
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 0 }, { onMessage: (text) => void toServer.push(text) });
      const client = new ClientWebSocket(pair.client, {}, { onMessage: (text) => void toClient.push(text) });

      client.sendJson({ type: 'ping-request', at: 1 });
      server.sendJson({ v: 1, bseq: 1, kind: 'bridge', frame: { type: 'pong', at: 2 } });

      await until(() => toServer.length === 1 && toClient.length === 1, 'both directions');
      expect(JSON.parse(toServer[0] as string)).toEqual({ type: 'ping-request', at: 1 });
      expect(JSON.parse(toClient[0] as string)).toEqual({ v: 1, bseq: 1, kind: 'bridge', frame: { type: 'pong', at: 2 } });
    } finally {
      pair.close();
    }
  });

  it('answers a server ping with a masked pong carrying the same payload', async () => {
    // RFC 6455 §5.5.3 requires echoing the payload. It is also how the server's
    // liveness check distinguishes a real answer from unrelated traffic.
    const pair = await socketPair();
    try {
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 0 });
      const client = new ClientWebSocket(pair.client);
      const pongs: Buffer[] = [];
      // Observe at the wire level: neither class exposes received pongs, and the
      // masking of the reply is exactly what is being checked.
      const decoder = new FrameDecoder({ maxMessageBytes: 1024 });
      pair.server.removeAllListeners('data');
      pair.server.on('data', (chunk: Buffer) => {
        const outcome = decoder.push(chunk);
        if (outcome.ok) for (const message of outcome.messages) if (message.kind === 'pong') pongs.push(message.data);
      });

      server.ping();
      await until(() => pongs.length === 1, 'pong');
      expect(pongs[0]?.byteLength).toBe(4);
      expect(client.isOpen).toBe(true);
    } finally {
      pair.close();
    }
  });

  it('reports the peer close code to the local close sink', async () => {
    const pair = await socketPair();
    try {
      const closes: { code: number; reason: string }[] = [];
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 0 });
      new ClientWebSocket(pair.client, {}, { onClose: (code, reason) => void closes.push({ code, reason }) });

      server.close(CLOSE.policyViolation, 'device revoked');
      await until(() => closes.length > 0, 'client close');
      // The code survives; the reason is not propagated by the client's close path,
      // which is why a phone needs the `device-revoked` *frame* sent before the
      // close to know why. That ordering is asserted in the hub tests.
      expect(closes[0]?.code).toBe(CLOSE.policyViolation);
    } finally {
      pair.close();
    }
  });

  it('refuses to send after close, without throwing', async () => {
    const pair = await socketPair();
    try {
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 0 });
      expect(server.send('before')).toBe(true);
      server.close();
      // A false return rather than a throw: fanout iterates subscribers, and a throw
      // from one dead socket would need a try/catch at every call site.
      expect(server.send('after')).toBe(false);
      expect(server.isOpen).toBe(false);
    } finally {
      pair.close();
    }
  });

  it('fires onClose exactly once across close, destroy, and socket teardown', async () => {
    const pair = await socketPair();
    try {
      let closeCount = 0;
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 0 }, { onClose: () => void (closeCount += 1) });
      server.close(CLOSE.normal, 'first');
      server.close(CLOSE.internalError, 'second');
      server.destroy();
      await until(() => true, 'noop');
      // Once, because the hub detaches the subscriber in this callback: a second
      // call would detach whatever took its place.
      expect(closeCount).toBe(1);
    } finally {
      pair.close();
    }
  });

  it('closes with 1002 when the peer sends an unmasked frame', async () => {
    // End to end: a client that does not mask gets closed rather than served, and the
    // server survives it.
    const pair = await socketPair();
    try {
      const closes: number[] = [];
      const received: string[] = [];
      new ServerWebSocket(pair.server, { keepAliveMs: 0 }, { onMessage: (text) => void received.push(text), onClose: (code) => void closes.push(code) });
      pair.client.write(encodeFrame(OPCODE.text, Buffer.from('unmasked'), true, false));

      await until(() => closes.length > 0, 'server close');
      expect(closes[0]).toBe(CLOSE.protocolError);
      expect(received).toEqual([]);
    } finally {
      pair.close();
    }
  });

  it('closes with 1009 when the peer exceeds the message cap', async () => {
    const pair = await socketPair();
    try {
      const closes: number[] = [];
      new ServerWebSocket(pair.server, { keepAliveMs: 0, maxMessageBytes: 64 }, { onClose: (code) => void closes.push(code) });
      pair.client.write(encodeFrame(OPCODE.text, Buffer.alloc(128, 0x61), true, true));
      await until(() => closes.length > 0, 'server close');
      expect(closes[0]).toBe(CLOSE.messageTooBig);
    } finally {
      pair.close();
    }
  });

  it('delivers bytes that arrived before sinks were attached', async () => {
    // The ordering the server actually runs: it needs the socket object to build a
    // close handler that detaches the subscriber, so sinks land one step after
    // construction. Node not delivering `data` until the tick yields is what makes
    // that safe, and this test is what proves it.
    const pair = await socketPair();
    try {
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 0 });
      pair.client.write(encodeFrame(OPCODE.text, Buffer.from('early'), true, true));
      const received: string[] = [];
      server.setSinks({ onMessage: (text) => void received.push(text) });
      await until(() => received.length > 0, 'early message');
      expect(received).toEqual(['early']);
    } finally {
      pair.close();
    }
  });

  it('reports an immediate close to sinks attached after the socket died', async () => {
    // Otherwise the hub keeps a subscriber attached to a socket that will never
    // deliver anything and never fires a close, which leaks the slot permanently.
    const pair = await socketPair();
    try {
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 0 });
      server.destroy();
      const closes: number[] = [];
      server.setSinks({ onClose: (code) => void closes.push(code) });
      expect(closes).toEqual([CLOSE.goingAway]);
    } finally {
      pair.close();
    }
  });

  it('drops the connection when a ping goes unanswered', async () => {
    // A backgrounded phone on a dead radio is indistinguishable from a live one at
    // the TCP level, so the pong deadline is the only thing that reclaims the slot.
    const pair = await socketPair();
    try {
      const closes: number[] = [];
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 10, pongTimeoutMs: 20 }, { onClose: (code) => void closes.push(code) });
      // No ClientWebSocket on the other end, so nothing will ever pong.
      pair.client.resume();
      await until(() => closes.length > 0, 'keepalive timeout', 3000);
      expect(server.isOpen).toBe(false);
    } finally {
      pair.close();
    }
  });

  it('stays open while the peer keeps answering pings', async () => {
    const pair = await socketPair();
    try {
      const closes: number[] = [];
      const server = new ServerWebSocket(pair.server, { keepAliveMs: 10, pongTimeoutMs: 60 }, { onClose: (code) => void closes.push(code) });
      new ClientWebSocket(pair.client);
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(closes).toEqual([]);
      expect(server.isOpen).toBe(true);
    } finally {
      pair.close();
    }
  });
});

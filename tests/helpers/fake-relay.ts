/**
 * A scripted relay and bridge peer, for driving `RelayClient` in unit tests.
 *
 * This is not a relay implementation — `bridge/tests` has the real one, and the
 * cross-tree integration test uses it. This exists to reach the states a real relay
 * makes hard to produce on demand: an error code at a chosen moment, a peer that
 * changes its ephemeral mid-handshake, a signature from the wrong key, a replayed
 * record. Those are the branches worth testing, and they are all adversarial.
 *
 * The socket is synchronous by design. `RelayClient` never awaits anything, so a
 * synchronous double keeps the tests free of arbitrary waits and makes the frame
 * ordering assertions exact.
 */

import {
  SEAL_KEY_BYTES,
  SealedChannel,
  beginHandshake,
  beginPairingHandshake,
  completeHandshake,
  handshakeTranscript,
  newRoutingId,
  signHandshake,
  type SealHandshake,
} from '../../src/m1/seal';
import { hkdfSha256, verifySignatureB64, x25519SharedSecret } from '../../src/m1/crypto';
import { fromBase64Url, utf8 } from '../../src/m1/bytes';
import type { WebSocketLike } from '../../src/m1/relay';
import type { DeviceIdentity } from '../../src/m1/crypto';

type Listeners = {
  open: (() => void)[];
  message: ((event: { data: unknown }) => void)[];
  close: (() => void)[];
  error: ((event: unknown) => void)[];
};

/** A `WebSocketLike` whose peer is the test body. */
export class FakeSocket implements WebSocketLike {
  /** Every frame the client sent, parsed. */
  readonly sent: Record<string, unknown>[] = [];
  readonly url: string;
  readonly subprotocols: readonly string[];
  closed = false;
  closeCode: number | undefined;
  /** Set to throw from `send`, to exercise the transport-failure path. */
  failSend = false;

  private readonly listeners: Listeners = { open: [], message: [], close: [], error: [] };

  constructor(url: string, subprotocols: readonly string[]) {
    this.url = url;
    this.subprotocols = subprotocols;
  }

  send(data: string): void {
    if (this.failSend) throw new Error('socket is not writable');
    this.sent.push(JSON.parse(data) as Record<string, unknown>);
  }

  close(code?: number): void {
    this.closed = true;
    this.closeCode = code;
  }

  addEventListener(type: 'open' | 'message' | 'close' | 'error', listener: (event: never) => void): void {
    (this.listeners[type] as unknown[]).push(listener);
  }

  /** Drive the client: the socket opened. */
  open(): void {
    for (const listener of [...this.listeners.open]) listener();
  }

  /** Drive the client: a frame arrived. Objects are JSON-encoded, strings sent raw. */
  deliver(message: unknown): void {
    const data = typeof message === 'string' ? message : JSON.stringify(message);
    for (const listener of [...this.listeners.message]) listener({ data });
  }

  /** Drive the client: a non-text frame arrived. */
  deliverRaw(data: unknown): void {
    for (const listener of [...this.listeners.message]) listener({ data });
  }

  fireClose(): void {
    for (const listener of [...this.listeners.close]) listener();
  }

  fireError(): void {
    for (const listener of [...this.listeners.error]) listener(new Error('socket error'));
  }

  /** The last frame of a given type, which is what most assertions want. */
  last(type: string): Record<string, unknown> | undefined {
    return [...this.sent].reverse().find((frame) => frame.type === type);
  }

  ofType(type: string): Record<string, unknown>[] {
    return this.sent.filter((frame) => frame.type === type);
  }
}

/**
 * The bridge's side of a seal handshake.
 *
 * Uses the same `src/m1/seal` module as the client, in the `responder` role. That is
 * enough for the client's state machine, and the cross-implementation check — phone
 * core against the bridge's independent seal implementation — is done by the
 * integration test, which is the right place for it.
 */
export class FakeBridgePeer {
  readonly identity: DeviceIdentity;
  readonly sessionId: string;
  private handshake: SealHandshake | undefined;
  private channel: SealedChannel | undefined;
  /** Set to sign with this key instead, to simulate a relay in the middle. */
  signWith: Uint8Array | undefined;

  constructor(input: {
    identity: DeviceIdentity;
    sessionId: string;
    /** Steady state: the phone's real public key. Pairing: the token binder. */
    phoneStatic: string;
    pairing?: boolean;
  }) {
    this.identity = input.identity;
    this.sessionId = input.sessionId;
    this.handshake = input.pairing === true
      ? beginPairingHandshake({
          role: 'responder',
          sessionId: input.sessionId,
          bridgeStaticPublicKey: input.identity.publicKey,
          tokenBinder: input.phoneStatic,
        })
      : beginHandshake({
          role: 'responder',
          sessionId: input.sessionId,
          ownStaticPublicKey: input.identity.publicKey,
          peerStaticPublicKey: input.phoneStatic,
        });
  }

  get ephemeral(): string {
    const handshake = this.handshake;
    if (handshake === undefined) throw new Error('handshake already completed');
    return handshake.message.eph;
  }

  /** Round one: our ephemeral, unsigned. */
  offer(): { v: 1; type: 'relay/handshake'; hs: { v: 1; eph: string; sig: string } } {
    return { v: 1, type: 'relay/handshake', hs: { v: 1, eph: this.ephemeral, sig: '' } };
  }

  /** Round two: our ephemeral plus a signature over the transcript. */
  answer(phoneEphemeral: string): { v: 1; type: 'relay/handshake'; hs: { v: 1; eph: string; sig: string } } {
    const handshake = this.handshake;
    if (handshake === undefined) throw new Error('handshake already completed');
    const key = this.signWith ?? this.identity.privateKey;
    return {
      v: 1,
      type: 'relay/handshake',
      hs: { v: 1, eph: handshake.message.eph, sig: signHandshake(handshake, phoneEphemeral, key) },
    };
  }

  /** Derive our own channel, so records can be sealed in both directions. */
  complete(phoneEphemeral: string, phoneSignature: string): void {
    const handshake = this.handshake;
    if (handshake === undefined) throw new Error('handshake already completed');
    const result = completeHandshake(handshake, { v: 1, eph: phoneEphemeral, sig: phoneSignature });
    if (!result.ok) throw new Error(`bridge could not complete the handshake: ${result.reason}`);
    this.channel = result.channel;
    this.handshake = undefined;
  }

  /**
   * Complete the pairing variant, deferring the phone's proof.
   *
   * The bridge cannot verify the phone here: the transcript's initiator slot holds
   * the token binder, and the signature was made with a device key the bridge has
   * not seen yet. So it derives the channel and retains the signature until the
   * claim reveals the key. `completeHandshake` always verifies, by design, so the
   * derivation is done from the same exported primitives instead.
   *
   * `verifyAs` is the deferred check itself: pass the device public key the claim
   * would carry, and this asserts the retained signature binds the channel to it.
   * That is the property the pairing handshake exists to provide.
   */
  completeDeferred(phoneEphemeral: string, options: { signature?: string; verifyAs?: string } = {}): void {
    const handshake = this.handshake;
    if (handshake === undefined) throw new Error('handshake already completed');
    const transcriptBytes = handshakeTranscript(handshake, phoneEphemeral);

    if (options.signature !== undefined && options.verifyAs !== undefined) {
      if (!verifySignatureB64(options.verifyAs, transcriptBytes, options.signature)) {
        throw new Error('deferred peer proof did not verify against the claimed device key');
      }
    }

    const shared = x25519SharedSecret(handshake.ephemeralPrivate, fromBase64Url(phoneEphemeral) ?? new Uint8Array());
    if (shared === undefined) throw new Error('bridge key agreement failed');
    // Responder orientation: i2r is what it receives, r2i what it sends.
    this.channel = new SealedChannel({
      sendKey: hkdfSha256(shared, transcriptBytes, utf8('dshm relay r2i'), SEAL_KEY_BYTES),
      receiveKey: hkdfSha256(shared, transcriptBytes, utf8('dshm relay i2r'), SEAL_KEY_BYTES),
      sessionId: handshake.sessionId,
    });
    this.handshake = undefined;
  }

  /** Wrap a value as a `relay/data` frame the client will accept. */
  data(value: unknown): { v: 1; type: 'relay/data'; record: unknown } {
    const channel = this.channel;
    if (channel === undefined) throw new Error('no sealed channel yet');
    return { v: 1, type: 'relay/data', record: channel.sealJson(value) };
  }

  /** Open a record the client sent. */
  open(record: unknown): unknown {
    const channel = this.channel;
    if (channel === undefined) throw new Error('no sealed channel yet');
    const result = channel.openJson(record);
    if (!result.ok) throw new Error(`bridge could not open a record: ${result.reason}`);
    return result.value;
  }
}

/** A routing id pair, for tests that do not care about the values. */
export function routingPair(): { phone: string; bridge: string } {
  return { phone: newRoutingId(), bridge: newRoutingId() };
}

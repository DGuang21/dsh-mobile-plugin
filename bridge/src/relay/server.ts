/**
 * [OUR DESIGN] Relay server.
 *
 * A dumb, untrusted forwarder. It pairs two routing ids and copies opaque sealed
 * records between them. Deliberate non-features, each of which would make it a
 * more attractive target:
 *   - It never decrypts. It holds no keys and could not decrypt if it wanted to.
 *   - It stores nothing. A record not deliverable right now is dropped, and the
 *     bridge's own bseq ring is what provides durability.
 *   - It has no account system, no database, and no admin surface.
 *
 * Threat posture: assume the relay operator is hostile and the relay host is
 * compromised. What leaks in that case is metadata — which routing ids are online,
 * frame sizes, and timing. That is why routing ids are opaque randoms that cannot
 * be linked back to a device, and why the sealed layer authenticates both statics.
 *
 * Marked `[NOT INTEGRATION-TESTED]`: exercised end-to-end against the in-process
 * connector and a real WebSocket client in tests, but never deployed behind a real
 * TLS terminator or against a phone.
 */

import { createServer, type Server } from 'node:http';
import type { Duplex } from 'node:stream';
import { CLOSE, ServerWebSocket, checkUpgrade, writeHandshake } from '../http/websocket.ts';
import { parsePath } from '../http/router.ts';
import {
  RELAY_SUBPROTOCOL,
  type RelayErrorCode,
  type RelayRegisterMode,
  type RelayRole,
  type RelayServerMessage,
  parseClientMessage,
} from './protocol.ts';

export const RELAY_PATH = '/relay/v1';

interface Peer {
  socket: ServerWebSocket;
  role: RelayRole;
  routingId: string;
  mode: RelayRegisterMode;
  /** Undefined for a rendezvous holder, which names no peer. */
  peerRoutingId: string | undefined;
  connectedAt: number;
  framesIn: number;
  framesOut: number;
  bytesIn: number;
  /** Fixed-window frame budget. */
  windowStart: number;
  windowFrames: number;
  /**
   * Routing ids that have sent us a frame while we are a rendezvous holder.
   *
   * Bounded by `maxRendezvousClaimants`: without a bound, anyone who knows a
   * rendezvous id could grow this set until the relay ran out of memory.
   */
  claimants: Set<string>;
}

export interface RelayServerOptions {
  /** Max sealed records per peer per minute. */
  frameRatePerMinute?: number;
  /** Max size of one control message, including the sealed record. */
  maxMessageBytes?: number;
  /** Max simultaneous registered peers. Bounds memory on a public endpoint. */
  maxPeers?: number;
  /**
   * Max distinct senders one rendezvous holder will track at a time.
   *
   * Small on purpose: a pairing window serves one phone. A few slots absorb a
   * retry without letting the set become an amplifier.
   */
  maxRendezvousClaimants?: number;
  now?: () => number;
  /** Emit one line per lifecycle event. Metadata only, never record contents. */
  verbose?: boolean;
}

export class RelayServer {
  private readonly server: Server;
  private readonly peers = new Map<string, Peer>();
  /** Sockets that connected but have not registered yet. */
  private readonly pending = new Set<ServerWebSocket>();
  private readonly frameRatePerMinute: number;
  private readonly maxMessageBytes: number;
  private readonly maxPeers: number;
  private readonly maxRendezvousClaimants: number;
  private readonly now: () => number;
  private readonly verbose: boolean;
  private totalFramesForwarded = 0;
  private totalFramesDropped = 0;

  constructor(options: RelayServerOptions = {}) {
    this.frameRatePerMinute = options.frameRatePerMinute ?? 3_000;
    this.maxMessageBytes = options.maxMessageBytes ?? 2 * 1024 * 1024;
    this.maxPeers = options.maxPeers ?? 1_000;
    this.maxRendezvousClaimants = options.maxRendezvousClaimants ?? 4;
    this.now = options.now ?? Date.now;
    this.verbose = options.verbose ?? false;

    this.server = createServer((request, response) => {
      // A relay has exactly one job. Health is the only plain HTTP route, and it
      // reveals nothing but liveness.
      const { path } = parsePath(request);
      if (path === '/relay/health' && (request.method ?? 'GET') === 'GET') {
        const body = JSON.stringify({ ok: true, protocol: 1, peers: this.peers.size });
        response.writeHead(200, { 'content-type': 'application/json', 'content-length': String(body.length) });
        response.end(body);
        return;
      }
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end('{"ok":false}');
    });

    this.server.on('upgrade', (request, socket, head) => {
      void head;
      this.handleUpgrade(request as Parameters<typeof checkUpgrade>[0], socket as Duplex);
    });
  }

  listen(port: number, host = '0.0.0.0'): Promise<number> {
    return new Promise((resolve) => {
      this.server.listen(port, host, () => {
        const address = this.server.address();
        resolve(typeof address === 'object' && address !== null ? address.port : port);
      });
    });
  }

  async close(): Promise<void> {
    for (const peer of [...this.peers.values()]) peer.socket.close(CLOSE.goingAway, 'relay shutting down');
    for (const socket of [...this.pending]) socket.close(CLOSE.goingAway, 'relay shutting down');
    this.peers.clear();
    this.pending.clear();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  stats(): {
    peers: number;
    pending: number;
    tunnels: number;
    framesForwarded: number;
    framesDropped: number;
  } {
    let tunnels = 0;
    for (const peer of this.peers.values()) {
      // Only mutually-naming pairs are tunnels. A rendezvous holder has no
      // counterpart and must not be counted as half of one.
      if (peer.peerRoutingId === undefined) continue;
      const counterpart = this.peers.get(peer.peerRoutingId);
      if (counterpart !== undefined && counterpart.peerRoutingId === peer.routingId) tunnels += 1;
    }
    return {
      peers: this.peers.size,
      pending: this.pending.size,
      // Each tunnel is counted from both ends.
      tunnels: tunnels / 2,
      framesForwarded: this.totalFramesForwarded,
      framesDropped: this.totalFramesDropped,
    };
  }

  private handleUpgrade(request: Parameters<typeof checkUpgrade>[0], socket: Duplex): void {
    const { path } = parsePath(request);
    if (path !== RELAY_PATH) return this.refuse(socket, 404, 'not found');

    const check = checkUpgrade(request);
    if (!check.ok || check.key === undefined) {
      return this.refuse(socket, check.status ?? 400, check.reason ?? 'bad upgrade');
    }
    if (!(check.subprotocols ?? []).includes(RELAY_SUBPROTOCOL)) {
      return this.refuse(socket, 400, 'missing relay subprotocol');
    }
    // Bound before accepting, so a flood cannot allocate first and be counted
    // afterwards.
    if (this.peers.size + this.pending.size >= this.maxPeers) {
      return this.refuse(socket, 503, 'relay at capacity');
    }

    writeHandshake(socket, check.key, RELAY_SUBPROTOCOL);
    const ws = new ServerWebSocket(socket, { maxMessageBytes: this.maxMessageBytes }, {});
    this.pending.add(ws);

    let peer: Peer | undefined;

    ws.setSinks({
      onMessage: (text) => {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          this.send(ws, { v: 1, type: 'relay/error', code: 'bad-message', message: 'not JSON' });
          return;
        }
        const result = parseClientMessage(parsed);
        if (!result.ok) {
          this.send(ws, { v: 1, type: 'relay/error', code: result.code, message: result.reason });
          return;
        }
        const message = result.message;

        if (message.type === 'relay/register') {
          if (peer !== undefined) {
            this.send(ws, { v: 1, type: 'relay/error', code: 'bad-message', message: 'already registered' });
            return;
          }
          if (this.peers.has(message.routingId)) {
            // Do NOT evict the incumbent: that would be a trivial way to
            // disconnect a bridge by guessing (or observing) its routing id.
            this.send(ws, { v: 1, type: 'relay/error', code: 'routing-id-taken', message: 'routing id in use' });
            ws.close(CLOSE.policyViolation, 'routing id in use');
            return;
          }
          const at = this.now();
          peer = {
            socket: ws,
            role: message.role,
            routingId: message.routingId,
            mode: message.mode,
            peerRoutingId: message.peerRoutingId,
            connectedAt: at,
            framesIn: 0,
            framesOut: 0,
            bytesIn: 0,
            windowStart: at,
            windowFrames: 0,
            claimants: new Set<string>(),
          };
          this.peers.set(message.routingId, peer);
          this.pending.delete(ws);
          // A rendezvous has no counterpart to look up: any sender may reach it.
          const counterpart =
            message.peerRoutingId === undefined ? undefined : this.peers.get(message.peerRoutingId);
          this.send(ws, {
            v: 1,
            type: 'relay/registered',
            routingId: message.routingId,
            peerPresent: counterpart !== undefined,
          });
          // Tell the counterpart too, so a bridge learns a phone arrived without
          // polling. Mutual naming is required, so a rendezvous never triggers it.
          if (counterpart !== undefined && counterpart.peerRoutingId === message.routingId) {
            this.send(counterpart.socket, { v: 1, type: 'relay/peer-online' });
            this.send(ws, { v: 1, type: 'relay/peer-online' });
          }
          this.log(`register ${message.role} ${message.routingId} mode=${message.mode} peer=${counterpart !== undefined}`);
          return;
        }

        if (message.type === 'relay/ping') {
          this.send(ws, { v: 1, type: 'relay/pong', at: message.at });
          return;
        }

        if (message.type === 'relay/bye') {
          ws.close(CLOSE.normal, 'bye');
          return;
        }

        // relay/data and relay/handshake: both are opaque payloads for the peer,
        // and both take the identical quota and pairing path.
        if (peer === undefined) {
          this.send(ws, { v: 1, type: 'relay/error', code: 'not-registered', message: 'register first' });
          return;
        }
        if (!this.withinQuota(peer)) {
          this.totalFramesDropped += 1;
          this.send(ws, { v: 1, type: 'relay/error', code: 'quota-exceeded', message: 'frame rate exceeded' });
          return;
        }
        peer.framesIn += 1;
        peer.bytesIn += text.length;

        const resolved = this.resolveTarget(peer, message.to);
        if (!resolved.ok) {
          this.totalFramesDropped += 1;
          this.send(ws, { v: 1, type: 'relay/error', code: resolved.code, message: resolved.reason });
          return;
        }
        const target = resolved.target;
        // A rendezvous holder cannot know who is calling, so inbound frames are
        // tagged with the sender. Peer-mode traffic is left untagged: the receiver
        // already knows its one counterpart, and echoing an id it did not ask for
        // would be a needless second source of truth.
        const from = target.mode === 'rendezvous' ? peer.routingId : undefined;
        if (target.mode === 'rendezvous') {
          // Remember the sender so the holder's reply can be routed back. Bounded,
          // and checked before insertion so the cap cannot be walked past.
          if (!target.claimants.has(peer.routingId)) {
            if (target.claimants.size >= this.maxRendezvousClaimants) {
              this.totalFramesDropped += 1;
              this.send(ws, { v: 1, type: 'relay/error', code: 'rendezvous-busy', message: 'rendezvous is busy' });
              return;
            }
            target.claimants.add(peer.routingId);
          }
        }
        // Forwarded verbatim. The relay has no opinion about the contents and no
        // ability to form one.
        this.send(
          target.socket,
          message.type === 'relay/data'
            ? { v: 1, type: 'relay/data', record: message.record, ...(from === undefined ? {} : { from }) }
            : { v: 1, type: 'relay/handshake', hs: message.hs, ...(from === undefined ? {} : { from }) },
        );
        target.framesOut += 1;
        this.totalFramesForwarded += 1;
      },
      onClose: () => {
        this.pending.delete(ws);
        if (peer === undefined) return;
        // Only remove the entry if it is still ours: a reconnect under the same
        // routing id must not be evicted by the old socket's close handler.
        if (this.peers.get(peer.routingId) === peer) this.peers.delete(peer.routingId);
        const counterpart = peer.peerRoutingId === undefined ? undefined : this.peers.get(peer.peerRoutingId);
        if (counterpart !== undefined && counterpart.peerRoutingId === peer.routingId) {
          this.send(counterpart.socket, { v: 1, type: 'relay/peer-offline' });
        }
        // Tell any rendezvous holder this peer was talking to that it went away,
        // so a bridge can drop the half-built pairing channel instead of waiting.
        for (const other of this.peers.values()) {
          if (other.mode !== 'rendezvous') continue;
          if (!other.claimants.delete(peer.routingId)) continue;
          this.send(other.socket, { v: 1, type: 'relay/peer-offline' });
        }
        // And the mirror: a rendezvous holder going away must tell its claimants.
        // The mutual-naming check above cannot do it — a holder names nobody — so
        // without this a phone mid-pairing would sit waiting for a reply that can
        // never arrive, until the pairing token expired.
        if (peer.mode === 'rendezvous') {
          for (const claimantId of peer.claimants) {
            const claimant = this.peers.get(claimantId);
            if (claimant?.peerRoutingId !== peer.routingId) continue;
            this.send(claimant.socket, { v: 1, type: 'relay/peer-offline' });
          }
        }
        this.log(`close ${peer.role} ${peer.routingId} in=${peer.framesIn} out=${peer.framesOut}`);
      },
    });
  }

  /**
   * Decide where a frame goes.
   *
   * The mutual-naming rule is the anti-injection invariant for peer mode and is
   * kept exactly as strict as before. Rendezvous mode relaxes it in one direction
   * only:
   *   - anyone → rendezvous is allowed, because a phone that has never paired has
   *     no id the holder could have named in advance;
   *   - rendezvous → someone requires an explicit `to` naming a sender that has
   *     already reached us, so a holder cannot be used to spray frames at
   *     arbitrary routing ids.
   */
  private resolveTarget(
    peer: Peer,
    to: string | undefined,
  ): { ok: true; target: Peer } | { ok: false; code: RelayErrorCode; reason: string } {
    if (peer.mode === 'rendezvous') {
      if (to === undefined) {
        return { ok: false, code: 'bad-message', reason: 'a rendezvous holder must name a target with to' };
      }
      // Only a peer that actually spoke to us first is addressable.
      if (!peer.claimants.has(to)) {
        return { ok: false, code: 'peer-offline', reason: 'no such claimant' };
      }
      const target = this.peers.get(to);
      if (target === undefined) return { ok: false, code: 'peer-offline', reason: 'peer not connected' };
      // The claimant must still name us, so a routing id that was recycled by a
      // different connection cannot inherit the earlier one's addressability.
      if (target.peerRoutingId !== peer.routingId) {
        return { ok: false, code: 'peer-offline', reason: 'peer not connected' };
      }
      return { ok: true, target };
    }

    // Peer mode. `to` is meaningless here and is refused rather than ignored:
    // silently dropping it would let a sender believe it had redirected a frame.
    if (to !== undefined && to !== peer.peerRoutingId) {
      return { ok: false, code: 'bad-message', reason: 'to must name this peer’s counterpart' };
    }
    if (peer.peerRoutingId === undefined) {
      return { ok: false, code: 'not-registered', reason: 'register first' };
    }
    const target = this.peers.get(peer.peerRoutingId);
    if (target === undefined) return { ok: false, code: 'peer-offline', reason: 'peer not connected' };
    // A rendezvous holder is reachable by anyone who knows its id, which is the
    // one case where the target does not name us back.
    if (target.mode === 'rendezvous') return { ok: true, target };
    // Both sides must name each other. A one-sided claim cannot be used to
    // inject frames into someone else's tunnel.
    if (target.peerRoutingId !== peer.routingId) {
      return { ok: false, code: 'peer-offline', reason: 'peer not connected' };
    }
    return { ok: true, target };
  }

  private withinQuota(peer: Peer): boolean {
    const at = this.now();
    if (at - peer.windowStart >= 60_000) {
      peer.windowStart = at;
      peer.windowFrames = 0;
    }
    if (peer.windowFrames >= this.frameRatePerMinute) return false;
    peer.windowFrames += 1;
    return true;
  }

  private send(socket: ServerWebSocket, message: RelayServerMessage): void {
    socket.sendJson(message);
  }

  private refuse(socket: Duplex, status: number, reason: string): void {
    try {
      socket.write(`HTTP/1.1 ${status} ${reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`);
    } catch {
      // Peer already gone.
    }
    socket.destroy();
  }

  private log(line: string): void {
    // Metadata only. A relay log must never be able to describe a frame's
    // contents, so nothing from a sealed record reaches this path.
    if (this.verbose) console.error(`[relay] ${line}`);
  }
}

/** Error codes re-exported so a connector can switch on them without a deep import. */
export type { RelayErrorCode };

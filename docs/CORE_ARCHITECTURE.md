# Core architecture: secure workstation bridge + mobile pairing

**Scope marker.** Section 1 restates verified official dsh behavior (full
citations in [DSH_CORE_RESEARCH.md](DSH_CORE_RESEARCH.md)). Everything from
section 2 onward — the bridge, the relay, pairing, device identity, the mobile
wire protocol — is **[OUR DESIGN]**. None of it exists in dsh, and none of it
should be described as official dsh behavior to users or in code comments.

## 1. The constraint we are designing against (official dsh)

| Fact | Source |
| --- | --- |
| Web server binds only `127.0.0.1` or `0.0.0.0` | `host/webserver` config schema |
| No TLS, no auth, no origin policy | `host/webserver` README, known limitations |
| `dsh web --host 0.0.0.0` refused by the CLI as remote code execution exposure | `bundle/web-app/src/startup.ts` |
| `/api` trust fence is "a reachability policy, not authentication" | `client/connection` README |
| 15 privileged methods pinned to loopback with an empty trust list | `client/connection/src/index.ts` |
| Default agent already carries `bash` + filesystem tools | `client/connection` source comment |

**Therefore: `/api` reachability == code execution as the workstation user.**

Three approaches are ruled out:

- **Direct phone → dsh.** Requires `0.0.0.0`, which the CLI refuses, and would
  publish an unauthenticated RCE endpoint to the LAN. Rejected.
- **A generic TCP tunnel** (ngrok-style, raw port forward). Publishes the same
  unauthenticated endpoint to a wider network. Rejected.
- **The stdio JSON-RPC SDK.** No cancel, no per-session close, no per-prompt
  result, and no network transport. It cannot back the mobile UX. Rejected as the
  primary path.

What remains is an authenticating, method-filtering process of our own on the
workstation. That is the bridge.

## 2. [OUR DESIGN] Topology

```
┌──────────────────────── workstation (user's machine) ────────────────────────┐
│                                                                              │
│   dsh web  ──────────────────  127.0.0.1:3080                                │
│   (unauthenticated /api, RCE-equivalent, untouched)                          │
│        ▲                                                                     │
│        │ loopback only. Host: 127.0.0.1:3080 → passes trust fence            │
│        │ carries privileged methods legitimately, but we deny them anyway    │
│        │                                                                     │
│   ┌────┴───────────────────────── dsh-mobile-bridge ──────────────────────┐  │
│   │  1. dsh client      : /api envelope RPC + 2 downlink streams          │  │
│   │  2. fanout + resume : merged frame log, per-device cursor             │  │
│   │  3. policy gate     : allow-list, deny-list, per-device scope         │  │
│   │  4. device registry : Ed25519 identities, pairing, revocation         │  │
│   │  5. transport       : TLS listener (LAN) and/or relay dialer          │  │
│   │  6. audit log       : append-only, on the workstation                 │  │
│   └────┬─────────────────────────────────┬────────────────────────────────┘  │
└────────┼─────────────────────────────────┼───────────────────────────────────┘
         │ Mode A: LAN direct              │ Mode B: relay (outbound only)
         │ TLS, cert pinned at pairing     │ bridge dials out; no inbound port
         ▼                                 ▼
   ┌───────────┐                    ┌──────────────┐
   │   phone   │                    │ relay server │  ← untrusted, sees only
   │ (this app)│◀──────────────────▶│  (blind)     │    ciphertext + routing id
   └───────────┘                    └──────────────┘
```

Non-negotiable invariants:

1. dsh itself is never reconfigured. It stays on loopback. We add no plugin and
   patch no upstream package.
2. The bridge is the **only** process that talks to `/api`.
3. No dsh port is ever bound to a non-loopback interface.
4. The relay is **untrusted** by construction and never holds a key that can
   decrypt payloads or authenticate as a device.
5. The phone holds no dsh credential. It holds only its own device key.

## 3. [OUR DESIGN] Bridge components

### 3.1 dsh client (`bridge/dsh/`)

Speaks the verified `/api` contract and nothing else.

- Unary: `POST /api/<method>` with `content-type: application/json` (mandatory —
  anything else is a 415), body `{type:'client-request', rpcId, method, payload}`.
  Verifies the echoed `rpcId`, folds `result.ok === false` into a typed error.
- Downlinks: opens **one** `events.mux` and **one** `events.host` for the whole
  bridge, regardless of how many devices are attached. Must implement the
  WebSocket upgrade path, because the Web composition answers a plain GET with
  **426**; SSE is only available to in-process carriers.
- Sends `Host: 127.0.0.1:<port>` so the upstream trust fence passes on loopback
  with no `trustedHosts` configuration required from the user.
- Readiness mirrors the official client: both sockets open **and** `host.describe`
  succeeds. On either socket ending, rebuild both and re-baseline.
- Recovery is the official procedure: reopen, take `session/subscribed.lastSeq`,
  refetch `session.history`, re-baseline `session.list` / `workspace.list` /
  history-tail `projections`, and re-surface replayed answerable frames. `since`
  is never sent — it is an unimplemented seat upstream.

### 3.2 Fanout and resume (`bridge/stream/`)

dsh has no resume. Mobile clients background, lose radio, and reconnect
constantly, so **the bridge owns resume** — this is our addition, not a dsh
feature.

- Merges mux and host frames into one ordered log with a bridge-assigned
  monotonic `bseq` (distinct from dsh's per-session `seq`).
- Retains a bounded ring buffer (default 2000 frames or 8 MiB, whichever first)
  plus the latest **snapshot** frames per session, which are idempotent by
  design: `session/queue`, `session/jobs`, `session/projection`
  (higher-seq-wins), `workspace-changed`.
- A device reconnecting with `?after=<bseq>` inside the window gets the delta. On
  overflow the bridge replies `resync-required`, and the phone re-baselines with
  the official procedure rather than trusting a partial delta.
- Pending answerable frames are re-sent on every device attach with the **same
  `rpcId`**, matching dsh's own replay semantics.
- Corrupt-frame policy matches upstream: report and skip, never kill the stream.

### 3.3 Policy gate (`bridge/policy/`)

Independent of dsh's loopback pinning. We are on loopback, so upstream would
*allow* privileged methods; we deny them ourselves.

- **Deny-list (hard, never overridable by config):** all 15 upstream privileged
  methods — `host.pickDirectory`, `host.openPath`, `settings.describe`,
  `settings.openDocument`, `settings.update`, `settings.replace`,
  `settings.mutate`, `credentials.describe`, `credentials.set`,
  `credentials.unset`, `agentPreset.read`, `agentPreset.copy`,
  `agentPreset.openDocument`, `agentPreset.remove`, `llm.discoverModels`.
  Rationale: they read or mutate host configuration, probe credential
  provenance, drive the host desktop, or are reconnaissance on what plugins a
  session runs. A phone has no business reaching any of them.
- **Default allow-list:** `session.list`, `session.search`, `session.history`,
  `session.create`, `session.prompt`, `session.cancel`, `session.rename`,
  `session.fork`, `session.models`, `session.selectModel`, `session.updateQueue`,
  `session.attachment`, `subagent.list`, `subagent.history`, `subagent.prompt`,
  `subagent.interrupt`, `host.describe`, `workspace.list`, `skill.list`,
  `agentPreset.list`, `agentPreset.select`, `goal.*`, `llm.providers`,
  `llm.models`, and `respond`.
- **Opt-in tier (off by default, per device):** `workspace.create`,
  `workspace.rename`, `workspace.delete`, `workspace.insertBefore`,
  `workspace.insertSessionBefore`, `workspace.archiveSession`,
  `host.listDirectory`, `host.createDirectory`.
- Unknown method → rejected. New upstream methods must be reviewed in, never
  auto-allowed; dsh is developer preview and will add methods.
- Payload caps enforced before forwarding: request body ≤ 8 MiB by default (far
  under upstream's 160 MiB resident bound), image blocks validated against the
  verified `mediaType` set, `content` shape checked before it reaches dsh.
- **Slash-command note.** `session.prompt` with exactly one text block starting
  with `/` is executed by the host command registry, not the model. The gate
  treats mobile slash commands as a distinct, separately loggable capability and
  can disable them per device.

### 3.4 Device registry (`bridge/identity/`)

- Each phone generates an **Ed25519** keypair on first run. The private key lives
  in `expo-secure-store` (Keychain / Keystore), is non-exportable from the UI, and
  never leaves the device.
- The bridge stores per device: `deviceId` (hash of the public key), public key,
  label, scope tier, `createdAt`, `lastSeenAt`, revocation state.
- Registry file is `0600` under the bridge's state directory. Revocation is
  immediate and terminates live streams for that device.

### 3.5 Transport (`bridge/transport/`)

**Mode A — LAN direct.** Bridge listens on TLS with a self-signed cert generated
at first run. The phone pins the SPKI fingerprint at pairing time and refuses any
other cert. No plaintext listener exists — not even for redirect.

**Mode B — Relay.** Bridge makes an **outbound** WSS connection to a relay and
registers under an opaque routing id. The phone connects to the same relay with
its own routing id. The relay forwards opaque frames. No inbound firewall change
is needed, which is the common case for home NAT and corporate Wi-Fi.

Relay trust: the relay is treated as a hostile network. All application frames
inside the relay tunnel are additionally sealed with a Noise-style handshake
(X25519 ephemeral + Ed25519 static device/bridge keys) so the relay sees only
ciphertext, frame lengths, and timing. TLS to the relay is transport hygiene, not
the security boundary. The relay never receives a device public key it could
replay, and pairing never completes through a relay-supplied identity.

### 3.6 Audit log (`bridge/audit/`)

Append-only JSONL on the workstation: timestamp, `deviceId`, method, decision
(`allowed` / `denied` / `rate-limited`), `sessionId`, and a payload digest —
never payload text, never credentials. Every approval and question answer
delivered from a phone is logged with its `rpcId`. The user can read this to
answer "what did my phone do while I was away."

## 4. [OUR DESIGN] Mobile wire protocol

Deliberately **not** dsh's protocol. It is a narrow, authenticated envelope with
its own versioning, so an upstream break does not silently reshape the phone's
contract.

| Endpoint | Purpose |
| --- | --- |
| `POST /m1/pair/claim` | One-shot pairing claim; consumes the pairing token |
| `POST /m1/auth/session` | Challenge/response with the device key → short-lived access token |
| `POST /m1/rpc` | `{ method, payload }` → gate → dsh unary → typed result |
| `GET /m1/stream?after=<bseq>` | Merged, resumable frame stream (WebSocket) |
| `POST /m1/respond` | Answer an answerable frame; `rpcId` echoed verbatim |
| `GET /m1/health` | Bridge liveness + dsh reachability + protocol version |

Frame envelope pushed to the phone:

```json
{ "v": 1, "bseq": 4821, "kind": "mux" | "host" | "bridge",
  "rpcId": "<echoed for answerable frames>", "frame": { "type": "session/event", "...": "..." } }
```

`kind: "bridge"` carries our own control frames (`resync-required`,
`dsh-disconnected`, `dsh-ready`, `token-expiring`, `device-revoked`) — clearly
distinguishable from dsh frames so the client never mistakes one for the other.

## 5. [OUR DESIGN] Pairing flow

Pairing is the only moment trust is established, so it requires physical access
to the workstation.

```
workstation                                   phone
───────────                                   ─────
$ dsh-mobile-bridge pair
  ├─ generate pairing token (32B random)
  ├─ TTL 120s, single use
  └─ render QR + numeric fallback
                                              scan QR
        ◀────── POST /m1/pair/claim ──────────
                { token, devicePublicKey, label,
                  proof: Sign(devicePrivKey, token ‖ bridgeId) }
  ├─ verify token unexpired + unconsumed
  ├─ verify signature over token ‖ bridgeId
  ├─ consume token (atomic; a second claim fails)
  ├─ display short authentication string (SAS)
  └─ REQUIRE the user to confirm on the workstation
        ────── { deviceId, bridgeName, scopeTier } ─────▶
                                              store deviceId + pinned SPKI/relay id
```

QR payload (`[OUR DESIGN]`, versioned):

```
dshm://pair?v=1&bid=<bridgeId>&tok=<token>
     &fp=<base64url SPKI SHA-256>        # Mode A
     &relay=<https origin>&rid=<routing id>   # Mode B
```

Pairing rules:

- Token is single-use, 120 s TTL, and consumed atomically. A replayed claim fails
  even within the TTL.
- The device's signature over `token ‖ bridgeId` binds the claim to that key, so
  observing the QR alone is not enough.
- The **SAS confirmation on the workstation is mandatory**, including on LAN. It
  defeats an attacker who photographs a QR from across the room.
- Pairing is refused entirely when the bridge cannot reach dsh, so a user never
  pairs into a dead bridge and blames the phone.
- Mode B pairing still pins the bridge's static public key from the QR. A relay
  cannot substitute its own identity.

## 6. [OUR DESIGN] Session authentication

- `POST /m1/auth/session` → bridge returns a nonce → phone signs
  `nonce ‖ deviceId ‖ bridgeId` → bridge verifies against the registered public
  key → issues an access token.
- Access token TTL **15 minutes**, bound to `deviceId`, and rotated on the stream
  connection. A stolen token is short-lived and useless without the device key.
- The token is sent in `Authorization: Bearer` for `/m1/rpc` and `/m1/respond`,
  and in the WebSocket subprotocol for `/m1/stream`. It is never placed in a query
  string — query strings land in logs.
- Phone-side storage: device private key and pinned fingerprint in
  `expo-secure-store`; access token in memory only. `AsyncStorage` holds neither.
- Revoking a device on the workstation kills its streams immediately and rejects
  its next auth attempt.

## 7. [OUR DESIGN] Approval and question handling

This is the highest-risk mobile surface: an `approval/requested` frame is dsh
asking permission to run a tool, and the default agent carries `bash`.

- The phone renders `toolName`, `reason`, and `callId` from the frame. It must not
  present a one-tap "allow" without showing what is being allowed.
- Only `allowed-once` and `rejected` are sendable — verified from the upstream
  approval payload schema. There is no "always allow" on mobile, by design.
- The `rpcId` is echoed **verbatim** from the frame. The bridge validates that the
  `rpcId` is currently pending for that device's view before forwarding, so a
  phone cannot answer a frame it never received.
- `respond` is single-shot upstream: a late or duplicate answer returns
  `{accepted:false, reason:'not-pending'}`. The bridge serializes answers per
  `rpcId` and surfaces `not-pending` to the phone as a benign "already resolved"
  state, not an error.
- The correlation ids in the answer payload come from the frame the bridge
  delivered, never from the request body. Upstream re-checks `sessionId` and
  `approvalId` against its own pending entry and answers `bad-response` on a
  mismatch, so a client-supplied id would be both useless and dangerous: it would
  let a device answer the frame its `rpcId` names while attributing the decision
  elsewhere. The phone sends only the decision.
- `question/requested` carries at least one item by wire contract, and may carry
  an `intent` of `{kind:'plan-review', approve}`. Unknown intents are rendered
  generically rather than dropped.
- A question is answered as a **whole batch**: one answer per item, in order, ids
  matching. The bridge maps the phone's single `value` field onto upstream's
  `{selected, custom}` split by comparing against the labels the question offered,
  and enforces upstream's own rules locally (no duplicate selections, at most one
  free-text value, single-select takes a label *or* free text). A malformed answer
  is a 400 naming the problem instead of an opaque upstream `bad-response`, and it
  never consumes the obligation — the frame stays answerable.
- Optional per-device setting: approvals require biometric re-auth
  (`expo-local-authentication`) before the answer is sent.

## 8. [OUR DESIGN] Client-side event fold

The phone reuses dsh's own robustness posture rather than assuming a fixed
vocabulary:

- Unknown `event.type` → generic fallback card, never a crash. The vocabulary is
  44 types in the pinned checkout and will grow; `data` is wide by contract.
- Snapshot frames replace, never merge: `session/queue`, `session/jobs`,
  `workspace-changed`.
- `session/projection` keeps a generic per-session key→value store under
  **higher-seq-wins**, seeded from the history tail `projections` block. Session
  titles arrive this way — there is no title frame.
- `blank` from `host/session-added` is always `true`; flip it on the first
  `host/session-status(running:true)` and treat `session.list`'s `summary.blank`
  as authoritative after reconnect.
- `view` on `tool/call` / `tool/result` is unpersisted render intent and may be
  absent on a later delivery. The generic JSON card is the documented default.
- `assistant/chunk` drives streaming text; `turn/end` is the turn boundary. The
  `/api` gateway gives us both, which is exactly what the stdio SDK cannot.

## 9. [OUR DESIGN] Failure modes and their handling

| Failure | Bridge behavior | Phone behavior |
| --- | --- | --- |
| dsh not running | `/m1/health` reports `dsh: down`; RPC returns `dsh-unavailable` | Explicit "harness offline on your workstation" state; no retry storm |
| dsh restarts | Rebuild both downlinks, re-baseline, emit `dsh-ready` | Re-fetch history for the open session |
| One downlink dies | Fail the generation, rebuild both (upstream semantics) | Show reconnecting; keep the last rendered state |
| Resume window overflow | Emit `resync-required` | Full re-baseline via the official procedure |
| Token expired | 401 | Silent re-auth with the device key, then retry once |
| Device revoked | Emit `device-revoked`, drop streams | Wipe local state, return to pairing |
| Relay down (Mode B) | Exponential backoff redial | Offline state; unchanged local history |
| Corrupt frame | Log and skip | No action; gap detection covers it |
| Denied method | 403 with the method name | Surface as a capability limit, not a bug |

## 10. [OUR DESIGN] Explicit non-goals

- No cloud-hosted dsh. The harness stays on the user's machine.
- No relay that can read traffic, and no relay-issued identity.
- No privileged-method access from mobile, ever — not behind a toggle.
- No plaintext HTTP fallback, on any interface, in any mode.
- No dsh source modification, patch, or plugin. We consume the published contract.
- No `--host 0.0.0.0` guidance in our docs or onboarding. The CLI refuses it and
  the reason is remote code execution.

## 11. Verification debt before implementation

Because dsh is developer preview with promised breaking changes, the following
must be re-verified against the pinned checkout at each milestone:

1. The RPC method map, and any newly added method's privilege classification.
2. Whether the deployed carrier still answers `GET /api/events.*` with 426 plus a
   WebSocket upgrade, versus serving SSE.
3. The event vocabulary set (regenerated upstream by `gen-persistence-catalog`).
4. `SESSION_FORMAT_VERSION`, currently pinned at 0 with no migration path.
5. Whether upstream has gained a real authentication layer — several upstream
   comments say privileged methods stay loopback-local "until a real
   authentication layer exists." If that lands, parts of this bridge may reduce to
   a thin transport.

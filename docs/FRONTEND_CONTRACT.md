# m1 frontend contract

**[OUR DESIGN]** The wire contract between the React Native app and the bridge.
Types live in [`src/m1/types.ts`](../src/m1/types.ts); runtime constants in
[`src/m1/paths.ts`](../src/m1/paths.ts). This document is the narrative version:
the state machine, the sequences, the exact payloads, and the error handling.

Every example below is **captured from the implementation**, not hand-written.
Where something is untested, it says so.

- **Protocol version:** `1` (`M1_PROTOCOL_VERSION`)
- **Transport:** HTTPS + WebSocket over TLS, self-signed cert, SPKI pinned by the phone
- **Encoding:** JSON, UTF-8
- **Auth:** `Authorization: Bearer <token>`, except on `/m1/pair/claim` and `/m1/health`

## Contents

1. [Why the bridge exists](#1-why-the-bridge-exists)
2. [Endpoints](#2-endpoints)
3. [The response envelope](#3-the-response-envelope)
4. [Error codes](#4-error-codes)
5. [Pairing](#5-pairing)
6. [Authentication](#6-authentication)
7. [RPC](#7-rpc)
8. [The stream](#8-the-stream)
9. [Answering approvals and questions](#9-answering-approvals-and-questions)
10. [Client state machine](#10-client-state-machine)
11. [Storage requirements](#11-storage-requirements)
12. [Relay mode](#12-relay-mode)
13. [The UI API: what `useDsh()` gives you](#13-the-ui-api-what-usedsh-gives-you)
14. [What is not verified](#14-what-is-not-verified)

## 1. Why the bridge exists

The app never talks to dsh. It talks to the bridge, which talks to dsh.

This is not indirection for its own sake. dsh's `/api` has **no
authentication** — its trust check is a reachability policy, and upstream
documents that anything able to reach `/api` can execute code as the workstation
user. There are 15 privileged methods it pins to loopback for exactly that reason.

So the bridge is the authorization boundary. It terminates the phone's connection,
authenticates the device against a registered Ed25519 key, checks the method
against a policy, and only then forwards. The app's job is to hold a device key
and a short-lived token correctly.

Two consequences the UI must respect:

- **A denied method is a normal outcome, not a bug.** Render it.
- **The phone's capability list is data, not a constant.** Read `allowedMethods`
  from the session and drive affordances from it.

## 2. Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/m1/health` | none | Liveness, dsh link state |
| `POST` | `/m1/pair/claim` | pairing proof | Claim a pairing token; poll for confirmation |
| `POST` | `/m1/auth/session` | device signature | Challenge, then prove; yields a token |
| `POST` | `/m1/rpc` | bearer | Forward one dsh method call |
| `POST` | `/m1/respond` | bearer | Answer an approval or question |
| `GET` | `/m1/stream` | bearer, in subprotocol | WebSocket event stream |

**The token never appears in a URL.** On `/m1/stream` it travels as a WebSocket
subprotocol, because query strings land in access logs, proxy logs, and shell
history. Offer both:

```
Sec-WebSocket-Protocol: dshm.v1, dshm.token.<token>
```

## 3. The response envelope

Every response except `/m1/health` is enveloped:

```ts
type M1Response<T> = { ok: true; value: T } | { ok: false; error: BridgeError };
```

`/m1/health` is deliberately flat — it is a probe a phone may call before it holds
any credential, and wrapping it would imply a session that does not exist:

```json
{
  "ok": true,
  "protocol": 1,
  "bridgeId": "8a2185be-2671-4aff-abf6-ab331b642782",
  "bridgeName": "dsh bridge",
  "bridgeVersion": "0.1.0",
  "dsh": "up",
  "dshState": "connected",
  "uptimeSeconds": 0,
  "pairedDevices": 0
}
```

`dsh: "up"` requires **both** downlinks open **and** a successful `host.describe`.
A bridge that is reachable while dsh is down answers `"down"` with HTTP 200 — the
bridge is healthy, the harness is not. Those are different problems and the UI
should say which one it is.

### Three distinct failure shapes on `/m1/rpc`

This is the single most important distinction in the contract:

```ts
type M1RpcResult =
  | { ok: true;  requestId?: string; value: unknown }            // dsh succeeded
  | { ok: false; requestId?: string; error: BridgeError }        // the bridge refused or could not ask
  | { ok: false; requestId?: string; dshError: DshBusinessError } // the harness said no
```

`error` and `dshError` are structurally separate on purpose. "You are not allowed
to do that" and "the harness tried and failed" need different UI and different
retry logic. A `dshError` arrives with **HTTP 200**, matching dsh's own behaviour.

## 4. Error codes

Closed set. `M1_BRIDGE_ERROR_CODES` exports it as runtime values so a `switch` can
be checked for exhaustiveness.

| Code | HTTP | Meaning | What the app should do |
|---|---|---|---|
| `unauthenticated` | 401 | No token, expired, or unknown | Re-authenticate silently with the device key |
| `method-denied` | 403 | Deny-listed or out of scope tier | Show the limit. Do not retry |
| `device-revoked` | 403 | Revoked at the workstation | Wipe local state, go to `unpaired` |
| `bad-request` | 400 | Malformed, or unknown method | Bug. Log it |
| `payload-too-large` | 413 | Over the documented limit | Shrink or refuse locally |
| `rate-limited` | 429 | Too many calls | Back off using `retryAfterMs` |
| `dsh-unavailable` | 503 | Harness not reachable | `harness-offline`. Keep history rendered |
| `dsh-protocol-error` | 502 | dsh answered out of contract | Log. Do not retry blindly |
| `pairing-invalid` | 400 | Token unknown, expired, or spent | Restart pairing |
| `pairing-unconfirmed` | 409 | Operator has not confirmed yet | Keep polling |
| `pairing-rejected` | 403 | Operator said no | Stop. Do not retry |
| `internal` | 500 | Bridge fault | Log, retry once |

Two of these are terminal and must **never** auto-retry: `pairing-rejected` (the
operator made a decision) and a **pin mismatch** (not an error code — a TLS
failure). A pin mismatch means the key at that address is not the key you paired
with. Fail closed, tell the user, and require re-pairing.

`unauthenticated` is the routine one. Tokens live 15 minutes; expiry is expected,
not exceptional. Recover without user interaction.

## 5. Pairing

One-shot token, 120-second window, operator-confirmed 6-digit SAS.

### The QR payload

Mode A, on the LAN, pinning the TLS SPKI:

```
dshm://pair?v=1&bid=8a2185be-2671-4aff-abf6-ab331b642782&tok=kQ7pX2vN8mR4tL6wY0zA3bC5dE9fG1hJ&bk=lEmLASH1mfLtu8Z0jW8WPTzfEoTMV6nbtIF05t1lwyo&fp=RXhhbXBsZVNwa2lQaW5CYXNlNjRVcmxWYWx1ZUhlcmU
```

Mode B, through a relay:

```
dshm://pair?v=1&bid=8a2185be-2671-4aff-abf6-ab331b642782&tok=kQ7pX2vN8mR4tL6wY0zA3bC5dE9fG1hJ&bk=lEmLASH1mfLtu8Z0jW8WPTzfEoTMV6nbtIF05t1lwyo&relay=wss%3A%2F%2Frelay.example%2Frelay%2Fv1&rid=r-7f3a9c1e
```

| Param | Required | Meaning |
|---|---|---|
| `v` | yes | `1` |
| `bid` | yes | Bridge id, stable across restarts |
| `tok` | yes | One-shot pairing token |
| `bk` | yes | **Bridge static Ed25519 public key. Pin this in both modes.** |
| `fp` | mode A | base64url SHA-256 of the TLS SPKI |
| `relay` | mode B | Relay origin to dial |
| `rid` | mode B | **Rendezvous** routing id — derived from `tok`, not a durable id |

`bk` is present in **both** modes, and that is the load-bearing detail: it is why a
relay can never substitute itself. The relay routes by routing id and never holds a
key, so a malicious relay that swapped in its own endpoint would fail the seal
against the pinned `bk`.

> **`rid` is not the bridge's durable routing id.** It is a *rendezvous* id derived
> from the pairing token, used for this one pairing and then discarded. The phone
> **must recompute it and refuse a mismatch** — see §12.2. The durable pair is agreed
> during pairing and the bridge's half arrives in the claim response, inside the
> sealed channel.

Parse with `parsePairingUri` from [`src/m1/pairing.ts`](../src/m1/pairing.ts).
It returns `undefined` for anything unrecognized — treat that as "not our QR code"
and keep scanning, not as an error.

### Sequence

```
 phone                                    bridge                       operator
   │                                        │                             │
   │  scan QR → parse → generate keypair    │                             │
   │                                        │                             │
   │─ POST /m1/pair/claim ─────────────────>│                             │
   │   {token, devicePublicKey, label,      │  verify proof over token    │
   │    proof}                              │  compute SAS                │
   │                                        │── show SAS ────────────────>│
   │<─ 200 {status:'awaiting-confirmation', │                             │
   │        sas, bridgeName, expiresAt} ────│                             │
   │                                        │                             │
   │  display SAS. user compares.           │                             │
   │                                        │<─ confirm (SAS matches) ────│
   │                                        │                             │
   │─ POST /m1/pair/claim (same body) ─────>│  proof-authenticated poll   │
   │<─ 200 {status:'paired', deviceId, ─────│                             │
   │        scopeTier, bridgeKeyFingerprint}│                             │
```

**Re-POST the identical body to poll.** The token was spent by the first claim, so
the second call is a proof-authenticated *read*, not a second claim. It is checked
before the claim path so a retry can never look like a replay.

### The proof

Sign a **domain-separated, length-prefixed** message:

```
domainMessage('pair', token, bridgeId)
```

Framing, shown with short values so the structure is visible —
`domainMessage('pair', 'A', 'BB')`:

```
6473686d2f70616972 00000001 41 00000002 4242
└── "dshm/pair" ──┘ └─ len ┘ └A┘ └─ len ┘ └BB┘
```

Every part carries a 4-byte big-endian length. No combination of values can be
rearranged into a different valid message, which is what makes the signature bind
to *this* token and *this* bridge. Auth uses `'dshm/auth'` and the SAS uses
`'dshm/sas'`, so a pairing proof can never be replayed as an auth response.

Real values from the implementation:

```
token       kQ7pX2vN8mR4tL6wY0zA3bC5dE9fG1hJ
bridgeId    8a2185be-2671-4aff-abf6-ab331b642782
device pk   EtgzXr9lexDm5WjNyJAmATG6ASRb5XYADUVeAI8mkro
deviceId    oLvJlP7hds51C93EXQ4gMA        (derived from the public key)
sas         902600
proof       dVuBMeAH3MdJL1q5V33QggjHyqiTwnIM-0RrnO8JWKEESxmpibzFkt7X7pIbjOQARNvNOJZRg10QcF0G71BnDQ
```

`deviceId` is derived from the public key, so it is not a secret and not
attacker-chosen.

### SAS rules

- **6 digits, bound to token + bridge id + device public key.** Not a checksum of
  the connection — an attacker who intercepts must also win the token race.
- **The phone must display it and require a human comparison.** Auto-accepting
  removes the entire defence.
- **120-second window, shared.** The operator gets the *remainder* of the token's
  window, not a fresh one. Show the countdown.

### Pairing is refused when dsh is down

`pairing-invalid` with reason `dsh-unavailable` → HTTP 503 `dsh-unavailable`.
Pairing into a bridge that cannot reach the harness produces a phone that looks
broken, so it is refused up front. Say "start the harness first", not "pairing
failed".

## 6. Authentication

Two steps, one endpoint. A body without `signature` is a challenge request; a body
with one is the proof.

```
POST /m1/auth/session          {"deviceId": "oLvJlP7hds51C93EXQ4gMA"}
→ 200 {"ok":true,"value":{"nonce":"...","bridgeId":"...","expiresAt":1755...}}

POST /m1/auth/session          {"deviceId":"...","nonce":"...","signature":"..."}
→ 200 {"ok":true,"value":{
     "token":"...","expiresAt":1755...,"deviceId":"...",
     "scopeTier":"default","allowedMethods":[...],"slashCommandsEnabled":true}}
```

Sign `domainMessage('auth', nonce, deviceId, bridgeId)`.

- Nonce: single-use, 60-second TTL, bound to the device.
- Token: opaque, **in-memory on both ends**, 15-minute TTL.
- A bridge restart invalidates every token. Re-auth is silent — the device key is
  the durable credential.

An unknown device and a revoked device get the **same** `unauthenticated` answer,
so an unauthenticated caller cannot enumerate which device ids ever existed. The
app cannot distinguish them, and does not need to: both mean re-pair.

Read `allowedMethods` and `slashCommandsEnabled` from the session rather than
assuming a tier's contents. Tiers are `default` and `extended`; `extended` is
granted explicitly at the workstation. **Neither tier can reach a denied method** —
that list is hard and not tier-dependent.

## 7. RPC

```
POST /m1/rpc
Authorization: Bearer <token>

{"v":1,"method":"session.list","payload":{},"requestId":"ui-42"}
```

```json
{ "ok": true, "requestId": "ui-42", "value": { "sessions": [] } }
```

`value` is dsh's **unwrapped** result. The bridge strips dsh's envelope so the app
never has to know that dsh reports business errors as HTTP 200.

The bridge mints dsh's `rpcId` itself; the phone never supplies one. `requestId` is
the app's own correlation id, echoed untouched.

A denied method:

```json
{
  "ok": false,
  "error": {
    "code": "method-denied",
    "message": "settings.update is permanently denied to mobile devices",
    "method": "settings.update"
  }
}
```

The gate runs **after** authentication, so a valid token does not widen the method
surface. Order is: deny list → known-method check → scope tier → payload limits.
An unknown method is refused rather than forwarded; a method nobody audited is not
a method a phone gets.

## 8. The stream

```
GET /m1/stream?after=<lastBseq>
Sec-WebSocket-Protocol: dshm.v1, dshm.token.<token>
```

### `bseq` is the only cursor that matters

Bridge-assigned, monotonic, and **not** dsh's per-session `seq`. Never compare
them. Persist the highest `bseq` you have fully processed and send it as `after=`
on reconnect.

### Hello, always first

```json
{
  "v": 1,
  "kind": "hello",
  "bridgeId": "8a2185be-...",
  "token": "<rotated>",
  "tokenExpiresAt": 1755000000000,
  "lastBseq": 412,
  "resync": false,
  "pendingCount": 1
}
```

**Adopt `hello.token` immediately.** Connecting rotates the token; the one you
dialled with is now stale. The long-lived credential is the device key, and the
token the phone carries afterwards is always a fresh one.

`resync: true` means your `after` fell outside the retention window. Discard
derived state and re-baseline properly — `session.list`, `workspace.list`, then
`session.history` per open session — rather than trusting a partial delta. A
`resync-required` bridge frame follows, then snapshots, then live frames.

`pendingCount` is how many answerable frames are replayed right after hello. A
phone that was away while the agent asked for approval still sees the request.

### Envelopes

```json
{ "v": 1, "bseq": 413, "kind": "mux", "rpcId": "e2e-1",
  "frame": { "type": "approval/requested", "sessionId": "s-1", "approvalId": "a-1", "toolName": "shell" } }
```

| `kind` | Source |
|---|---|
| `mux` | dsh session stream: events, approvals, questions, queue, jobs |
| `host` | dsh host stream: sessions, workspaces |
| `bridge` | Our own control frames |

`rpcId` is present **only on answerable frames** (`approval/requested`,
`question/requested`). A non-answerable frame carries none, deliberately: a phone
that cannot answer should not be handed a correlation id.

`frame` is typed `unknown` and must stay that way. The mux and host vocabularies
are upstream's and will grow. **Fold an unknown `frame.type` to a generic card.
Never crash, never drop silently.**

### Bridge control frames

| `frame.type` | Meaning | App action |
|---|---|---|
| `resync-required` | Window overflow or dsh restart | Re-baseline |
| `dsh-disconnected` | Harness link lost | `harness-offline`; keep history |
| `dsh-ready` | Harness back, with a generation number | Re-baseline; bseq is only meaningful within a generation |
| `token-expiring` | Token near expiry | Re-auth now, before it fails |
| `device-revoked` | Revoked at the workstation | Wipe local state. Terminal |
| `pong` | Reply to your ping | Liveness |

### Client → server

The stream is **not** an RPC channel. Only two messages:

```json
{ "v": 1, "kind": "ping", "at": 1755000000000 }
{ "v": 1, "kind": "ack",  "bseq": 413 }
```

Everything else goes over HTTP. A stream that accepted commands would be a second
authorization path, and two paths eventually disagree.

### Upgrade refusals

Read the HTTP status on a failed upgrade; it tells you what to do.

| Status | Meaning | Action |
|---|---|---|
| 401 | Missing, expired, or unknown token | Re-auth, then reconnect |
| 403 | Device revoked | Stop. Wipe. Do not retry |
| 400 | Bad `after` | Bug |
| 404 | Wrong path | Bug |

Closed with `dsh not ready` right after a `dsh-disconnected` frame means the bridge
is up but the harness is not — told explicitly so the UI can render "harness
offline" instead of spinning on "connecting".

## 9. Answering approvals and questions

```
POST /m1/respond
{"v":1,"rpcId":"e2e-1","kind":"approval","outcome":"allowed-once"}
{"v":1,"rpcId":"e2e-1","kind":"question","answers":[{"id":"q1","value":"main"}]}
```

Echo `rpcId` **verbatim** from the frame. The bridge rejects an `rpcId` that is not
currently pending for this device.

Send **only** the decision. Do not send `sessionId` or `approvalId`: the bridge takes
those from the frame it delivered and ignores yours. dsh re-checks them against its
own pending entry, so a payload built from client-supplied ids would be refused
upstream — and letting a client name them would let it answer one approval while
attributing the answer elsewhere.

Only `allowed-once` and `rejected` exist for approvals. **There is no "always
allow" on mobile.** A persistent grant made on a phone, away from the machine it
affects, is a decision made with the least context and the widest consequences.

### Question answers

One answer per question in the frame, **in the same order**, each `id` matching. A
partial batch is a 400: dsh answers one `ask()` as a whole batch, never per question.

`value` is a string or an array of strings, and the bridge sorts each one out for
you:

| What you send | What dsh receives | When |
|---|---|---|
| a value equal to an offered `option.label` | `selected: [label]` | choosing an option |
| any other non-blank string | `custom: "..."` | free text |
| several labels | `selected: [...]` | `multiSelect: true` only |
| labels plus one free-text value | both | `multiSelect: true` only |

So a single-select question takes exactly one value — a label **or** free text, not
both — and no question accepts more than one free-text value or a repeated
selection. Each answer's `value` is capped at 32 KiB of UTF-8, over which the reply
is `413 payload-too-large` rather than a `bad-request`, so you can truncate and
retry rather than reshape.

These rules mirror upstream's own validation. The bridge enforces them locally so a
malformed answer comes back as a 400 naming the problem, instead of an opaque
`bad-response` from dsh. A refused answer never consumes the obligation: the frame
stays open and remains answerable.

```ts
type M1RespondResult =
  | { status: 'accepted' }
  | { status: 'already-resolved' }
  | { status: 'rejected'; reason: 'bad-response' };
```

`already-resolved` is **benign**. dsh `respond` is single-shot, so a late answer —
the operator approved at the workstation first, or the user double-tapped —
legitimately returns `not-pending`. Do not show it as an error. Reconcile the UI to
the resolved state and move on.

`rejected` with `bad-response` is **not** benign and not retryable: dsh refused the
payload the bridge built. Report it as a bridge bug rather than looping.

## 10. Client state machine

```
                        ┌──────────┐
                        │ unpaired │◄──────────────────┐
                        └────┬─────┘                   │
                     scan QR │                         │ wipe
                             ▼                         │
                    ┌────────────────┐           ┌───────────┐
                    │    pairing     │           │  revoked  │
                    │  scanning      │           └───────────┘
                    │  claiming      │                 ▲
                    │  awaiting-     │                 │ device-revoked
                    │  confirmation  │                 │ (frame or 403)
                    └───────┬────────┘                 │
                     paired │                          │
                            ▼                          │
                   ┌────────────────┐                  │
            ┌─────►│ authenticating │──────────────────┤
            │      └───────┬────────┘                  │
            │       token  │                           │
            │              ▼                           │
            │       ┌─────────────┐                    │
            │       │ connecting  │                    │
            │       └──────┬──────┘                    │
            │        hello │                           │
            │              ▼                           │
            │        ┌───────────┐   resync:true  ┌───────────┐
            │        │   ready   │───────────────►│ resyncing │
            │        │  lastBseq │◄───────────────└───────────┘
            │        └─┬───────┬─┘   re-baselined
            │  socket  │       │ dsh-disconnected
            │  lost    │       ▼
            │          │  ┌─────────────────┐
            │          │  │ harness-offline │
            │          │  └────────┬────────┘
            │          │           │ dsh-ready
            │          ▼           ▼
            │   ┌──────────────┐   │
            └───│ reconnecting │◄──┘
       401      │  attempt     │
                │  nextRetryAt │        ┌───────────────┐
                └──────────────┘        │ pin-mismatch  │  terminal,
                                        └───────────────┘  never auto-recover
```

Exhaustive by design. Every failure mode lands in exactly one state.

| State | Invariant |
|---|---|
| `unpaired` | No device key, or wiped after revocation |
| `pairing` | Holds a keypair and a token; trusts nothing yet |
| `authenticating` | Paired, no valid token. Silent, no user interaction |
| `connecting` | Have a token, opening the stream |
| `ready` | Live stream. `lastBseq` is the resume point |
| `reconnecting` | Transient: radio loss, backgrounding, bridge restart. Backoff |
| `harness-offline` | Bridge reachable, dsh not. **Keep local history rendered** |
| `resyncing` | Window overflowed. Re-baselining |
| `revoked` | Terminal until re-paired. Wipe |
| `pin-mismatch` | Terminal for this bridge. **Never auto-recover** |

Two rules worth stating plainly:

- **`harness-offline` is not an error screen.** The bridge is fine, the harness is
  not. Keep everything already fetched on screen; a phone that blanks its history
  because a workstation restarted is worse than one that shows a banner.
- **`pin-mismatch` never auto-recovers.** The key at that address is not the key
  you paired with. That is either a misconfiguration or an attack, and the app
  cannot tell which. Require explicit re-pairing.

## 11. Storage requirements

| Item | Where | Why |
|---|---|---|
| Device private key | Secure enclave / keystore (`expo-secure-store`) | The durable credential. Never in plain storage |
| `deviceId`, `bridgeId` | Ordinary storage | Not secret; derived from public data |
| Pinned `bk` and `fp` | Ordinary storage, **integrity matters** | A silently-changed pin is a downgrade |
| Access token | **Memory only** | 15-minute lifetime. Persisting it widens the window for nothing |
| `lastBseq` | Ordinary storage | Resume cursor |

The access token must not be persisted. It is re-obtainable in one round trip from
the device key, so writing it to disk adds exposure and buys nothing.

## 12. Relay mode

When the phone is off the LAN, both sides dial a relay. It is treated as hostile:

- It **cannot decrypt**. It forwards opaque sealed records between two routing ids.
- It **stores nothing**. No accounts, no history of who talked to whom.
- It has **no admin surface** — nothing to authenticate to, so nothing to steal.
- Each paired device gets a **fresh routing id**, so one paired phone cannot
  observe another's tunnel metadata.

Sealing uses X25519 ephemerals, the pinned Ed25519 statics from `bk`,
transcript-bound signatures, HKDF-SHA256 to two directional AES-256-GCM keys, and
64-bit counter nonces authenticated as AAD. Crypto is **fail-closed**: a record
that will not open drops the connection rather than degrading.

**This construction is Noise-IK-*shaped* but is [OUR DESIGN], not a Noise
implementation, and has had no external cryptographic review.** It is covered by
unit tests, which is not the same thing as being sound.

The app's contract does not change in relay mode: the same `/m1/*` requests are
replayed inside the tunnel against the bridge's own routes, so there is exactly one
authorization path whether the phone is on the LAN or across the internet.

### 12.1 Two kinds of routing id

Do not conflate these. Confusing them is what made the earlier design unusable.

| | Rendezvous id | Durable routing id |
|---|---|---|
| Where it comes from | Derived from the pairing token | Random, minted at pairing |
| Who computes it | Both sides, independently | Bridge mints its own; phone mints its own |
| Lifetime | One pairing window (≤120 s) | Until the device is revoked |
| Carried in | The QR's `rid` | Claim response `value.relay`, then stored |
| Used for | Exactly one pairing | Every tunnel afterwards |

**The workstation does not need to know anything about the phone before printing a
mode B QR code.** That is the whole point of the rendezvous: `pair --relay` takes no
routing id, because there is none to take yet.

### 12.2 First pairing over a relay — exact phone-facing sequence

```
 phone                                relay                    bridge      operator
   │                                    │                        │            │
   │  scan QR (mode B)                  │                        │            │
   │                                    │  register(rid,         │            │
   │                                    │<─ mode:'rendezvous') ──│            │
   │  1. R = derive(tok, bid)           │                        │            │
   │     REFUSE if R !== rid            │                        │            │
   │  2. P = 16 random bytes → b64url   │                        │            │
   │─ register{role:'phone',            │                        │            │
   │   routingId:P, mode:'peer',        │                        │            │
   │   peerRoutingId:R} ───────────────>│                        │            │
   │<─ registered ──────────────────────│                        │            │
   │                                    │                        │            │
   │  3. pairing handshake (§12.3)      │                        │            │
   │─ handshake{eph, sig:''} ──────────>│─ handshake{…, from:P} ─>│            │
   │<─ handshake{eph, sig} ─────────────│<─ handshake{…, to:P} ──│            │
   │     VERIFY sig against bk          │                        │            │
   │─ handshake{eph, sig:deviceSig} ───>│───────────────────────>│  retain    │
   │                                    │                        │  transcript│
   │  ── sealed from here on ──         │                        │            │
   │  4. tunnel/request POST            │                        │            │
   │     /m1/pair/claim                 │                        │            │
   │     {token, devicePublicKey,       │                        │  verify    │
   │      label, proof,                 │                        │  retained  │
   │      relayRoutingId:P} ───────────>│───────────────────────>│  transcript│
   │                                    │                        │── SAS ────>│
   │<─ 200 {status:'awaiting-           │                        │            │
   │        confirmation', sas} ────────│                        │            │
   │  display SAS. user compares.       │                        │<─ confirm ─│
   │                                    │                        │            │
   │  5. re-POST the identical body     │                        │            │
   │<─ 200 {status:'paired', deviceId,  │                        │            │
   │        relay:{bridgeRoutingId:B,   │                        │            │
   │               peerRoutingId:P}} ───│                        │            │
   │                                    │                        │            │
   │  6. store (B, P). drop rendezvous. │                        │            │
   │     reconnect: register{routingId:P, peerRoutingId:B} and run the         │
   │     STEADY-STATE handshake (both statics real).                          │
```

Step by step, with the phone's obligations:

**1. Recompute `rid` and refuse a mismatch.**

```
msg = utf8("dshm/pair-rendezvous")
    || u32be(len(utf8(tok))) || utf8(tok)
    || u32be(len(utf8(bid))) || utf8(bid)

R   = base64url( SHA-256(msg)[0..16] )        // first 16 bytes → 22 chars, no padding
```

The length prefixes are what make the encoding injective — without them `tok="a"`,
`bid="bc"` and `tok="ab"`, `bid="c"` would hash the same. This is the same
`domainMessage` framing used by every other signature in this contract (§4), so an
implementation that already has it needs only the new `pair-rendezvous` purpose string.

`R` and `rid` are equal by construction, so a mismatch means the QR was altered in
transit. Refusing is free, so refuse — do not dial `rid` on trust.

**2. Mint your own routing id.** 16 random bytes, base64url, no padding — 22
characters. The phone chooses this. Nothing needs to have seen it before.

**3. Run the pairing handshake** (§12.3), then verify the bridge's signature against
the `bk` you pinned from the QR. **A failure here is terminal for this QR**: it means
something in the path is not the bridge. Do not retry, do not fall back.

**4. Claim inside the sealed channel.** Send a `tunnel/request` whose body is the
ordinary LAN claim body plus one transport field:

```jsonc
{
  "v": 1, "type": "tunnel/request", "id": "<your correlation id>",
  "method": "POST", "path": "/m1/pair/claim",
  "body": {
    "v": 1,
    "token": "…",               // from the QR
    "devicePublicKey": "…",     // your Ed25519 static, base64url raw
    "label": "Pixel 8",
    "proof": "…",               // domainMessage('pair', token, bridgeId), as on LAN
    "relayRoutingId": "…"       // P — REQUIRED over a relay, omitted on LAN
  }
}
```

No `token` field on the *frame* — that is the session token, which does not exist yet.
The pairing token goes in the body, as it does on LAN.

`relayRoutingId` is required and must be a valid 22-character routing id; the bridge
answers `400` and does **not** spend the token if it is missing or malformed. It is
declared *inside* the sealed channel rather than taken from the relay's `from` field,
so a hostile relay cannot choose which routing id gets registered.

Only `POST /m1/pair/claim` is reachable before pairing. Anything else — `/m1/rpc`,
`/m1/health`, `tunnel/subscribe` — is refused. `tunnel/ping` works, and is a cheap way
to confirm the sealed channel before showing the user a code.

**5. Poll by re-POSTing the identical body.** Same rule as LAN. On success the
response carries one extra field mode A does not have:

```jsonc
{
  "ok": true,
  "value": {
    "status": "paired",
    "deviceId": "…",
    "bridgeId": "…",
    "bridgeName": "…",
    "scopeTier": "default",
    "bridgeKeyFingerprint": "…",  // mode A only
    "relay": {                     // MODE B ONLY — added by the rendezvous listener
      "bridgeRoutingId": "…",      // B — store this; it is the only place you learn it
      "peerRoutingId": "…"         // P — echoed back so you can assert it round-tripped
    }
  }
}
```

**Store `bridgeRoutingId` durably.** It is the only time the bridge sends it. The
rendezvous is closed shortly after the operator confirms (about 20 seconds), so a
phone that discards it has to re-pair.

**6. Reconnect in steady state.** Register `{routingId: P, peerRoutingId: B}` in
`mode:'peer'` and run the **steady-state** handshake, in which both statics are real
keys. The pairing handshake is never used again.

### 12.3 The pairing handshake, and why it differs

The steady-state seal binds both pinned Ed25519 statics into the transcript. At first
contact the bridge does not know the phone's key — that key arrives *inside* the
claim, so requiring it to build the channel that carries the claim is circular.

The pairing handshake substitutes a **token binder** for the phone's static:

```
binder = base64url( HKDF-SHA256(
             ikm  = utf8(tok),
             salt = utf8(bid),
             info = utf8("dshm pair binder"),
             len  = 32) )
```

32 bytes, so it occupies a static slot exactly like a real Ed25519 public key does —
the transcript builder cannot tell the difference, which is why no other part of the
handshake needs a pairing-specific branch.

Both sides then run the ordinary transcript with the initiator slot set to `binder`
and the responder slot set to the bridge's real `bk`. Nothing else changes: same
canonical field order, same HKDF labels (`dshm relay i2r` / `dshm relay r2i`), same
record layer.

Session id is `"<P>:<R>"` — the phone's routing id, then the rendezvous id. The bridge
builds it from the routing id the relay tagged the frame with, so the phone must use
the same `P` it registered or no signature will verify. (That is separate from the
`relayRoutingId` *inside* the claim, which is the address the phone asks to be
registered at; it is normally the same value and there is no reason to differ.)

On the wire, both handshake messages are the same two-field shape carried in
`relay/handshake`:

```jsonc
{ "v": 1, "type": "relay/handshake",
  "hs": { "v": 1, "eph": "<base64url raw X25519, 32 bytes>", "sig": "…" } }
```

Round one sends `sig: ""` — the transcript commits to the peer's ephemeral, which is
not known yet, so there is nothing to sign. Round two carries the signature. Both
sides send their ephemeral first and sign second; the phone signs with its **device**
key, the bridge with the static behind `bk`.

What each side proves:

| Party | Proves | How |
|---|---|---|
| Bridge | It is the bridge in the QR | Signs the transcript with the static behind `bk`. **The phone verifies this and must refuse on failure.** |
| Phone | It saw the QR | Cannot compute `binder` without `tok` |
| Phone | It owns the device key | Signs the transcript with its device key; the bridge retains it and verifies once the claim reveals the key |

That last row is what binds the sealed channel to the device being registered: a
claim whose `devicePublicKey` did not establish the channel is refused and the channel
dropped. So a relay cannot splice one device's channel onto another's claim.

**What this does not defend against**, stated plainly: anyone who *reads the QR* can
compute `binder` and open a pairing channel of their own. That is the same exposure
mode A has, and it is why the operator-confirmed SAS is mandatory in both modes — the
SAS commits to the device public key, so an attacker's channel yields a code that does
not match the phone in the user's hand. The token is single-use and consumed
atomically, so only one claim ever reaches the SAS step.

### 12.4 Relay frames the phone must handle

| Frame | When | Phone's job |
|---|---|---|
| `relay/registered` | After register | Proceed to the handshake |
| `relay/peer-offline` | The rendezvous holder disconnected | Abandon this pairing; re-scan. Do not retry the handshake — the bridge discarded its half |
| `relay/error` `rendezvous-busy` | Too many concurrent claimants | Ask the operator to re-run `pair` |
| `relay/error` `routing-id-taken` | Your `P` collided | Mint a new `P` and re-register |
| `relay/error` `peer-offline` | The rendezvous was already gone when you sent | Token likely expired; re-scan |
| `relay/error` `quota-exceeded` | Frame rate exceeded | Back off; the connection stays usable |

The two `peer-offline` shapes are different signals. The bare `relay/peer-offline`
frame is unsolicited and means the counterpart you were talking to has left;
`relay/error` with code `peer-offline` is the rejection of a specific frame you just
sent. Neither names the peer, because a peer has only one counterpart.

Frames the phone sends to a rendezvous need no `to` field: the rendezvous is its
registered `peerRoutingId`. The bridge's replies carry no `from` in steady state,
because a peer already knows its one counterpart.

One asymmetry worth knowing: the relay only admits a phone to a rendezvous's claimant
set when the phone sends its **first frame**, not when it registers. A phone that
registers and then sits idle is invisible to the holder and will not be told when the
holder leaves. Send the round-one handshake promptly after `relay/registered`.

## 13. The UI API: what `useDsh()` gives you

**[OUR DESIGN]** This section is the boundary between the protocol core and `app/`.
Everything above describes the wire; this describes the only surface `app/` should
touch. The core is `src/m1/` and is owned by the protocol side; `app/` consumes it
exclusively through `useDsh()` from [`src/useDsh.tsx`](../src/useDsh.tsx).

Nothing in `app/` should import from `src/m1/` directly. If a screen needs something
the hook does not expose, the hook is what changes.

### 13.1 Getting at it

`DshProvider` must wrap the tree; `useDsh()` throws outside it.

```tsx
import { DshProvider, useDsh } from '../src/useDsh';

<DshProvider><Stack /></DshProvider>
```

### 13.2 Connection state — the field to branch on

```ts
const { state } = useDsh();
```

`state` is `M1ClientState`, a discriminated union on `state.name`. It is the single
source of truth for what to show. Every variant and its payload:

| `state.name` | Payload | What it means for the UI |
| --- | --- | --- |
| `unpaired` | `reason: 'fresh' \| 'cleared' \| 'pairing-rejected' \| 'pairing-invalid' \| 'stale-record'` | Show the QR scanner. `reason` is why we are here, not an error to alarm the user with. |
| `scanning` | — | Camera is up, nothing scanned yet. |
| `pairing` | `phase: 'claiming' \| 'sealing' \| 'confirming'` | Spinner with a sub-caption. |
| `awaiting-confirmation` | `sas: string`, `bridgeName: string`, `expiresAt: number` | **Show `sas` prominently.** The user compares it with the workstation. |
| `paired` | `bridgeName: string`, `deviceId: string` | Pairing done, not yet connected. Transient. |
| `connecting` | `phase: 'relay' \| 'sealing' \| 'authenticating' \| 'streaming'`, `attempt: number` | First connect of a session. |
| `ready` | `lastBseq: number`, `dsh: 'up'` | The only state where RPCs are expected to work. |
| `reconnecting` | `attempt: number`, `nextRetryAt: number`, `reason: string` | Retrying. `nextRetryAt` is an epoch ms for a countdown. |
| `harness-offline` | — | Bridge reachable, `dsh web` is not. Nothing the user can fix from the phone. |
| `relay-unavailable` | `attempt: number`, `nextRetryAt: number`, `code?: RelayErrorCode` | Relay or the far side is unreachable. See §13.7 on `code: 'peer-offline'`. |
| `resyncing` | — | Cursor fell out of the bridge's window; history is being rebuilt. Brief. |
| `rendezvous-busy` | — | **Terminal.** Too many phones on one QR. Needs a new QR. |
| `routing-collision` | — | **Terminal.** Our routing id is taken. Needs re-pairing. |
| `revoked` | — | **Terminal.** The operator removed this device. Route already wiped. |
| `pin-mismatch` | `detail: string` | **Terminal, and a security event.** Tell the user not to continue. |

Terminal means retrying is pointless — the core has stopped and only `pair()` or
`clear()` moves it. Do not hand-roll that list:

```ts
import { isTerminalState, describeState } from '../src/m1/state';
```

`describeState(state)` returns a short human sentence for every variant, so a screen
can render an unknown-to-it state without a fallthrough bug. `state.name === 'ready'`
is also available as the boolean `connected`.

### 13.3 Pairing

```ts
const { pair, pairing, clear } = useDsh();

const result = await pair(uri, 'My iPhone');   // uri is the scanned dshm:// string
```

`pair()` resolves to a `PairClaimResult` and never rejects. Drive the UI from `state`
while it is in flight: it passes through `pairing` → `awaiting-confirmation` → `paired`
→ `connecting` → `ready`. The SAS the user must compare is in the
`awaiting-confirmation` state, and mirrored in `pairing` for convenience.

`clear()` forgets the workstation: wipes the stored route, drops the in-memory token,
and returns to `unpaired` with `reason: 'cleared'`. It does **not** tell the bridge —
the operator still sees the device listed until they revoke it there.

The device keypair survives `clear()` by design, so re-pairing the same phone keeps
the same `deviceId`.

### 13.4 Sessions, messages, and the rest

All of these reject on failure with an `M1Error` carrying `code` (see §4) — or a
`TransportError` if the bridge could not be reached at all.

```ts
const {
  sessions,        // SessionSummary[], kept fresh by the stream
  refresh,         // () => Promise<void> — re-fetch the list
  create,          // (title: string) => Promise<string>  → sessionId
  send,            // (id, content, mode?: 'queue' | 'steer') => Promise<void>
  cancel,          // (id) => Promise<void>
  loadHistory,     // (id) => Promise<void> — fills getMessages(id)
  getMessages,     // (id) => ChatMessage[]      — synchronous, from cache
  getApprovals,    // (id) => PendingApproval[]  — synchronous
  getQuestions,    // (id) => PendingQuestion[]  — synchronous
  resolve,         // (sessionId, rpcId, 'approve' | 'deny') => Promise<void>
  answer,          // (rpcId, answers: QuestionAnswer[]) => Promise<void>
  subscribe,       // (id, listener) => () => void — per-session live events
  activity,        // ActivityItem[] — a rolling human-readable log
  lastBseq,        // number — the stream cursor, for debug screens
} = useDsh();
```

`getMessages`/`getApprovals`/`getQuestions` read a cache the stream maintains; they are
synchronous and safe to call during render. `subscribe(id, listener)` returns its own
unsubscribe — call it from a `useEffect` cleanup.

Approvals and questions arrive with an `rpcId` that must be echoed back exactly. It is
the bridge's handle for a blocked harness call, so a wrong or reused one silently fails
to unblock anything.

### 13.5 What the hook deliberately does not expose

- **The access token.** It is memory-only inside the core and never leaves it (§11).
  `token` and `wsUrl` are present on the returned object as empty strings for
  backwards compatibility with older screens and carry no value — do not build on them.
- **The device private key.** Held in `expo-secure-store`, reachable only by the core.
- **Routing ids and the bridge's static key.** In `bridge` for a diagnostics screen if
  one is wanted, but they are not something a screen should act on.

### 13.6 Reconnect is automatic

The core owns its own backoff — `500ms, 1s, 2s, 5s, 10s, 20s, 30s` with ±25% jitter,
capped, resetting on a successful stream hello. A screen should never call `connect()`
in a retry loop; render `reconnecting` with the `nextRetryAt` countdown instead.

Token rotation, resync, and re-authentication after expiry are likewise internal. The
UI sees them only as brief `resyncing` or `connecting` states.

### 13.7 One honest gap the UI has to absorb

**A sleeping workstation looks like any other relay outage.** When the far side stops
answering — closed laptop, dropped Wi-Fi, relay hiccup — the phone lands in
`relay-unavailable` with `code: 'peer-offline'` and retries forever. That is deliberate:
a transient outage is far more common than a permanent one, and forgetting the
workstation on every dropped connection would be worse. But the phone cannot tell a
laptop that will wake up from one that never will, so **offer a "forget this
workstation" action on a long-lived `relay-unavailable`** — it maps to `clear()` and is
the only escape the state machine will not take on its own.

Note this is *not* how revocation or an operator decline surface. Revocation now
delivers `device-revoked` over the relay just as it does on the LAN, so the phone
reaches the terminal `revoked` state; and a relay pairing decline now delivers the 403
`pairing-rejected`, so the phone reaches `unpaired` with `reason: 'pairing-rejected'`.
Both are read from a rendezvous/connector that the bridge deliberately holds open a
moment past the decision so the phone's in-flight poll can collect it — see §14. So a
`peer-offline` that persists is genuinely an outage, not a swallowed refusal.

## 14. What is not verified

Stated plainly, because a contract document is exactly where a reader will assume
everything has been proven.

**Tested** — `npm test`, 734 passing across 27 files, plus `npm run typecheck:all`.

The bridge side (`npm run test:bridge`):

- Policy gate, deny list, tier scoping, payload limits
- Pairing: proof verification, replay, SAS binding, expiry, dsh-unavailable refusal
- Auth: challenge/prove, nonce single-use, token rotation, revocation
- RPC forwarding and dsh business-error passthrough
- Stream: resume, window overflow, snapshots, pending replay
- Relay: routing, sealing, connector backoff, fail-closed rejection
- **Mode B first pairing (§12.2), end to end over a real relay process**: rendezvous
  id derivation and mismatch refusal, pairing handshake in both directions, bridge
  signature forgery refused, impostor `devicePublicKey` refused with the token left
  unspent, missing/malformed `relayRoutingId` refused before the claim is replayed,
  paths other than `/m1/pair/claim` refused, rendezvous claimant cap, routing-id
  collision, and the durable route persisted from the sealed claim
- End to end over real TLS: pair → auth → rpc → revoke, and a live `/m1/stream`
  delivering a dsh frame

The RN core (`tests/m1-*.test.ts`), against a bridge double:

- Relay client: registration, error taxonomy, peer presence, frame-rate refusal
- Sealed tunnel: handshake, pinned-key verification, replay window, fail-closed on any
  crypto failure, request/response correlation, stream subscription
- Pair flow: both modes, the rendezvous-id consistency check, every failure kind
- `validateStoredBridge`: every rejectable record shape, including a Mode B record
  holding a rendezvous id where a durable one belongs
- Storage policy: **the fake keystore records every write, so a token reaching disk
  fails the suite**
- Core state machine: reconnect and the exact backoff schedule, token rotation and the
  refresh margin, resync, revocation, terminality, pin mismatch, LAN address changes,
  the harness-down-vs-bridge-down split, and every one of the 15 states in §10
- The UI translation layer (`tests/m1-ui-adapter.test.ts`): frame → event mapping, and
  specifically that an approval's or question's `rpcId` survives into what a screen
  receives — losing it produces a prompt the user cannot answer and a harness that stays
  blocked. Plus operator-readable copy for every `PairFailure` kind, checked to contain
  no routing ids or key material.

**The RN core against the real bridge and relay** — `bridge/tests/m1-mobile-e2e.test.ts`,
16 tests. No protocol double on either side: a real `RelayServer`, a real
`RendezvousListener`, a real bridge, `FakeDshServer` behind it, and the actual `src/m1`
core as the phone. It covers a relay QR to `ready` through the sealed tunnel with
`sealing` proven to precede `authenticating`; the durable route being the bridge-minted
one and not the QR's `rid`; no token on any write; an RPC answered by dsh; a policy
refusal that keeps the session up; a live mux envelope with its `rpcId` intact; an
approval answered; reconnect on the durable route with the rendezvous gone; token
rotation across hellos; a cold start from storage with no QR; revocation; an operator
decline; a spent token; a tampered `bk` in the QR; and `clear()`.

**Verified against a real `dsh web`** — `npm run smoke:dsh`, 18/18 passing against
upstream `0.1.0-rc.5` (commit `47f9438`) on 2026-08-16; see
[REAL_DSH_SMOKE.md](./REAL_DSH_SMOKE.md) for the reproduction and the full check list:

- The `/api` envelope, the HTTP-200-business-error vs carrier-error split, and the
  404/415/400 carrier behaviours this contract describes
- All 15 deny-list methods exist upstream; `host.pickDirectory` blocks a real host
  indefinitely, which is why it is denied
- `GET /api/events.mux` answers 426 `upgrade: websocket`, and `DshDownlink` reads a
  real frame over the WebSocket
- The whole bridge in front of real dsh: `/m1/health` connected, a full pair → auth →
  `/m1/rpc session.list`, and a 403 `method-denied` for `settings.describe`

**Verified as a plugin under a real `dsh web`** — `plugins/dsh-bridge/scripts/integration-test`,
PASS against the same upstream `47f9438` on 2026-08-16; see
[DSH_PLUGIN_INTEGRATION.md](./DSH_PLUGIN_INTEGRATION.md). `dsh plugin add` links the
package and reconciles `dsh.profile.bundles`, `cordis.patch.yml` composes the
`mobile-bridge` row into the tree, the Cordis loader mounts `src/index.ts`, and the
in-process bridge reaches `dshState: connected` on its own TLS listener — no source
change needed. The deterministic CI guard for the plugin's own `apply()` contract is
`bridge/tests/dsh-plugin-loader.test.ts`.

**Fixed (previously listed as bridge-side defects):**

- **Revocation now reaches the phone on the relay path.** `controlHandlers.revoke`
  fires the revocation listeners — which queue `device-revoked` onto the carrier
  stream and drop the stream subscriber — and the relay connector's teardown is now
  *deferred* by a bounded linger (`REVOCATION_LINGER_MS`, default 1 s) in
  [`bridge/src/bridge.ts`](../bridge/src/bridge.ts) rather than run in the same tick.
  The frame therefore traverses hub → carrier socket → connector → seal → relay before
  the tunnel is torn down, and the phone reaches the terminal `revoked` state. Deferring
  is safe: the device is already out of the registry, so anything arriving through the
  still-open tunnel gets 401/403, and `disconnectDevice` drops the stream subscriber
  synchronously. `bridge/tests/m1-mobile-e2e.test.ts` asserts the phone reaching
  `revoked` on `controlHandlers.revoke`, alongside the direct-frame case.
- **A relay pairing decline now reaches the phone as `pairing-rejected`.** `confirm(false)`
  rejects the SAS with `pairing.reject()` (which keeps the session in `failed` rather
  than erasing it) and lingers the rendezvous, so the phone's next proof-authenticated
  poll reads the 403 `pairing-rejected` the LAN path always gave it. The phone reaches
  `unpaired` with `reason: 'pairing-rejected'`. Covered by
  `bridge/tests/relay-rendezvous.test.ts` (the phone reads the 403 over the lingering
  rendezvous) and `bridge/tests/m1-mobile-e2e.test.ts` (the core lands in
  `pairing-rejected` end to end).

**Not verified:**

- **Mode A has no enforceable certificate pin, and the LAN path never verifies `bk`.**
  The QR's `fp` is stored but cannot be checked: React Native's `fetch` and `WebSocket`
  expose no certificate hook, so the TLS SPKI pin this document describes is not
  actually enforced in JS. `/m1/auth/session` is also one-way — the phone signs a
  nonce, the bridge signs nothing — so the pinned `bk` goes unused on the LAN path. The
  `bridgeId` check in the core catches a *different* bridge answering, not a proxy
  relaying to the right one. **Mode B has no such gap**: the seal handshake verifies a
  signature by the pinned `bk` before any application byte moves, and the e2e suite
  proves a tampered `bk` is refused. Closing the Mode A hole needs either a native
  TLS-pinning module or a bridge-signed nonce in the auth response. Documented at
  length in [`src/m1/lan-transport.ts`](../src/m1/lan-transport.ts).
- **Any dsh revision other than `47f9438`.** The compatibility claim above is
  point-in-time. `/api` is pre-1.0 and is not a stability contract, and the unit
  suite still runs against `FakeDshServer`, which is a model of upstream rather than
  upstream. Re-run `npm run smoke:dsh` when upstream moves.
- **The relay path against real dsh.** The smoke test covers the LAN composition;
  relay coverage is `bridge/tests/relay-*.test.ts` and `m1-mobile-e2e.test.ts` against
  the local backend.
- **A physical device.** Every test runs the core under Node, with `expo-secure-store`
  and `expo-crypto` mocked and Node's `WebSocket` shimmed to the core's
  `WebSocketLike`. Real keychain behaviour, background suspension, and camera QR
  capture are unexercised.
- **The React wiring inside `useDsh.tsx`.** No renderer is installed, so the hook's
  effects, state updates, and cleanup are covered by `tsc` only. The pure translation
  functions it delegates to *are* tested (above), and the core it drives is tested
  thoroughly, but "the hook re-renders correctly on a state event" is not asserted
  anywhere.
- **A deployed relay behind public WSS.** The relay in tests is an in-process
  `ws://127.0.0.1`. No TLS, no proxy, no idle timeout, no NAT rebinding.
- **A native build.** Nothing here has been through `expo prebuild` or run on a
  simulator or device; the core is verified as a library, not as a bundled app.
- **Relay crypto review.** Unit-tested, not audited.
- **Windows.** The control socket is a Unix socket.

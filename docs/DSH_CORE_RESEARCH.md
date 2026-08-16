# DeepSeek Harness (`dsh`) core research

Verified against an official DeepSeek Harness source checkout on 2026-08-15.
Every claim below was read directly out of package sources or package READMEs in
that checkout. Anything that is *our* design rather than official dsh behavior is
marked **[OUR DESIGN]** and lives in
[CORE_ARCHITECTURE.md](CORE_ARCHITECTURE.md).

This document supersedes the guesses in [API_RESEARCH.md](API_RESEARCH.md).
That file assumed a REST shape (`/v1/sessions`, `GET /health`,
`WebSocket /ws?sessionId=`) which **does not exist** in dsh. The real surface is
a single envelope-based RPC gateway under `/api`.

## 1. What dsh is

`dsh` is DeepSeek AI's open-source agent harness (MIT). Its architecture is
"everything is a plugin", powered by the Cordis framework. It ships a Web UI:

```sh
npx @deepseek-ai/dsh web     # serves http://127.0.0.1:3080 by default
```

Relevant packages for a mobile client:

| Package | Role |
| --- | --- |
| `@deepseek-ai/dsh-host-apiproxy` | The API contract every client shares: TS types, zod schemas, the host-side `ApiProxy`, and the fetch carrier pair. Registers **no** routes itself. |
| `@deepseek-ai/dsh-client-connection` | Mounts the single `/api` route on the web server, owns the browser-trust fence and the WebSocket downlinks. |
| `@deepseek-ai/dsh-host-webserver` | `node:http` server, config `{host, port}`. Knows no harness concepts. |
| `@deepseek-ai/dsh-sdk-jsonrpc-server` | Newline-delimited JSON-RPC over **stdio** for out-of-process SDK clients. |
| `@deepseek-ai/dsh-sdk-protocol` | Shared wire types for the stdio JSON-RPC protocol. |
| `@deepseek-ai/dsh-session` | Session log, `SessionEvent` envelope, event vocabulary. |

There are therefore **two distinct official protocols**, and they are not
interchangeable:

1. **The `/api` HTTP gateway** — what the Web UI uses. Envelope RPC + two event
   streams. This is the one a mobile app should target.
2. **The stdio JSON-RPC SDK** — three request methods, four notifications, over
   a child process's stdin/stdout. No network listener at all.

## 2. Verified routes (host/apiproxy)

Source of truth: `packages/host/apiproxy/src/fetch/handler.ts` (`toFetchHandler`)
for the host side, `packages/host/apiproxy/src/fetch/client.ts`
(`AbstractApiClient`) for the client side, and
`packages/client/connection/src/index.ts` for what is actually mounted over HTTP.

There are exactly five physical route shapes. Everything else 404s.

### 2.1 `POST /api/<method>` — unary RPC

- Path segment after `/api/` is the RPC method name, e.g. `POST /api/session.list`.
- `content-type` **must** be `application/json`. Any other media type is
  rejected with **415** before dispatch. This is a deliberate cross-site write
  fence: browsers send "simple" POSTs without a CORS preflight, so only the JSON
  media type is accepted, forcing a preflight the server never answers.
- Body is a `ClientRequest` full form:
  ```json
  { "type": "client-request", "rpcId": "<uuid>", "method": "session.list", "payload": {} }
  ```
- Body that is not JSON → **400** (`body is not JSON`).
- Unknown method (not in the RPC map) → **404**.
- `message.method` must equal the path method, otherwise a `bad-request` error
  response is returned.
- Success and *business* failure both return **HTTP 200** with a
  `ServerResponse` body. HTTP status describes only the carrier:
  ```json
  { "type": "server-response", "rpcId": "<echoed>", "result": { "ok": true, "value": {} } }
  ```
  ```json
  { "type": "server-response", "rpcId": "<echoed>", "result": { "ok": false, "error": { "code": "internal", "message": "...", "details": {} } } }
  ```
- The client verifies the echoed `rpcId` matches what it sent and throws on
  mismatch. It then parses `result.value` against the method's value schema.
- The client applies a default request timeout (`AbortSignal.timeout`) merged
  with any caller signal; non-2xx is a transport throw.

### 2.2 `GET /api/events.mux` — all-session aggregated event stream

- Handled in `toFetchHandler` as **SSE**: `content-type: text/event-stream`,
  `cache-control: no-cache`, frames delimited by `\n\n`, payload lines prefixed
  `data: `.
- Each frame is a `ServerRequest` full form whose `payload` is a `MuxFrame`.
- **Critical deployment nuance:** in the shipped Web composition this GET does
  *not* serve SSE. `packages/client/connection/src/index.ts` intercepts
  `GET /api/events.mux` and returns **426 Upgrade Required** with
  `connection: Upgrade`, `upgrade: websocket`. The path accepts a WebSocket
  upgrade instead, and sends only `ServerRequest` text messages downstream; the
  client sends no application data over that socket. `toFetchHandler`'s SSE codec
  serves only the isomorphic in-process carrier (Electron/in-process clients).
- On open, the mux stream emits a `session/subscribed` control frame for every
  attached session, then replays each session's still-pending
  `approval/requested` and `question/requested` frames with the **same `rpcId`
  reused verbatim**. That replay is the documented refresh-recovery baseline.
- The `since` payload field (`Record<SessionId, number>`) is a reserved seat and
  is **unimplemented in v1** — it is ignored if passed. Official reconnection is:
  reopen the stream and refetch history.

### 2.3 `GET /api/events.host` — host-level event stream

- Same carrier rules as `events.mux`, including the 426/WebSocket substitution in
  the Web composition.
- Payload is a `HostFrame`. Empty request payload is `{}`.
- Carries session create/destroy, running-status flips, workspace snapshots, and
  agent failures that have no turn position.

### 2.4 `POST /api/respond` — answer a server-initiated request

- Body is a `ClientResponse` full form; the `rpcId` is **echoed from the
  server's frame, never minted anew**:
  ```json
  { "type": "client-response", "rpcId": "<from the requested frame>", "result": { "ok": true, "value": { "sessionId": "...", "approvalId": "...", "outcome": "allowed-once" } } }
  ```
- Response body is a carrier-layer `RpcReceipt`, **not** an RPC message:
  `{"accepted": true}` or `{"accepted": false, "reason": "not-pending" | "bad-response"}`.
  A late or duplicate answer yields `not-pending`; a malformed body yields
  `bad-response` — still HTTP 200.
- Approval payload: `{sessionId, approvalId, outcome: 'allowed-once' | 'rejected'}`.
- Question payload: `{sessionId, answer}`.
- The pending entry is keyed by the stable `rpcId` that the mux stream carried.

### 2.5 `GET` / `HEAD /api/session.export` — session log download

- Not an envelope route. Reads `sessionId` from the query string, validated by
  `sessionLogQuerySchema`; invalid or missing → **400**
  (`missing or invalid sessionId query parameter`).
- `HEAD` returns the same status and headers with the body cancelled.

### 2.6 Route dispatch summary

| Method + path | Body / query | Result |
| --- | --- | --- |
| `POST /api/<method>` | `ClientRequest` JSON | 200 `ServerResponse`; 415 wrong media type; 400 non-JSON; 404 unknown method |
| `GET /api/events.mux` | none | SSE in-process; **426 + WebSocket upgrade** in the Web composition |
| `GET /api/events.host` | none | SSE in-process; **426 + WebSocket upgrade** in the Web composition |
| `POST /api/respond` | `ClientResponse` JSON | 200 `RpcReceipt` |
| `GET`/`HEAD /api/session.export` | `?sessionId=` | log stream; 400 on bad query |
| anything else | — | 404 (`not found`) |

## 3. Verified `/api` RPC method map

Source: `packages/host/apiproxy/src/api/rpc-map.ts`. Map keys **are** the wire
path segments. `respond` is deliberately absent from the map because it is a
client-*response*, not a client-request.

**Sessions:** `session.list`, `session.search`, `session.create`,
`session.history`, `session.models`, `session.selectModel`, `session.rename`,
`session.fork`, `session.prompt`, `session.attachment`, `session.updateQueue`,
`session.cancel`

**Subagents:** `subagent.list`, `subagent.history`, `subagent.prompt`,
`subagent.interrupt`

**Host:** `host.describe`, `host.pickDirectory`, `host.listDirectory`,
`host.createDirectory`, `host.openPath`

**Workspace:** `workspace.list`, `workspace.create`, `workspace.rename`,
`workspace.delete`, `workspace.insertBefore`, `workspace.insertSessionBefore`,
`workspace.archiveSession`

**Skills:** `skill.list`

**Agent presets:** `agentPreset.list`, `agentPreset.select`, `agentPreset.read`,
`agentPreset.copy`, `agentPreset.openDocument`, `agentPreset.remove`

**Goals:** `goal.create`, `goal.edit`, `goal.pause`, `goal.resume`,
`goal.complete`, `goal.clear`

**Settings:** `settings.describe`, `settings.openDocument`, `settings.update`,
`settings.replace`, `settings.mutate`

**Credentials:** `credentials.describe`, `credentials.set`, `credentials.unset`

**LLM:** `llm.providers`, `llm.models`, `llm.discoverModels`

### 3.1 Verified signatures a mobile client needs

From `packages/host/apiproxy/src/api/sessions.ts` and `host.ts`:

```ts
session.list     ({ cursor?: string })                       -> { items: SessionSummary[] }
session.create   ({ workspaceId?, cwd?, sessionId?, agentPreset? })
session.history  ({ sessionId, beforeSeq?, maxMessages? })   -> { events: HistoryEntry[]; hasMore: boolean; projections?: SessionProjectionsBlock }
session.prompt   ({ sessionId, mode: 'queue'|'steer', content: PromptContentPart[], clientTimeZone? })
                                                             -> { accepted: true; command?: { kind: 'success'; text?: string } }
session.cancel   ({ sessionId })                             -> { accepted: true }
session.rename   ({ sessionId, title })                      -> { title: string; seq: number }
session.fork     ({ sessionId, atSeq? })                     -> { sessionId }
session.models   ({ sessionId })                             -> SessionModels
session.selectModel ({ sessionId, provider, model, reasoningEffort? }) -> { selected: ModelSelection }
session.updateQueue ({ sessionId, itemId, action: QueueAction }) -> { accepted: true }
session.attachment  ({ sessionId, attachmentId })            -> { attachment: ImageAttachmentRef; data: string }
host.describe    ({})                                        -> capability description incl. canOpenPath
```

Verified behavioral facts on these:

- `session.list` returns **everything** in v1, ordered `updatedAt` descending;
  `cursor` is a reserved, unimplemented seat.
- `session.prompt` `mode` maps 1:1 — `queue`→send, `steer`→steer. A prompt whose
  content is exactly one text block starting with `/` is a **slash command**:
  the host runs it through the command registry and it is never sent to the
  model. Usage/state errors come back as RPC errors `command-error`;
  unrecognized names as `unknown-command`.
- Browser callers attach `clientTimeZone` (an IANA zone); the host validates,
  canonicalizes, and records it on that exact user message. Omission is valid for
  non-browser callers.
- Session-backed **subagents reject** `prompt`, `cancel`, `rename`, `models`,
  `selectModel`, and `updateQueue` with error code `agent-busy`; subagents use
  the `subagent.*` methods instead.
- `session.fork` anchors the cut at the first `turn/end` at or after `atSeq`; an
  open turn fails with `fork-unavailable`.
- Business errors use a closed error-code union with a required `details` object;
  `internal` is the catch-all and uses an explicit `{}`.

## 4. Verified JSON-RPC SDK (`sdk/server` + `sdk/protocol`)

Source: `packages/sdk/server/src/server.ts` (dispatch switch in
`handleRequest`), `packages/sdk/protocol/src/types.ts`
(`HarnessSdkRequestMap`, `HarnessSdkNotificationMap`), and the
`@deepseek-ai/dsh-sdk-jsonrpc-server` README.

Transport is **newline-delimited JSON-RPC over stdio**. There is no HTTP
listener. Stdout carries only JSON-RPC frames — diagnostics must go to stderr, and
a deployment that composes a stdout logger corrupts the channel.

### 4.1 Request methods — exactly three

| Method | Params | Result |
| --- | --- | --- |
| `initialize` | `{ cwd, provider, model, maxTokens? }` | `{ serverInfo: { name, version } }` |
| `session/prompt` | `{ sessionId, contentBlocks }` | `{ messageId }` |
| `shutdown` | `undefined` | `{}` (empty object) |

Any other method throws, which becomes a JSON-RPC error response
(`unknown DeepSeek Harness SDK runtime method: <method>`).

Verified details:

- `serverInfo.name` is the **wire-stable** string `deepseek-harness-sdk-runtime`
  (version `0.0.1` in this checkout).
- `initialize.maxTokens` must be a **positive safe integer**; an invalid value
  rejects initialization with a `TypeError`. Omission sends no SDK cap and lets
  the adapter/provider default apply. The cap is inherited by SDK-created agents
  and their in-process descendants.
- `initialize` mounts `dsh-llm-deepseek` as a fallback **only** when the provider
  route is unowned *and* named `deepseek-official`. Any other unowned provider
  fails initialization with `no adapter registered for provider "<name>"`.
  Server defaults before `initialize` are `provider = model = 'deepseek-official'`,
  `cwd = process.cwd()`.
- Reinitialization is unsupported.
- `session/prompt` **queues one identified user message and returns immediately**
  with `{ messageId }`. It does not wait for the turn, and no assistant message or
  `turn/end` is attributed to that prompt. An unknown `sessionId` lazily creates
  the agent+session pair. If the record's agent was disposed outside the server,
  the call throws `session agent was disposed outside the server: <id>`.
- `shutdown` is idempotent (the task is memoized), disposes server-owned agents,
  the fallback adapter fiber, and subscriptions, then the plugin flushes the
  response and exits with code **0**. Teardown failures surface as the single
  error or an `AggregateError`.

### 4.2 Server-to-client notifications — exactly four

| Notification | Payload |
| --- | --- |
| `session.event` | `{ sessionId, event: SessionEvent }` |
| `session.status` | `{ sessionId, status: 'idle' \| 'running' }` |
| `subagent.started` | `{ parentSessionId, childSessionId }` |
| `subagent.finished` | `{ provider, agentId, parentSessionId, childSessionId, status: 'ok' \| 'error', stopReason, lastAssistantMessage? }` |

Verified details:

- `session.event` is emitted for **every session in the runtime**, not only
  SDK-created ones. It is a direct bridge of the internal `session/event` hook.
- `session.status` is a whole-agent lifecycle transition bridged from
  `agent/status` — only `idle` and `running`.
- `subagent.started` fires from `session/created` and only when the new session
  has a `parentSession` on its header.
- `subagent.finished` fires from `subagent/end` and is forwarded **only when the
  service-snapshotted lifecycle `local` flag is true**. Remote runs are never
  reported; provider names, child ids, and durable lineage never establish
  locality. `agentId` equals `childSessionId` for local runs.
- `status` mapping: `stopReason === 'completed'` → `ok`. `max-tokens` → `ok` only
  when the plugin's `maxTokensAsSuccess` config is `true` (default `false`);
  everything else → `error`. This mapping affects only `subagent.finished`;
  root-session prompts have no prompt-level status.

### 4.3 SDK limitations that matter for mobile

Documented in the package README as known limitations:

- **No per-session close and no prompt-cancel method.** SDK-created agents stay
  live until process shutdown.
- **No per-prompt result.** `messageId` identifies inbox admission only; a client
  that wants a completion boundary must define and observe it itself.
- Automatic adapter mounting is DeepSeek-specific.

Consequence: the stdio SDK cannot support a mobile client's cancel button or
per-turn completion UX. The `/api` gateway (which has `session.cancel` and
`turn/end` events) is the correct target.

## 5. Verified session event facts

### 5.1 The `SessionEvent` envelope

From `packages/host/apiproxy/src/api/sessions.schema.ts` — a **strict envelope
with a wide `data`** ("the client fold handles unknown types via its documented
default"):

```ts
{
  type: string            // event vocabulary name
  seq: number             // non-negative integer, per-session monotonic
  time: number            // epoch ms
  data: unknown           // domain payload, NOT validated at the carrier
  sourceEventSeqs?: number[]
  surfaceOp?: unknown
  ignorable?: true        // marker allowing older readers to skip an unknown type
}
```

`data` is deliberately not deep-validated at the wire boundary. A client must
tolerate unknown `type` values and unknown `data` shapes.

### 5.2 The event vocabulary — 44 known types

From the **generated** catalog `packages/core/session/src/known-event-types.ts`
(`KNOWN_SESSION_EVENT_TYPES`; regenerated by `pnpm run gen-persistence-catalog`
and verified by `doc-sync`):

```
agent-preset/selected      compaction/summary    request/header        tool-workflow/agent-end
agent/inbox/spliced        feedback/record       sandbox/mode          tool-workflow/agent-start
approval/asked             goal/change           schedule/change       tool-workflow/run-end
approval/decided           hook/invoked          session/end-seed      tool-workflow/run-start
approval/policy            hook/result           session/title         tool/call
assistant/chunk            llm/retry             session/title-llm-request  tool/code-dispatch
assistant/message          llm/retry-started     step/end              tool/code-dispatch-start
command/done               permission/preset     step/start            tool/result
command/run                plan/mode             subagent/descriptor   turn/end
compaction/end             request/context       todo/write            turn/start
compaction/prune                                                       user/message
                                                                       web/deepseek-search-llm-request
```

The persistence read path **refuses** to interpret a log containing a type
outside this set unless that event carries the `ignorable` marker — a log with an
unknown required event was likely written by a newer harness, and silently
skipping it would reconstruct a wrong session.

`SESSION_FORMAT_VERSION` is pinned at **0** while unreleased: no compatibility is
implied, incompatible logs are rejected, and no migration is provided. Adding an
ordinary event type does not bump it; the per-event `ignorable` guard covers
vocabulary growth.

### 5.3 `MuxFrame` union — verified members

From `packages/host/apiproxy/src/api/events.ts` and `events.schema.ts`
(a zod `discriminatedUnion('type')`):

| Frame | Shape | Answerable? |
| --- | --- | --- |
| `session/event` | `{ sessionId, event: SessionEvent, view?: ToolEventView }` | push |
| `session/subscribed` | `{ sessionId, lastSeq: number }` | push (control) |
| `approval/requested` | `{ sessionId, approvalId, toolName, callId?, reason? }` | **yes → `/api/respond`** |
| `approval/resolved` | `{ sessionId, approvalId, outcome }` | push |
| `question/requested` | `{ sessionId, questions: AskUserQuestionItem[] }` (min 1) | **yes → `/api/respond`** |
| `question/resolved` | `{ sessionId, questionRpcId, outcome: 'answered'\|'cancelled' }` | push |
| `session/queue` | `{ sessionId, items: QueuedInboxItem[] }` | push (full snapshot) |
| `session/jobs` | `{ sessionId, jobs: JobView[] }` | push (full snapshot) |
| `session/projection` | `{ sessionId, key: string, value: unknown, seq: number }` | push |
| `stream/error` | `{ error: RpcError }` | push |

`ApprovalOutcome` on `approval/resolved` is one of `allowed-once`, `rejected`,
`cancelled`, `unavailable`. A client may only *send* `allowed-once` or
`rejected`.

Verified semantics:

- **Answerable vs push is decided statically by frame type**, not by a runtime
  flag. There is no third kind. For answerable frames the `rpcId` is stable and
  reused on replay; for pure pushes it identifies that one push.
- `session/queue` is the **complete** transient inbox state after every enqueue,
  mutation, claim, or discard. Pending work is not model-visible and has no
  durable session event, so the whole snapshot is the only convergence signal for
  edit, deletion, cancel, reconnect, and a second client. `placement` is
  `queued` (renders in the queue dock), `steering` (renders at the conversation
  tail), or `context` (invisible until claimed).
- `session/jobs` is likewise a whole snapshot, sent as a subscription baseline
  **only for a session that currently has tasks**. An absent key means empty. A
  change that empties the set still sends `[]`, because absence cannot express
  that transition.
- `session/projection` is live push state that is **never logged** — replay
  recomputes it on the host. Clients keep one generic per-session value store
  under **higher-seq-wins**, seeded by the history tail page's `projections`
  block. Session titles ride this generic pair rather than a dedicated frame.
- `view` (`ToolEventView`) is a host-computed render intent for `tool/call` and
  `tool/result`, derived through the presenter registered at emission time. It is
  **never persisted**, so the same event may carry a different view — or none — on
  a later delivery. Absent view means the client's documented default (generic
  JSON card). `for` is `'call'` or `'result'`.
- `question/requested` is non-empty by wire contract; the user-questions service
  rejects empty batches at `ask()`, so an empty array is host breakage and fails
  loudly at the schema rather than reaching the composer.
- A frame that fails either parse level is reported and **skipped** — one corrupt
  frame must not kill the stream; the client's gap detection covers what it
  carried.

### 5.4 `HostFrame` union — verified members

Confirmed from `events.ts` / `events.schema.ts`: `host/session-added`
(`{ sessionId, blank, parentSessionId?, origin?: 'subagent', cwd?, agentPreset? }`),
`host/session-removed` (`{ sessionId }`), plus running-status flips
(`host/session-status`), `agent-error`, and workspace push frames
(`workspace-changed` carrying the full new snapshot, `workspace-removed`).

Verified semantics:

- `host/session-added` fires at `session/created`, so **`blank` is constantly
  true** on the frame. Clients flip it on that session's first
  `host/session-status(running: true)` — a blank session never runs. A
  reconnecting client must take `session.list`'s `summary.blank` as
  authoritative instead.
- `agent-error` is the only outlet for live failures that have no turn position.
- `workspace-changed` pushes the full new snapshot after every durable workspace
  mutation; the client upserts, and `workspace.list` is the reconnect baseline.

### 5.5 Reconnection model (verified)

There is **no official resume**. `since` on the mux stream is ignored in v1. The
official recovery procedure is:

1. Reopen the stream.
2. Take `session/subscribed { lastSeq }` per session as the watermark.
3. Refetch history via `session.history`.
4. Re-render pending answerable frames from the replay (same `rpcId`).
5. Re-baseline snapshots: `session.list`, `workspace.list`, and the history tail
   `projections` block.

## 6. Verified security posture of official dsh

This is the single most important set of facts for a mobile client, and it is why
a bridge is required.

- **`dsh-host-webserver` accepts only `127.0.0.1` (default posture) or
  `0.0.0.0` (deliberate network exposure)** as its bind host — a zod union of
  exactly those two literals.
- **The web server has no TLS, no auth, and no origin policy.** Stated verbatim
  in its README's known limitations: "binding a non-loopback address exposes the
  server to that network; deployment hardening (or fronting it with a real
  reverse proxy) is deliberately out of scope for the dev-facing v1."
- **`dsh web --host 0.0.0.0` is refused by the CLI.** `packages/bundle/web-app/src/startup.ts`
  errors with: "`--host 0.0.0.0` is intentionally not supported yet for safety:
  it would expose remote code execution to the network; use 127.0.0.1 instead."
  Flags available are `--host`, `--port` (0 lets the OS pick), and repeatable
  `--trusted-host <authority...>`.
- **The `/api` browser-trust fence** (`packages/client/connection/src/api-request-trust.ts`)
  guards every entry under `/api` before bridging or upgrading. Every request must
  present a `Host` that is a loopback authority or matches a `trustedHosts`
  entry — exact on `host:port` entries, any port on port-less entries, both sides
  compared through WHATWG normalization. This is DNS-rebinding defense. When
  browser markers are present, an attached `Origin` must equal the Host
  authority, and an explicit `sec-fetch-site: cross-site` is refused. Failures
  answer plain **403** before any RPC dispatch; upgrade failures reject the
  handshake before any stream starts.
- **The fence is explicitly "a reachability policy, not authentication"**, and
  "the Web carrier provides no authentication layer."
- **Privileged methods are pinned to loopback** by passing the fence with an
  empty trust list, so a declared `trustedHosts` authority cannot reach them:
  `host.pickDirectory`, `host.openPath`, `settings.describe`,
  `settings.openDocument`, `settings.update`, `settings.replace`,
  `settings.mutate`, `credentials.describe`, `credentials.set`,
  `credentials.unset`, `agentPreset.read`, `agentPreset.copy`,
  `agentPreset.openDocument`, `agentPreset.remove`, and `llm.discoverModels`.
  `agentPreset.list` and `agentPreset.select` stay out of that set.
- **The default agent already carries `bash` and filesystem tools.** The upstream
  comment is blunt: any caller that may start a session at all can already run
  commands as that process, so pinning the preset switch "would be a fence beside
  an open gate."

### 6.1 The load-bearing conclusion

**Reaching `/api` is equivalent to arbitrary code execution as the workstation
user.** There is no official authentication anywhere in the transport. A mobile
app must therefore never be given direct network reachability to a dsh `/api`
port, and we must not ask users to run `--host 0.0.0.0` (the CLI refuses it
anyway). Everything in [CORE_ARCHITECTURE.md](CORE_ARCHITECTURE.md) follows from
this.

## 7. Other verified facts worth keeping

- The `/api` bridge **buffers each request body in memory**; `maxRequestBodyBytes`
  defaults to **160 MiB**, sized for the default 100 MiB aggregate image limit
  after base64 expansion plus envelope headroom. That default is also the
  per-request resident bound.
- Image content blocks are `{ type: 'image', mediaType, data, name? }` with
  `mediaType` restricted to `image/png`, `image/jpeg`, `image/webp`, `image/gif`.
  Text blocks are `{ type: 'text', text }`.
- Readiness in the official client requires **both** downlink sockets open **and**
  a successful `host.describe`. If either socket ends, the connection generation
  fails and both streams are rebuilt. Each successful handshake publishes the
  exact `host.describe` value before `onConnected`; generation loss clears it, so
  capability answers are never retained while disconnected.
- `session.history` opening a cold session **may create the host-side agent** and
  add latency to the first open; there is no persistence-only read path.
- dsh is in **developer preview** with explicitly promised
  compatibility-breaking changes. Any client must pin a checkout and re-verify.

# dsh mobile-bridge management panel — frozen contract

This freezes the **host API** and the **exact UI hook** for the operator
management panel the `dsh-bridge` plugin serves under `dsh web`. The UI code in
`plugins/dsh-bridge/panel-ui/` is the primary agent's to style and finish; this
document is the boundary between that UI and the backend, and the backend will
not change it without a version bump here.

Companion docs: [`DSH_PLUGIN_INTEGRATION.md`](./DSH_PLUGIN_INTEGRATION.md) (the
plugin loads under a real `dsh web`) and [`REAL_DSH_SMOKE.md`](./REAL_DSH_SMOKE.md)
(the bridge's dsh-facing half). This one is the panel half.

**Contract version: 2** (2026-08-16).

> **Changed in v2 (delivery only; the UI hook §2 and the API §4 are unchanged, so
> the primary agent's UI needs no changes).** The panel now mounts **same-origin on
> dsh's own webserver** at `<dsh-origin>/mobile-bridge/` when dsh is loopback-bound
> (the supported upstream client-injection contract — see §6), and falls back to a
> dedicated `127.0.0.1` listener when dsh binds the LAN or predates
> `webServer.register`. The base path, bootstrap global, endpoints, and fence are
> identical in both modes.

---

## 1. What the panel is, and where it lives

The panel is a loopback-only, token-gated operator surface for the running
bridge. It exposes exactly what the owner-only control socket does — status,
device list, revoke, relay URL, recent audit, and **pairing** (the browser is the
operator-attended surface a bare plugin lacks, so it can compare the SAS) — and
nothing more. Every privileged action routes through the same
`ControlHandlers` the CLI uses; the panel introduces no new authorization path.

### Delivery: same-origin on dsh, or a dedicated loopback listener — never the LAN

The plugin chooses the mount from **dsh's own bind**, and the choice is invisible to
the UI (same base path, same bootstrap, same fence in both):

- **Same-origin route (default, when dsh is loopback-bound).** The plugin registers
  a prefix route on dsh's webserver via `ctx.webServer.register({ kind: 'prefix',
  path: '/mobile-bridge', handler })` — the supported client-injection contract for
  an out-of-tree plugin (see §6). The panel is served by dsh itself at
  `http://127.0.0.1:<dsh-port>/mobile-bridge/`, right next to the dsh web UI. Because
  dsh is loopback-bound, the route is only reachable from the local host anyway.
- **Dedicated `127.0.0.1` listener (fallback, when dsh binds `0.0.0.0`, or a host
  predates `webServer.register`).** The plugin opens its **own `http` listener bound
  to `127.0.0.1`** on `panelPort`. This keeps the panel **not even TCP-reachable**
  from another host by construction, even though dsh is serving the LAN.

Either way the same non-negotiable holds: **the panel is loopback-only and
bearer-gated, and is never served on the LAN.** The reasons the panel is safe on
dsh's shared listener even though the phone surface is not:

- The panel is *more* privileged than the phone surface (it mints access, revokes
  devices, opens pairing), so unlike the phone surface it does **not** rely on where
  it is served for its security. It carries its **own** four-check fence (§3), which
  does not depend on dsh's trust model at all. dsh's webserver fence is a
  *reachability policy, not authentication*; the panel adds real authentication on
  top, and **fails closed for any non-loopback peer** (403 at check #1) before a
  handler runs or the token is served. A LAN client that reaches the same-origin
  route because an operator bound dsh to `0.0.0.0` is refused at the door — which is
  also exactly why the plugin switches to the dedicated listener in that case, so the
  panel is not even reachable to be refused.
- The *phone* surface still never rides dsh's webserver: it is a separate TLS
  listener with its own identity, because putting the phone behind dsh's
  reachability-only fence would mean an operator who exposed the bridge had also
  exposed `/api`. That separation (see `plugins/dsh-bridge/src/index.ts`) is
  unchanged.
- Plain HTTP (not TLS) is correct for the panel: loopback traffic never leaves the
  machine, so transport secrecy buys nothing and a second self-signed cert would
  only train the operator to click through browser warnings. **The bearer token is
  the credential**, and it never crosses a wire that leaves the host.

```
 phone ── TLS ──▶ bridge :8765          (0.0.0.0 only by explicit operator choice)
 relay ── wss ──▶ carrier.sock          (unix socket, owner-only)
 CLI   ────────▶ control.sock           (unix socket, owner-only)
 operator ─────▶ dsh :<port>/mobile-bridge/   (SAME-ORIGIN when dsh is loopback)  ◀── this doc
        or ────▶ panel :8766            (dedicated 127.0.0.1 listener when dsh binds the LAN)
```

Enable/port: the panel is enabled by default. `panelPort` (env
`DSH_MOBILE_BRIDGE_PANEL_PORT`, default **8766**) sets the dedicated-listener port
and doubles as the master switch — **`panelPort <= 0` disables the panel entirely**,
in both modes. In same-origin mode the numeric port is unused (dsh's port is the
address); its sign still controls whether the panel is mounted at all.

<!-- APPEND_MARKER_2 -->

---

## 2. The UI hook (frozen)

The host serves the static files in `plugins/dsh-bridge/panel-ui/` verbatim under
the base path `/mobile-bridge/`, with **one** transformation: into `index.html`
only, it injects a single `<script>` immediately before `</head>` (or in place of
the `%%DSH_MOBILE_BRIDGE_BOOTSTRAP%%` placeholder comment if present) defining:

```js
window.__DSH_MOBILE_BRIDGE__ = {
  token: "<per-boot bearer token>",
  base:  "/mobile-bridge/api"
};
```

The UI **must** read the token and API base from this global and send the token
as `Authorization: Bearer <token>` on every `/api` call. That is the entire
contract the UI depends on. Everything else in `panel-ui/` — markup, styling,
framework choice, file layout — is the primary agent's to change. The reference
`panel.js` is vanilla ES modules with no build step (matching the repo's
zero-dependency ethos); replacing it with a built SPA is fine as long as the
final `index.html` still receives the injected bootstrap and the endpoint
contract below is honored.

Rules the host enforces around delivery:

- `index.html` is the only file the token is injected into. Every other asset is
  served byte-for-byte, so the token never lands in a cacheable `.js`/`.css`.
- All responses are `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- Path traversal out of `panel-ui/` is refused (403/404).
- **No CORS headers are ever sent.** A browser on another origin cannot drive the
  API even if it somehow obtained the token.

---

## 3. Security fence (all four must pass before any handler runs)

| # | Check | Failure | Defends against |
|---|-------|---------|-----------------|
| 1 | Remote peer is loopback (or a unix socket) | 403 | LAN clients if the listener is ever shared |
| 2 | `Host` header names a loopback address / `localhost` | 403 | DNS rebinding |
| 3 | `Authorization: Bearer <token>` on every `/api/*` (constant-time compare) | 401 | CSRF, rebinding that passed #2, cross-origin reads |
| 4 | `Content-Type: application/json` on every mutating route | 400 | `<form>`-based CSRF (a form cannot set that header cross-origin) |

In **dedicated-listener mode** the listener binds `127.0.0.1` and **refuses to bind
a non-loopback host** (`mountPanel` throws). In **same-origin mode** the route rides
dsh's listener, so check #1 (loopback peer) is what keeps it local — it fails closed
(403) for any non-loopback peer before a handler runs, so a LAN-bound dsh cannot leak
the panel. The token is a per-boot 256-bit random value, written to
`<stateDir>/panel-token` at mode `0600` so same-user tooling can read it — that file
is a convenience, not the boundary; the boundary is that all four checks above
already require you to be the local workstation user.

### What the panel never returns

- The bridge private key (never in `ControlHandlers` output to begin with).
- Raw pairing tokens. The QR `uri` is returned (it embeds the token as `tok=`,
  exactly as the QR an operator scans does — returning it to the already-
  authenticated local operator is equivalent to the CLI printing it), but the
  bare `token` field is dropped and never appears in status, list, or audit.
- Session tokens or nonces (none exist).

The public bridge key and TLS SPKI pin **are** returned: they are public by
construction (a phone pins them from the QR) and the panel renders them so the
operator can compare the same identity.

<!-- APPEND_MARKER_3 -->

---

## 4. API endpoints (frozen)

Base: `/mobile-bridge/api`. All responses are JSON with a uniform envelope:

```jsonc
// success
{ "ok": true, "value": { /* ... */ } }
// failure
{ "ok": false, "error": { "code": "bad-request", "message": "…" } }
```

Error `code` values: `bad-request` (400), `unauthenticated` (401), `not-found`
(404), `conflict` (409). All mutating routes (`POST`/`PUT`) require
`Content-Type: application/json`.

| Method | Path | Body | Success `value` |
|--------|------|------|-----------------|
| GET | `/status` | — | full dashboard snapshot (see below) |
| GET | `/devices` | — | `{ devices: Device[] }` |
| POST | `/devices/revoke` | `{ deviceId }` | `{ message }` |
| GET | `/audit` | `?limit=<1..200>` (default 50) | `{ entries: AuditEntry[] }` |
| GET | `/relay` | — | `{ active, configured, pinned, source, managedExternally, restartRequired }` |
| PUT | `/relay` | `{ url }` | `{ configured, restartRequired: true, message }` — or **409** when `managedExternally` |
| DELETE | `/relay` | — | `{ configured: null, restartRequired: true, message }` — or **409** when `managedExternally` |
| POST | `/pairing` | `{ tier?, relay? }` | pairing snapshot |
| GET | `/pairing` | — | pairing snapshot |
| POST | `/pairing/confirm` | `{ accept: boolean }` | `{ message, pairing }` |
| DELETE | `/pairing` | — | `{ message }` |

### `GET /status` value

`handlers.status()` (secret-free) with a `relay` block augmented for the panel and
the current `pairing` snapshot folded in:

```jsonc
{
  "bridgeId": "…", "bridgeVersion": "0.1.0",
  "bridgeKey": "<public key b64>", "spkiPin": "<TLS SPKI pin>",
  "listen": { "host": "127.0.0.1", "port": 8765 },
  "dsh": { "url": "http://127.0.0.1:PORT", "state": "connected" },
  "relay": {
    "url": "wss://… | null",          // running bridge's value
    "pinned": false,                   // fixed by config/env or a --relay flag
    "source": "config|env|cli | null", // which, when pinned; null otherwise
    "connectors": [ … ],
    "active": "wss://… | null",        // = url
    "configured": "wss://… | null",    // on-disk value
    "managedExternally": false,        // = pinned
    "restartRequired": false           // active !== configured AND not pinned
  },
  "stream": { … }, "devices": 2, "activeDevices": 1,
  "pairingOpen": false,
  "recentAudit": [ … ],
  "pairing": { "phase": "idle", "rev": 0 }
}
```

`restartRequired` is how the panel warns that a relay change made via the panel is
persisted but the running bridge won't adopt it until restart — identical to the
CLI's behavior.

**When the relay is externally pinned (`pinned: true`).** If the running bridge got
its relay from plugin/profile config, the `DSH_MOBILE_BRIDGE_RELAY` env var, or a
`--relay` flag on `start`, that value overrides the on-disk one at every start — so a
panel write can never take effect while the pin stands. In that case:

- `managedExternally` is `true` and `source` names where the relay is set
  (`config` | `env` | `cli`), so the UI can tell the operator where to change it;
- `restartRequired` stays `false` **even when `active !== configured`**, because a
  restart would re-apply the pin, not the on-disk value — reporting `true` here would
  be a false promise (this is the bug this behavior fixes);
- `PUT`/`DELETE /relay` are refused with **409 `conflict`** and a message naming the
  external source, and **nothing is written to disk** — the panel does not persist a
  value that could never take effect. The UI should render the relay read-only and
  surface the message rather than offer a save/clear that would 409.

When not pinned (the default — the operator saved the relay via the panel or CLI, or
there is none), behavior is unchanged: the on-disk value is authoritative, the panel
edits it freely, and `restartRequired` is `active !== configured`.

### `Device` (from `GET /devices`)

```jsonc
{ "deviceId": "…", "label": "…", "tier": "default|extended",
  "pairedAt": 1690000000000, "lastSeenAt": 1690000000000 | null,
  "revokedAt": 1690000000000 | null, "relayRoute": false }
```

### Relay validation (`PUT /relay`)

Mirrors the CLI `relay` command exactly: `wss://` for a real relay; `ws://`
accepted only for `127.0.0.1`/`localhost` (local testing). Anything else → 400.
When the relay is not externally pinned, the value is persisted immediately and
`restartRequired: true`. When it **is** pinned (`managedExternally`), the mutation is
refused with 409 before any validation or write — see the pinned note above.

<!-- APPEND_MARKER_4 -->

### Pairing is pull-based (poll `GET /pairing`)

A browser cannot hold the pairing stream open the way the CLI does over the
control socket, so the push-based `beginPair` is adapted into a pollable snapshot.
The flow:

1. `POST /pairing { tier, relay }` opens a window and returns the first snapshot.
   The QR `uri` may **not** be present yet (relay mode registers the rendezvous
   first). Poll `GET /pairing` until `uri` appears or `phase` is `failed`.
2. When a phone claims the token, `phase` becomes `claimed` and `sas` is present —
   the operator compares the 6 digits against the phone.
3. `POST /pairing/confirm { accept: true|false }` forwards the decision.
   `accept:true` → `phase: done`; `accept:false` → `phase: failed`.
4. `DELETE /pairing` cancels an in-flight window. An abandoned window also
   self-terminates when the 120 s token TTL lapses (no polling required).

Pairing snapshot shape (`PanelPairingSnapshot`):

```jsonc
{
  "phase": "idle|open|claimed|done|failed",
  "uri": "dshm://pair?…",        // from `open` onward; the QR to render
  "expiresAt": 1690000000000,     // epoch ms the window closes
  "sas": "123456",                // in `claimed`: the code to compare
  "deviceId": "…", "label": "…",  // in `claimed`/`done`
  "tier": "default|extended",
  "relay": false,
  "grantedTier": "default",       // in `done`
  "reason": "…",                  // in `failed`, never a secret
  "rev": 7                        // monotonic; distinguishes a new snapshot from a repeat
}
```

There is never a bare `token` field. `confirm` when nothing is awaiting → 409.

---

## 5. Where the code lives

| Concern | File |
|---------|------|
| Transport-agnostic API logic | `bridge/src/panel/api.ts` (`PanelApi`) |
| Pull-based pairing adapter | `bridge/src/panel/pairing.ts` (`PanelPairingController`) |
| HTTP fence + static delivery | `bridge/src/panel/server.ts` (`PanelServer`) |
| Same-origin route mount | `bridge/src/panel/mount.ts` (`attachPanel`) |
| Dedicated loopback listener | `bridge/src/panel/mount.ts` (`mountPanel`) |
| Plugin wiring + mode choice (`ctx.effect`) | `plugins/dsh-bridge/src/index.ts` |
| **UI (primary agent owns)** | `plugins/dsh-bridge/panel-ui/` |
| Core tests | `bridge/tests/panel-api.test.ts` |
| Fence tests, both mounts (real listener) | `bridge/tests/panel-server.test.ts` |
| Loads-under-real-`dsh web` | `bridge/tests/dsh-plugin-loader.test.ts` + `plugins/dsh-bridge/scripts/integration-test` |

<!-- APPEND_MARKER_5 -->

---

## 6. Upstream client-injection: what is supported, and what we chose

This section records the upstream research the delivery choice rests on, with file
citations into the pinned upstream tree (`dsh` 0.1.0-rc.5, upstream commit
`47f9438`, checked out at `/private/tmp/deepseek-harness-upstream.uJWWHk`). The task
was explicit: implement the *real* client-injection contract if one exists; if it
does not, document the blocker and ship the closest safe delivery. **A supported
contract exists, and the panel uses it.**

### The two client-injection surfaces upstream offers

**Surface 1 — server-side routes on the shared webserver (what the panel uses).**
`ctx.webServer` is a first-class Cordis service
(`packages/host/webserver/src/index.ts`). Any plugin that lists `inject:
['webServer']` may call:

```ts
webServer.register({ kind: 'exact' | 'prefix', path, handler }): () => void
```

Verified facts that make this safe and correct for the panel:

- The handler is passed the **raw** `IncomingMessage`/`ServerResponse`
  (`index.ts:149–156`). `req.url` keeps the full `/mobile-bridge/...` path and
  `req.socket.remoteAddress` survives, so `PanelServer.handle` matches its base path
  and the **loopback-peer fence works unchanged** on the shared listener.
- `kind: 'prefix'` claims `path` and everything under `path/`, longest-prefix-wins
  after an exact-table miss (`index.ts:242–251`). One `register` at
  `/mobile-bridge` captures the whole panel subtree.
- There is **no first-party allowlist**: `register` throws only on a duplicate
  `(kind, path)` (`index.ts:94–101`), so an out-of-tree profile plugin is a
  first-class route owner — no dsh source change, no patch to a route registry.
- The bind host is `'127.0.0.1' | '0.0.0.0'` only (`index.ts:46–49, 60–63`); dsh
  never binds a routable interface implicitly. When it is `127.0.0.1`, the
  same-origin route is only locally reachable to begin with.

This is exactly how in-tree plugins expose HTTP (e.g. `packages/client/connection`
registers its routes the same way). Registering the panel here is the sanctioned
mechanism, not a workaround.

**Surface 2 — a prebuilt SPA client bundle (deliberately NOT used for the panel).**
A plugin may declare `dsh.client: { platform: 'web' }` with an `exports["./client"]`
entry pointing at a prebuilt bundle; dsh composes those into `window.__DSH_BOOT__`
and serves them at `/plugins/<id>/client.js`, and the bundle registers SPA slots via
`ctx.slots.register` / `ctx.conversationEvents.register`. We did **not** put the
panel here, for two decisive reasons:

1. **It cannot safely carry the bearer token.** The SPA bundle is served to *every*
   client that can reach dsh's webserver — including LAN clients when dsh binds
   `0.0.0.0`. Injecting the panel's per-boot token into that bundle would hand the
   panel credential to the LAN, defeating the entire fence. The token may only be
   delivered by a handler that has already applied the loopback + Host checks, i.e.
   Surface 1.
2. **It requires a build step and is SPA UI code.** The bundle must be produced by a
   bundler (tsdown) and shipped prebuilt, which conflicts with this repo's
   zero-build, `--experimental-strip-types` ethos, and the SPA screen code is the
   primary agent's domain, not the backend's.

### What we chose, and why it is the safe reconciliation

The panel uses **Surface 1**: a same-origin prefix route at `/mobile-bridge` when dsh
is loopback-bound, falling back to a dedicated `127.0.0.1` listener when dsh binds
the LAN. Both paths reuse the identical `PanelServer.handle` fence, so the security
boundary is the same regardless of mount:

- On the same-origin route, a non-loopback peer is refused **403 at check #1** before
  any handler runs — the panel HTML and token are never sent to a LAN client.
- On a LAN-bound dsh, the plugin does not even offer the panel on dsh's listener; it
  binds a separate `127.0.0.1` socket that a LAN client cannot open at all.

This satisfies both halves of the task at once: it is the *real* upstream injection
contract (Surface 1, `webServer.register`), and it keeps management endpoints
loopback-only. It is proven end to end under a real `dsh web` by
`plugins/dsh-bridge/scripts/integration-test` step 4, which loads the plugin via the
real installer, then asserts the panel is served **by dsh's own webserver** at
`/mobile-bridge/` with the token-gated fence, and that no dedicated listener came up.

### Residual gaps / not-done (by design)

- **No SPA nav entry / link into the panel from the dsh web UI.** Adding a
  "Mobile bridge" item to dsh's own navigation would require a Surface-2 client
  bundle (build step + SPA code owned by the primary agent). The panel is reachable
  by URL (`<dsh-origin>/mobile-bridge/`); a nav link is a UI affordance the primary
  agent can add later via the Surface-2 hook described above, linking to that same
  path — **without** embedding the token, which the panel still delivers itself
  through the fenced route. Documented here so it is a known, deliberate omission,
  not an oversight.
- **Point-in-time compatibility.** All of the above is verified against upstream
  `47f9438`. It is one revision, not a standing guarantee; the deterministic guard
  is `bridge/tests/dsh-plugin-loader.test.ts` and the live check is the integration
  script.

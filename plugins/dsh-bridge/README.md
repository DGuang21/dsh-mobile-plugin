# dsh mobile bridge

Serves a paired phone an authenticated, policy-gated view of a dsh workstation.

Two ways to run it. Both start the same `buildBridge()`:

| | How | When |
|---|---|---|
| **Standalone** | `scripts/bridge start` | Anything. No dsh install changes. **Tested.** |
| **In `dsh web`** | `scripts/install-into-profile` | You want it to boot and die with dsh. **Integration-tested against upstream `47f9438`; see [docs/DSH_PLUGIN_INTEGRATION.md](../../docs/DSH_PLUGIN_INTEGRATION.md).** |

## Quick start, standalone

```bash
# dsh must already be running on 127.0.0.1:3080
./scripts/bridge start --host 0.0.0.0

# in a second terminal
./scripts/bridge pair
```

`pair` prints a QR payload and a 6-digit code. Scan the payload with the app, then
confirm that the code on the phone matches the one in your terminal. It will not
pair without that confirmation, and the window closes after 120 seconds.

```bash
./scripts/bridge list      # paired devices, tier, last seen
./scripts/bridge status    # dsh link, relay connectors, stream stats, recent audit
./scripts/bridge revoke <device-id>
```

`revoke` requires a running bridge. It refuses to edit the registry offline
because revocation's job is to drop live sockets and tunnels, and a bridge that
is not running cannot do that. Stopping the bridge cuts all access anyway.

## What the bridge is for

dsh's `/api` has no authentication. Its trust check is a reachability policy, and
upstream says so: anything that can reach `/api` can execute code as the
workstation user. So the bridge does not proxy `/api`. It terminates the phone's
connection, authenticates it, decides what it may ask, and only then forwards.

Four controls, in the order a request meets them:

1. **TLS**, self-signed, with the SPKI pinned by the phone from the pairing QR.
2. **Device authentication.** Per-device Ed25519 key, established by a one-shot
   120-second token plus operator SAS confirmation. Access tokens are in-memory,
   short-lived, and rotate when a stream connects.
3. **Method policy.** A hard deny list covering the 15 methods dsh itself pins to
   loopback, over a known-method allow list. An unknown method is refused rather
   than forwarded — a method we have not audited is not a method a phone gets.
4. **Audit.** Every pairing, auth, rpc, and approval decision, with a payload
   digest.

Revocation is immediate: it deletes the device's tokens, drops its streams, and
stops its relay connector.

## Running inside `dsh web`

```bash
./scripts/install-into-profile web
```

This runs `dsh plugin add`, which installs this package into the profile and
activates it because `package.json` declares `dsh.bundle.patch`. On the next boot,
`cordis.patch.yml` inserts the `mobile-bridge` row.

`install-into-profile` is the human-facing wrapper (it prompts before touching a
profile). The automated, hermetic version of exactly this path — `dsh plugin add`
→ `dump-config` → boot `dsh web` → `GET /m1/health` → assert `dshState: connected`
— is `scripts/integration-test`, and it has been run against a real `dsh web`. See
[docs/DSH_PLUGIN_INTEGRATION.md](../../docs/DSH_PLUGIN_INTEGRATION.md).

**It does not change your webserver host or port.** There is no `webserver` row in
the patch, and there must never be one: a patch replaces the targeted row's whole
config, so naming that row would silently override the operator's bind. The plugin
reads dsh's bind through `ctx.webServer` instead. The bridge always listens on its
own port with its own TLS identity — sharing dsh's listener would put the phone's
surface behind dsh's trust fence, which is exactly what this design refuses.

Configuration is by environment, so the patch needs no editing:

| Variable | Default |
|---|---|
| `DSH_MOBILE_BRIDGE_STATE_DIR` | `$DSH_HOME/mobile-bridge` |
| `DSH_MOBILE_BRIDGE_HOST` | `127.0.0.1` |
| `DSH_MOBILE_BRIDGE_PORT` | `8765` |
| `DSH_MOBILE_BRIDGE_RELAY` | unset (LAN only) |

Verify before booting:

```bash
dsh --profile web dump-config | grep -A 8 mobile-bridge
```

Pairing is not available in-process — there is no terminal attached to a plugin to
show a SAS on. Use `scripts/bridge pair`, which talks to the running bridge over
its control socket.

## Reaching the workstation from outside the LAN

```bash
./scripts/bridge relay wss://your-relay.example/relay/v1
```

The relay is treated as hostile. It routes opaque sealed records between two ids
and never holds a key, stores nothing, and has no account or admin surface. Frames
are sealed end to end with X25519 ephemerals, pinned Ed25519 statics, and
AES-256-GCM; crypto is fail-closed, and a record that fails to open drops the
connection rather than degrading. The sealing construction is Noise-IK-*shaped*
but is **[OUR DESIGN]**, not a Noise implementation, and has not had external
review.

## Runtime requirements

Node 22 is a hard floor, not a preference. The bridge uses `node:crypto` for
Ed25519, X25519, and AES-256-GCM, and runs its TypeScript entry point directly
under `--experimental-strip-types`. There is no build step and there are zero
runtime dependencies, which is why it can live in a tree shared with Expo.

The entry point is the repo-root CLI, not a file in this directory:

```bash
node --experimental-strip-types bridge/src/cli.ts start   # from the repo root
```

`scripts/bridge` is a thin wrapper around exactly that. `start` is the
long-running process; every other subcommand talks to it over the control socket.

## CLI commands

| Command | What it does |
|---|---|
| `start` | Run the bridge. Idempotent per state dir; refuses a second instance on the same control socket. |
| `pair` | Open a 120-second pairing window, print the QR payload, and require the operator to confirm a 6-digit SAS. |
| `list` | Paired devices, scope tier, last-seen time. |
| `revoke <device-id>` | Revoke a device. Requires a running bridge so live sockets and tunnels are actually dropped. |
| `status` | Bridge identity, dsh link state, relay connectors, stream stats, recent audit entries. |
| `relay [url]` | Show or set the relay URL used for out-of-LAN reachability. `relay off` clears it. |
| `paths` | Print the `/m1` route table as JSON — useful when writing a client without the docs open. |
| `version` | Print the bridge version. |

`pair --relay` needs a relay configured first (`relay <url>`). It takes no
routing id: the rendezvous id is derived from the pairing token, so the phone
needs nothing known in advance. See §12 of `docs/FRONTEND_CONTRACT.md`.

## Configuration

The two run modes are configured differently. Do not mix them up: the
`DSH_MOBILE_BRIDGE_*` variables are read by `cordis.patch.yml` and have no effect
on the CLI.

**Standalone** — CLI flags, with one environment fallback:

| Setting | Flag | Default |
|---|---|---|
| State directory | `--state-dir` (or `DSH_BRIDGE_STATE_DIR`) | `~/.dsh-mobile-bridge` |
| dsh origin | `--dsh <url>` | `http://127.0.0.1:3080` |
| Listener host | `--host <addr>` | `0.0.0.0` |
| Listener port | `--port <n>` | `8765` |
| Certificate SAN | `--cert-host <h>` (repeatable) | `localhost`, `127.0.0.1` |
| Bridge name | `--name <label>` | hostname-derived |
| Relay URL | `--relay <url>` on `start`, persisted by `relay <url>` | unset (LAN only) |
| Audit mirroring | `--echo-audit` | off |

**In `dsh web`** — environment only, so the patch needs no editing:

| Variable | Default |
|---|---|
| `DSH_MOBILE_BRIDGE_STATE_DIR` | `${DSH_HOME:-~/.dsh}/mobile-bridge` |
| `DSH_MOBILE_BRIDGE_HOST` | `127.0.0.1` |
| `DSH_MOBILE_BRIDGE_PORT` | `8765` |
| `DSH_MOBILE_BRIDGE_RELAY` | unset (LAN only) |

The state directory holds the Ed25519 identity, TLS material, device registry,
and audit log. It is created `0700`; secrets are written `0600`.

The request rate limit is 120 per minute per device. It is not exposed as a flag;
`buildBridge({ rateLimitPerMinute })` is the only way to change it.

The dsh origin should stay on loopback. Reaching `/api` is equivalent to code
execution as the workstation user, so a non-loopback dsh is a hole no bridge
setting can close.

The listener host is the bridge's own, and never changes dsh's bind. Note the
default differs by mode: standalone defaults to `0.0.0.0` because a phone on the
LAN is the point, while the plugin defaults to `127.0.0.1` because a plugin that
silently opened a LAN port on upgrade would be a surprise.

## Security model

Stated at length because installing this widens your attack surface and you
deserve to read why each control exists.

**Trust model.** The bridge is the authorization boundary. dsh's own `/api`
trust check is a reachability policy, not authentication, so the bridge
authenticates every caller itself and never exposes `/api` directly.

**Device authentication.** Ed25519 per-device keypair, established by a one-shot
120-second pairing token plus an operator-confirmed 6-digit SAS. Access tokens
are short-lived, held in memory only, and rotated when a stream connects.

**Method policy.** A hard deny list for the 15 privileged methods dsh pins to
loopback, over a known-method allow list. An unknown method is refused, never
forwarded.

**Transport.** TLS with a self-signed certificate whose SPKI the phone pins from
the pairing QR payload.

**Relay trust.** The relay forwards opaque sealed records and is treated as
hostile. Frames are sealed end to end with X25519 ephemerals, pinned Ed25519
statics, and AES-256-GCM. Crypto is fail-closed. **[OUR DESIGN]**

**Audit.** Every pairing, auth, RPC, and approval decision is appended to an
audit log with a payload digest.

## Manifests in this directory

There are two, and they are consumed by different things:

| File | Consumer | Status |
|---|---|---|
| `package.json` | `dsh plugin add`, via its `dsh.bundle.patch` declaration | Loaded by a real `dsh web` at upstream `47f9438`. **Integration-tested** — see [docs/DSH_PLUGIN_INTEGRATION.md](../../docs/DSH_PLUGIN_INTEGRATION.md). |
| `.codex-plugin/plugin.json` | Codex-style plugin hosts | Passes the local `validate_plugin.py`. Not a dsh format. |

The upstream harness at the audited revision has **no `.codex-plugin/plugin.json`
loader**. Its extension mechanism is an npm package whose `package.json` declares
`dsh.bundle.patch` pointing at a Cordis patch overlay; `dsh plugin add` installs
it into the profile and appends it to `dsh.profile.bundles`. That is the path
implemented by `package.json` and `cordis.patch.yml`.

`.codex-plugin/plugin.json` is therefore a host-agnostic descriptor, kept because
this repo's tooling validates it. It carries only the fields that validator
accepts — name, version, description, license, keywords, author, and the
`interface` block. Everything an operator actually needs (runtime, commands,
configuration, security posture) lives in this file instead, because the manifest
schema has nowhere to put it.

A third manifest, `plugins/dsh-bridge/plugin.json`, was **deleted**. It described
`src/protocol/client.ts` — the *phone's* HTTP/WebSocket client — as if that were
the plugin. It is not: the plugin is the workstation half, entered through
`src/index.ts`. The file was already inert, referenced by nothing but itself, and
a manifest that mislabels which half of the system it describes is worse than no
manifest.

## Honest status

Covered by tests (`npm run test:bridge`, 442 passing): the policy gate, pairing
including replay and SAS, auth and token rotation, RPC forwarding, stream resume
and overflow, approval serialization, relay routing and sealing, mode B first
pairing over a real relay process, and a whole-composition end-to-end path over
real TLS against a fake dsh. The plugin's own load contract — `apply()` starting
the bridge to `dshState: connected` and its disposer stopping it — is covered
deterministically by `bridge/tests/dsh-plugin-loader.test.ts`.

Verified against a **real `dsh web`** (`npm run smoke:dsh`, 18/18 passing against
upstream `0.1.0-rc.5`, commit `47f9438`, on 2026-08-16): the `/api` envelope and its
error taxonomy, all 15 deny-list methods existing upstream, the 426 WebSocket upgrade
for event streams, and the whole bridge pairing and forwarding an RPC to the real
server with the policy gate refusing a method that server would have answered. See
[docs/REAL_DSH_SMOKE.md](../../docs/REAL_DSH_SMOKE.md) to reproduce.

Verified as a **plugin under a real `dsh web`** (`scripts/integration-test`, PASS
against the same `47f9438`, on 2026-08-16): `dsh plugin add` links the package and
reconciles `dsh.profile.bundles`, `cordis.patch.yml` composes the `mobile-bridge`
row into the tree, the Cordis loader mounts `src/index.ts`, and the in-process
bridge reaches `dshState: connected` on its own TLS listener. No source change was
needed. See [docs/DSH_PLUGIN_INTEGRATION.md](../../docs/DSH_PLUGIN_INTEGRATION.md).

Not verified:

- **Any dsh revision other than `47f9438`.** That compatibility result is
  point-in-time; `/api` and the bundle format are pre-1.0. The unit suite still
  runs against `FakeDshServer`, a model of upstream rather than upstream.
- **The relay path against real dsh.** The smoke and integration tests cover the
  LAN composition; the plugin integration test runs with no relay configured.
- **A real phone.** The RN app is not part of this test surface.
- **In-process pairing.** Pairing needs an operator SAS and stays in the CLI; the
  plugin serves already-paired devices, so the integration test asserts load and
  connection, not a pairing.
- **`.codex-plugin/plugin.json` against a real host.** It passes the local
  validator. No plugin host has loaded it.
- **Windows.** The control socket is a Unix socket.

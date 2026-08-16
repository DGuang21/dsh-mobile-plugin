# dsh plugin integration

This is the companion to [`REAL_DSH_SMOKE.md`](./REAL_DSH_SMOKE.md). That one
proves the bridge's *dsh-facing* half against a real server. This one proves the
other direction: that a real `dsh web` **loads this repo's `plugins/dsh-bridge`
package as a plugin** and the in-process bridge it starts connects back to its
host dsh.

Until now that path carried `[NOT INTEGRATION-TESTED]` everywhere. It no longer
does — see "Result of the last run" below. The claim rests on one script,
`plugins/dsh-bridge/scripts/integration-test`, which runs the actual upstream
mechanism end to end and asserts on what came back. It takes no shortcuts and
mocks nothing.

## Result of the last run

| | |
|---|---|
| Upstream tree | `/private/tmp/deepseek-harness-upstream.uJWWHk` |
| Upstream version | `0.1.0-rc.5` |
| Upstream commit | `47f943859bef60e4160492346772ded9b24f765a` (`47f9438`) |
| Run date | 2026-08-16 |
| Node | v22.22.3 |
| pnpm | 11.7.0 |
| Result | **PASS — plugin loaded, bridge reached `dshState: connected`** |

Observed `GET /m1/health` on the bridge's own TLS listener, served from inside
`dsh web`:

```json
{"ok":true,"protocol":1,"bridgeId":"7dcc419b-…","bridgeName":"dsh bridge",
 "bridgeVersion":"0.1.0","dsh":"up","dshState":"connected",
 "uptimeSeconds":1,"pairedDevices":0}
```

`dshState: connected` is the load-and-start observation: the plugin's `apply()`
ran under Cordis, `buildBridge()` executed, the bridge bound its own port, and it
completed the readiness handshake against the host dsh's `/api`. **No source
change to the plugin or the bridge was needed** to make this work — the package
as committed loads as-is.

Like the smoke test, this is point-in-time against one revision, not a standing
guarantee. Re-run it when upstream moves.

## The mechanism, as verified from upstream source

The extension mechanism is an npm package whose `package.json` declares
`dsh.bundle.patch`. There is **no `.codex-plugin/plugin.json` loader** upstream at
this revision; that file is kept only because this repo's own tooling validates
it. The path that actually runs is:

1. **`dsh plugin --profile <p> add <spec>`** is a thin pnpm forwarder
   (`apps/cli/src/plugin.ts`). It initializes the profile on first use, runs
   `pnpm <args>` in `$DSH_HOME/profiles/<p>`, then **reconciles**
   `dsh.profile.bundles`: any dependency that resolves to a package declaring
   `dsh.bundle` is appended to the layer list. Reconciliation is by installed
   state, not dependency diff, so a package that gains `dsh.bundle` in a later
   version activates on `update`.

   A **local directory spec links, it does not copy.** pnpm records
   `@deepseek-ai/dsh-mobile-bridge: link:<abs path to plugins/dsh-bridge>` and
   symlinks it into the profile's `node_modules`. The source checkout builds a
   standalone `dist/index.js` before installation, so the same package also
   works when downloaded from a Release rather than linked back to this repo.

2. **On boot**, `loadProfile` (`packages/boot/app-boot/src/profile.ts`) resolves
   each bundle to its `cordis.patch.yml` and stacks the patches over an empty
   root (`apps/cli/src/profile-boot.ts`). Our `cordis.patch.yml` carries a single
   `insert` of the `mobile-bridge` row — no `webserver` row, by design, so it
   cannot restate the operator's bind.

3. **The Cordis loader mounts the row.** The row's `name` is the package name;
   the loader dynamically `import()`s the package `main`. Our `main` is
   `dist/index.js` — the standalone bundle produced by `npm run plugin:build`.
   `apply(ctx, config)`
   reads dsh's real bind through the injected `ctx.webServer`, dials it over
   loopback (normalizing `0.0.0.0`), and starts `buildBridge()` inside a
   `ctx.effect` whose disposer stops the bridge when dsh shuts down.

The bridge listens on its **own** port with its **own** TLS identity. It never
registers a route on dsh's webserver, so exposing the bridge to the LAN never
exposes dsh's unauthenticated `/api`.

## Reproducing it

The upstream tree must be built once (three steps, same as the smoke test — each
is there because skipping it produces a specific failure):

```bash
cd /private/tmp/deepseek-harness-upstream.uJWWHk
pnpm install --frozen-lockfile   # ~22s
npm run build:lib:host           # else: dsh-client-ui-trajectory/lib/index.js not found
npm run build:lib:client         # same family of missing lib/ resolutions
npm run build:web                # else: "web-app: frontend dist not built"
```

Then, from this repo, run the one script:

```bash
cd /Users/daguang/project/deepseek-harness-mobile
DSH_UPSTREAM=/private/tmp/deepseek-harness-upstream.uJWWHk \
  plugins/dsh-bridge/scripts/integration-test
```

It is hermetic: a throwaway `$DSH_HOME`, a throwaway bridge state dir, and free
ephemeral ports, all removed on exit. It never touches your real dsh state.

Finding dsh (first hit wins): `$DSH_BIN` (a `dsh` executable or its `bin.js`),
then `$DSH_UPSTREAM` (a built checkout — uses `<root>/apps/cli/lib/bin.js`), then
`dsh` on `PATH`, then the documented upstream tree above.

Exit codes match `smoke:dsh`, so it gates the same way:

| Code | Meaning |
|---|---|
| `0` | every assertion passed — the plugin loaded and the bridge connected |
| `1` | an assertion failed — a real incompatibility; the blocker is printed |
| `2` | skip — no runnable dsh, or the upstream tree is not built; not a failure |

Because a skip is exit 2 and the whole thing needs a built external tree, it is
deliberately **not** wired into `npm run verify`, exactly like `smoke:dsh`.

## What runs in CI instead

`bridge/tests/dsh-plugin-loader.test.ts` is the deterministic guard that runs in
`npm run test`. It imports the plugin's real exports — `name`, `inject`,
`apply` — and runs `apply(ctx, config)` unmodified against a hand-written
`MinimalContext` and the same `FakeDshServer` the rest of the suite uses. It
asserts the plugin's contract: it starts the bridge, the bridge reaches
`dshState: connected`, `0.0.0.0` is normalized to loopback for outbound calls,
and the `ctx.effect` disposer stops the listener.

It mocks only Cordis's `Context` (that package is not, and must not become, a
dependency of this repo). So a green run proves the **plugin's own code** is
correct against the contract; it does **not** prove the Cordis loader resolves
and mounts it. That is precisely the gap the integration script closes, and why
both exist.

## What this still does not prove

- Compatibility with any upstream revision other than `47f9438`. `/api` and the
  bundle format are pre-1.0.
- Pairing in-process. Pairing needs an operator SAS and stays in the CLI
  (`scripts/bridge pair`) against the running bridge's control socket; the plugin
  serves already-paired devices. The full pair → rpc path against real dsh is
  covered by `smoke:dsh`, not here.
- The relay path under the plugin. The integration test is LAN-only
  (`DSH_MOBILE_BRIDGE_RELAY` unset).
- Windows. The control socket is a Unix socket.

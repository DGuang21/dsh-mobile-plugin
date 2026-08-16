# Real dsh smoke test

Everything else in this repo tests the dsh seam against `FakeDshServer`, which
reproduces the envelope rules we verified by *reading* upstream source. That is a
model of upstream, not upstream. This document is how you check the model against
the real thing.

`bridge/scripts/smoke-real-dsh.ts` is the only test in the repo that can support a
compatibility claim. It uses `DshApiClient`, `DshDownlink`, and `buildBridge`
unmodified, over a real socket, against a real `dsh web`.

## Result of the last run

| | |
|---|---|
| Upstream tree | `/private/tmp/deepseek-harness-upstream.uJWWHk` |
| Upstream version | `0.1.0-rc.5` |
| Upstream commit | `47f943859bef60e4160492346772ded9b24f765a` (2026-08-13) |
| Run date | 2026-08-16 |
| Node | v22.22.3 |
| pnpm | 11.7.0 |
| Result | **18/18 checks passed** |

That run is what the bounded compatibility claim in
[`FRONTEND_CONTRACT.md`](./FRONTEND_CONTRACT.md) §14 rests on. It is a point-in-time
result against one revision, not a standing guarantee: re-run it when upstream moves.

## Reproducing it

Upstream is a pnpm workspace and needs three build steps before the CLI will boot.
Each one below is there because skipping it produces a specific failure, noted after
the command.

```bash
cd /private/tmp/deepseek-harness-upstream.uJWWHk

pnpm install --frozen-lockfile   # ~22s
npm run build:lib:host           # else: dsh-client-ui-trajectory/lib/index.js not found
npm run build:lib:client         # same family of missing lib/ resolutions
npm run build:web                # else: "web-app: frontend dist not built"

# A throwaway DSH_HOME keeps the smoke run out of your real dsh state.
DSH_HOME=/tmp/dsh-smoke-home node apps/cli/lib/bin.js web --host 127.0.0.1 --port 13080
```

Wait for `dsh web: http://127.0.0.1:13080`, then in this repo:

```bash
cd /Users/daguang/project/deepseek-harness-mobile
npm run smoke:dsh                       # defaults to http://127.0.0.1:13080
npm run smoke:dsh -- http://127.0.0.1:9000   # or point it somewhere else
```

`$DSH_SMOKE_URL` also works. Exit codes: `0` every check passed, `1` a check failed,
`2` the server was unreachable — a skip, not a bridge failure, which is why this is
not wired into `npm run verify`.

## What the 18 checks cover

The first fifteen exercise the bridge's dsh-facing half directly:

- **Envelope shape** — `host.describe`, `session.list`, and `workspace.list` return
  what `validateServerResponse` expects, including the rpcId correlation check.
- **The 200-vs-carrier split** — a business error (`session-not-found`) arrives as
  HTTP 200 with a `ServerResponse` body; `callOrThrow` folds it into `DshRpcError`;
  a malformed payload is likewise a 200 business error, not a transport failure.
- **Carrier errors** — unknown method is a 404, method/path mismatch is refused,
  non-JSON content type is 415, non-JSON body is 400.
- **`respond`** — answering an unknown rpcId returns `{accepted: false, reason:
  'not-pending'}` rather than throwing.
- **The deny list** — all 15 entries in `DENIED_METHODS` exist upstream, so none of
  them is dead weight guarding a method that was never there.
- **A write path** — `session.create` then `session.list` observes the new session,
  so the client is not only verified on reads.
- **The event stream** — `GET /api/events.mux` answers 426 with `upgrade:
  websocket`, and `DshDownlink` then reads a real frame over the WebSocket.

The last three stand the **whole bridge** up in front of the real server and drive it
the way a phone does, so the forwarded RPC lands on real dsh rather than on a fake:
`/m1/health` reaching `dshState: connected`; a full pair → confirm → challenge →
signature → `/m1/rpc session.list`; and the policy gate answering 403 `method-denied`
to `settings.describe`, a method the real server would happily have answered.

## Two findings worth keeping

**`host.pickDirectory` blocks forever on a real host.** It opens a native directory
dialog and does not return until a human answers. The deny-list probe treats a
3-second timeout as *present* — routing precedes dispatch upstream, so an absent path
404s immediately — and reports it as a live demonstration of why the method is
denied. A phone that could call it would hang the workstation's harness.

**The shipped Web composition requires a WebSocket upgrade for event streams.**
`packages/client/connection/src/index.ts:152` intercepts `GET /api/events.mux` and
`/api/events.host` and answers 426. `toFetchHandler`'s SSE codec only serves the
in-process and Electron carriers, so any client arriving over a network socket must
upgrade. `bridge/src/dsh/downlink.ts` already implements WebSocket and cites that
file; the smoke test asserts the 426 rather than the SSE path.

## What this does not prove

- Compatibility with any revision other than `47f9438`. Upstream is pre-1.0 and
  `/api` is not a stability contract.
- Anything about the RN app. The phone side of every check here is this repo's own
  HTTP and WebSocket client code, not the Expo app. [NOT INTEGRATION-TESTED]
- The relay path end-to-end against real dsh. The relay checks live in
  `bridge/tests/relay-*.test.ts` and use the local backend.

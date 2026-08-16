# DeepSeek Harness Mobile

An Expo/React Native control surface for a dsh-compatible coding agent gateway. It is designed for the “Happy Coder” workflow: keep an agent running on a workstation or server, then inspect sessions, stream output, approve tools, and send the next instruction from a phone.

## Run

```bash
npm install
cp .env.example .env
npx expo start
```

The app starts in demo mode when no server URL is configured. Open Settings to connect a real gateway. The bridge defaults to the contract documented in [`docs/API_RESEARCH.md`](docs/API_RESEARCH.md), with configurable paths in `src/protocol/client.ts`.

## Plugin releases

The workstation plugin is built as a standalone Node 22 ESM bundle. Build and
verify it locally with:

```bash
npm run plugin:pack
```

Pushing a `v*` tag whose version matches `plugins/dsh-bridge/package.json`
triggers the full CI suite, builds the `.tgz`, and publishes it to the matching
GitHub Release. The Release asset is the downloadable plugin package; the
Actions artifact is retained only as a short-lived CI copy.

## Project layout

- `src/protocol`: typed dsh-compatible HTTP/WebSocket bridge and event normalization.
- `src/state`: session state reducer used by the chat screen and tests.
- `app`: Expo Router screens for sessions, a live session, activity, and settings.
- `plugins/dsh-bridge`: plugin manifest and integration notes for embedding the bridge in another host.

## Security

Tokens are stored with `expo-secure-store` on device. Do not put production credentials in `.env` committed to source control. For a phone to reach a workstation, use a private VPN or an authenticated reverse proxy; do not expose an unauthenticated agent port to the public internet.

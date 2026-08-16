# DeepSeek Harness / dsh API research

## What is verified

As of 2026-08-15, there is no public, stable API specification for a product named “DeepSeek Harness” or “dsh” that can be verified from the local workspace. Claude Code was asked to research the surface and explicitly reported that it could not verify a public project or endpoint schema. The repository also contains no dsh source, OpenAPI document, or SDK.

The app therefore treats dsh as a configurable, self-hosted agent gateway. The adapter is deliberately tolerant: unknown event fields are preserved under `raw`, and endpoint paths can be overridden in one place.

## Compatibility contract implemented here

The default contract follows conventions used by mobile agent clients and OpenAI/Anthropic-compatible gateways. It is an integration target, not a claim about an official DeepSeek API.

| Operation | Default request | Expected response |
| --- | --- | --- |
| Health | `GET /health` | `{ ok: boolean, version?: string }` |
| Sessions | `GET /v1/sessions` | `{ sessions: Session[] }` or `Session[]` |
| Create session | `POST /v1/sessions` with `{ title?, cwd?, model? }` | `Session` |
| Send prompt | `POST /v1/sessions/:id/messages` with `{ content, attachments? }` | message/ack, optionally streamed |
| Approve tool | `POST /v1/sessions/:id/approvals/:approvalId` with `{ decision }` | `{ ok: true }` |
| Events | WebSocket `GET /ws?sessionId=:id` | JSON event envelopes |

Supported event names are `message.delta`, `message.completed`, `tool.requested`, `tool.completed`, `approval.requested`, `approval.resolved`, `session.updated`, and `error`. A server may send `type`, `event`, or `kind`; the adapter normalizes all three.

## Authentication and transport

The bridge sends `Authorization: Bearer <token>` when a token is configured. It never logs or persists the token in AsyncStorage; the production app stores it in `expo-secure-store`. WebSocket auth uses the same bearer as a subprotocol (`bearer,<token>`) and query-free headers where the platform supports them.

## What must be confirmed against a real dsh server

1. Exact route prefixes and whether sessions are called runs/tasks.
2. The server's WebSocket upgrade/auth mechanism and heartbeat interval.
3. Tool/approval payload fields, especially the command preview and expiry.
4. Whether streaming is SSE, WebSocket, or chunked HTTP for prompt responses.
5. Resume/reconnect semantics and server-side event IDs.

The adapter exposes `paths` and `parseEvent` so these differences can be mapped without changing the UI.

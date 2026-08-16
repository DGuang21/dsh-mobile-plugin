#!/usr/bin/env -S node --experimental-strip-types
/**
 * Bridge CLI.
 *
 * Runs *beside* `dsh web`, never in place of it, and never reconfigures it. That
 * constraint shapes the whole design:
 *
 *   - The bridge is a separate process with its own port. Nothing here writes dsh
 *     settings, changes its bind address, or asks it to listen anywhere new.
 *   - The bridge reaches dsh over loopback as an ordinary `/api` client, exactly as
 *     the upstream web UI does.
 *   - If dsh is not running, the bridge starts anyway and reports `dsh: down`. It
 *     refuses to pair until dsh answers, so nobody pairs into a dead bridge.
 *
 * Why the bridge exists at all rather than exposing `dsh web` to the LAN: reaching
 * `/api` is equivalent to arbitrary code execution as the workstation user, and
 * upstream's `isTrustedApiRequest` is a reachability policy, not authentication.
 * Binding dsh to `0.0.0.0` would put that on the network unauthenticated.
 *
 * Commands: start, pair, list, revoke, status, relay.
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { BRIDGE_VERSION, buildBridge } from './bridge.ts';
import { connectControl, readResponses, type ControlResponse } from './control.ts';
import { buildPairingUri, PAIRING_TOKEN_TTL_MS } from './identity/pairing.ts';
import { DeviceRegistry } from './identity/registry.ts';
import { IdentityStore } from './identity/store.ts';
import { M1_PATHS } from './m1/wire.ts';

const DEFAULT_STATE_DIR = join(homedir(), '.dsh-mobile-bridge');
const DEFAULT_DSH_URL = 'http://127.0.0.1:3080';
const DEFAULT_PORT = 8765;

interface Flags {
  positional: string[];
  values: Map<string, string>;
  booleans: Set<string>;
}

/**
 * Parse `--key value`, `--key=value`, and `--flag`.
 *
 * Hand-rolled rather than pulled from npm: this is thirty lines, and the
 * dependency budget for a tree shared with an Expo app is better spent elsewhere.
 */
function parseFlags(argv: string[]): Flags {
  const positional: string[] = [];
  const values = new Map<string, string>();
  const booleans = new Set<string>();

  for (let i = 0; i < argv.length; i += 1) {
    const argument = argv[i] as string;
    if (!argument.startsWith('--')) {
      positional.push(argument);
      continue;
    }
    const body = argument.slice(2);
    const equals = body.indexOf('=');
    if (equals !== -1) {
      values.set(body.slice(0, equals), body.slice(equals + 1));
      continue;
    }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      values.set(body, next);
      i += 1;
      continue;
    }
    booleans.add(body);
  }
  return { positional, values, booleans };
}

function stateDirFrom(flags: Flags): string {
  return flags.values.get('state-dir') ?? process.env.DSH_BRIDGE_STATE_DIR ?? DEFAULT_STATE_DIR;
}

function numberFlag(flags: Flags, name: string, fallback: number): number {
  const raw = flags.values.get(name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0) {
    fail(`--${name} must be a non-negative integer`);
  }
  return value;
}

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

function out(line = ''): void {
  process.stdout.write(`${line}\n`);
}

/**
 * Ask a yes/no question on stdin.
 *
 * Uses raw `data` events rather than `node:readline`: @types/node 26 declares the
 * readline input as an async-iterable this repo's TypeScript 5.3 cannot express, and
 * the app's toolchain is not something a bridge-only concern gets to bump.
 */
function confirmPrompt(question: string): Promise<boolean> {
  return new Promise((resolve) => {
    process.stdout.write(question);
    const onData = (chunk: Buffer): void => {
      process.stdin.removeListener('data', onData);
      process.stdin.pause();
      const answer = chunk.toString('utf8').trim().toLowerCase();
      resolve(answer === 'y' || answer === 'yes');
    };
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

const USAGE = `dsh-mobile-bridge ${BRIDGE_VERSION}

Runs alongside \`dsh web\`. Does not modify dsh's configuration or bind address.

Usage:
  dsh-mobile-bridge start   [options]        Run the bridge in the foreground
  dsh-mobile-bridge pair    [options]        Open a pairing window and print a QR payload
  dsh-mobile-bridge list    [options]        List paired devices
  dsh-mobile-bridge revoke  <device-id>      Revoke a device immediately
  dsh-mobile-bridge status  [options]        Show bridge and dsh state
  dsh-mobile-bridge relay   <url|off>        Set or clear the relay this bridge dials
  dsh-mobile-bridge paths                    Print the /m1 route table as JSON
  dsh-mobile-bridge version                  Print the bridge version

Common options:
  --state-dir <path>   State directory (default ~/.dsh-mobile-bridge)
  --dsh <url>          dsh web origin (default ${DEFAULT_DSH_URL})
  --port <n>           Phone-facing HTTPS port (default ${DEFAULT_PORT})
  --host <addr>        Listen address (default 0.0.0.0; use 127.0.0.1 to stay local)
  --cert-host <h>      Extra hostname/IP for the certificate SAN (repeatable)
  --name <label>       Bridge name shown on the phone
  --echo-audit         Mirror audit entries to stderr
  --json               Machine-readable output where supported

Pairing options:
  --tier <default|extended>   Scope tier granted on confirmation (default: default)
  --relay                     Emit a relay-mode QR payload instead of LAN mode
                              (needs a relay set via \`relay <url>\`; the phone
                              needs no routing id in advance)

Environment:
  DSH_BRIDGE_STATE_DIR  Same as --state-dir
`;

// ── start ───────────────────────────────────────────────────────────────────

async function commandStart(flags: Flags): Promise<void> {
  const host = flags.values.get('host') ?? '0.0.0.0';
  const port = numberFlag(flags, 'port', DEFAULT_PORT);
  const certHosts = ['localhost', '127.0.0.1', ...collectRepeated(flags, 'cert-host')];

  const built = buildBridge({
    stateDir: stateDirFrom(flags),
    dshUrl: flags.values.get('dsh') ?? DEFAULT_DSH_URL,
    port,
    host,
    certHosts,
    ...(flags.values.get('name') === undefined ? {} : { bridgeName: flags.values.get('name') as string }),
    echoAudit: flags.booleans.has('echo-audit'),
    // A `--relay` on `start` PINS the relay for this run: it overrides the saved
    // value and the management panel cannot edit it (the panel reports it as
    // externally managed rather than promising a restart it cannot honor). Omit the
    // flag to let the panel manage the saved relay.
    ...(flags.values.get('relay') === undefined
      ? {}
      : { relayUrl: flags.values.get('relay') as string, relaySource: 'cli' as const }),
  });

  await built.start();

  out(`dsh-mobile-bridge ${BRIDGE_VERSION}`);
  out(`  bridge id      ${built.identity.bridgeId}`);
  out(`  listening      https://${host}:${port}`);
  out(`  spki pin       ${built.tlsFingerprint}`);
  out(`  bridge key     ${built.identity.publicKeyB64}`);
  out(`  dsh            ${flags.values.get('dsh') ?? DEFAULT_DSH_URL}`);
  out(`  state          ${stateDirFrom(flags)}`);
  const relay = built.identity.relayUrl ?? flags.values.get('relay');
  out(`  relay          ${relay ?? 'disabled (LAN only)'}`);
  out(`  paired devices ${built.registry.list().filter((device) => device.revokedAt === undefined).length}`);
  out();
  if (host === '0.0.0.0') {
    // Said plainly, because the whole point of the bridge is that this listener is
    // authenticated and dsh's own is not.
    out('This listener is on the LAN. Every route except /m1/health and /m1/pair/claim');
    out('requires a paired device key and a short-lived token; dsh itself is untouched');
    out('on loopback. Pair with `dsh-mobile-bridge pair` in another terminal.');
  } else {
    out(`Bound to ${host}. A phone on the LAN cannot reach this; use --host 0.0.0.0 or a relay.`);
  }
  out();

  const shutdown = (signal: string): void => {
    out(`\nreceived ${signal}, shutting down`);
    void built.stop().then(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  // Report dsh transitions: "bridge up, harness down" is the state operators hit
  // most often, and it is invisible otherwise.
  let lastState = '';
  setInterval(() => {
    const state = built.connection.getState();
    if (state === lastState) return;
    lastState = state;
    out(`dsh ${state}`);
  }, 1_000).unref?.();

  await new Promise<void>(() => {
    // Run until signalled.
  });
}

function collectRepeated(flags: Flags, name: string): string[] {
  // `Map` keeps only the last `--cert-host`, so also accept a comma-separated list.
  const single = flags.values.get(name);
  if (single === undefined) return [];
  return single
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

// ── pair ────────────────────────────────────────────────────────────────────

async function commandPair(flags: Flags): Promise<void> {
  const stateDir = stateDirFrom(flags);
  const tierRaw = flags.values.get('tier') ?? 'default';
  if (tierRaw !== 'default' && tierRaw !== 'extended') fail('--tier must be default or extended');
  const relay = flags.booleans.has('relay');
  // `--peer-routing-id` used to be required here. It asked for the phone's routing
  // id before the phone had one, so out-of-LAN first pairing was unreachable. The
  // rendezvous id is now derived from the pairing token by both sides.
  if (flags.values.has('peer-routing-id') || flags.booleans.has('peer-routing-id')) {
    fail(
      '--peer-routing-id is no longer used: relay pairing derives its rendezvous id from the pairing token.\n' +
        'Run `dsh-mobile-bridge pair --relay` on its own.',
    );
  }

  const connected = await connectControl(stateDir);
  if (!connected.ok) {
    fail(`${connected.reason}\nStart it first: dsh-mobile-bridge start`);
  }
  const socket = connected.socket;
  socket.write(`${JSON.stringify({ type: 'pair', tier: tierRaw, relay })}\n`);

  const prompt = { close: () => process.stdin.pause() };
  let exitCode = 0;

  await readResponses(socket, (message: ControlResponse) => {
    switch (message.type) {
      case 'pair-open': {
        const seconds = Math.max(0, Math.round((message.expiresAt - Date.now()) / 1000));
        out('Pairing window open. Scan this on the phone:');
        out();
        out(`  ${message.uri}`);
        out();
        out(`This token is single-use and expires in ${seconds}s (${PAIRING_TOKEN_TTL_MS / 1000}s window).`);
        out('Waiting for the phone to claim it...');
        return false;
      }
      case 'pair-claimed': {
        out();
        out(`Device claimed the token: ${message.label || '(no label)'}`);
        out(`  device id  ${message.deviceId}`);
        out();
        out(`  Comparison code:  ${message.sas}`);
        out();
        // The SAS is the entire defence against a key-substituting attacker on the
        // pairing path, so the prompt says what to compare and why.
        out('The phone is showing a 6-digit code. Confirm ONLY if it matches exactly.');
        void confirmPrompt('Codes match? [y/N] ').then((accept) => {
          socket.write(`${JSON.stringify({ type: 'pair-confirm', accept })}\n`);
        });
        return false;
      }
      case 'pair-done': {
        out();
        out(`Paired: ${message.label} (${message.deviceId}) at tier ${message.tier}`);
        return true;
      }
      case 'pair-failed': {
        out();
        out(`Pairing failed: ${message.reason}`);
        exitCode = 1;
        return true;
      }
      case 'error': {
        out(`error: ${message.message}`);
        exitCode = 1;
        return true;
      }
      default:
        return false;
    }
  });

  prompt.close();
  socket.destroy();
  process.exit(exitCode);
}

// ── list ────────────────────────────────────────────────────────────────────

async function commandList(flags: Flags): Promise<void> {
  const stateDir = stateDirFrom(flags);
  const json = flags.booleans.has('json');

  const connected = await connectControl(stateDir);
  if (connected.ok) {
    const devices = await requestOnce(connected.socket, { type: 'list' });
    connected.socket.destroy();
    printDevices(devices as DeviceRow[], json);
    return;
  }

  // Offline fallback. Reading the registry directly is safe; mutating it would not
  // be, which is why `revoke` refuses to do the same thing.
  const registry = DeviceRegistry.open(stateDir);
  const identity = IdentityStore.open(stateDir);
  const rows: DeviceRow[] = registry.list().map((device) => ({
    deviceId: device.deviceId,
    label: device.label,
    tier: device.tier,
    pairedAt: device.createdAt,
    lastSeenAt: device.lastSeenAt ?? null,
    revokedAt: device.revokedAt ?? null,
    relayRoute: identity.routeFor(device.deviceId) !== undefined,
  }));
  if (!json) out('(bridge not running; reading the registry from disk)');
  printDevices(rows, json);
}

interface DeviceRow {
  deviceId: string;
  label: string;
  tier: string;
  pairedAt: number;
  lastSeenAt: number | null;
  revokedAt: number | null;
  relayRoute: boolean;
}

function printDevices(rows: DeviceRow[], json: boolean): void {
  if (json) {
    out(JSON.stringify(rows, null, 2));
    return;
  }
  if (rows.length === 0) {
    out('No paired devices. Run `dsh-mobile-bridge pair`.');
    return;
  }
  out('DEVICE ID                             TIER      RELAY  STATUS    LABEL');
  for (const row of rows) {
    const status = row.revokedAt !== null ? 'revoked' : 'active';
    out(
      `${row.deviceId.padEnd(37)} ${row.tier.padEnd(9)} ${(row.relayRoute ? 'yes' : 'no').padEnd(6)} ${status.padEnd(9)} ${row.label}`,
    );
  }
}

// ── revoke ──────────────────────────────────────────────────────────────────

async function commandRevoke(flags: Flags): Promise<void> {
  const deviceId = flags.positional[0];
  if (deviceId === undefined) fail('revoke requires a device id (see `dsh-mobile-bridge list`)');

  const connected = await connectControl(stateDirFrom(flags));
  if (!connected.ok) {
    // Deliberately refused rather than done on disk. Revocation has to terminate
    // live streams and relay tunnels, and a file edit would leave a revoked phone
    // connected until it happened to reconnect.
    fail(
      `${connected.reason}\n` +
        'Revocation must reach the running bridge so it can drop live connections.\n' +
        'Start the bridge and retry, or stop it entirely to cut all access at once.',
    );
  }
  const result = await requestOnce(connected.socket, { type: 'revoke', deviceId });
  connected.socket.destroy();
  out(String((result as { message?: string }).message ?? 'revoked'));
}

// ── status ──────────────────────────────────────────────────────────────────

async function commandStatus(flags: Flags): Promise<void> {
  const stateDir = stateDirFrom(flags);
  const json = flags.booleans.has('json');
  const connected = await connectControl(stateDir);

  if (!connected.ok) {
    const identity = IdentityStore.open(stateDir);
    const registry = DeviceRegistry.open(stateDir);
    const offline = {
      running: false,
      reason: connected.reason,
      bridgeId: identity.bridgeId,
      bridgeKey: identity.publicKeyB64,
      relay: identity.relayUrl ?? null,
      devices: registry.list().length,
      activeDevices: registry.list().filter((device) => device.revokedAt === undefined).length,
    };
    if (json) out(JSON.stringify(offline, null, 2));
    else {
      out('bridge:  not running');
      out(`reason:  ${connected.reason}`);
      out(`id:      ${offline.bridgeId}`);
      out(`key:     ${offline.bridgeKey}`);
      out(`relay:   ${offline.relay ?? 'disabled'}`);
      out(`devices: ${offline.activeDevices} active / ${offline.devices} total`);
    }
    process.exitCode = 1;
    return;
  }

  const status = (await requestOnce(connected.socket, { type: 'status' })) as StatusPayload;
  connected.socket.destroy();
  if (json) {
    out(JSON.stringify({ running: true, ...status }, null, 2));
    return;
  }
  out(`bridge:  running (${status.bridgeVersion})`);
  out(`id:      ${status.bridgeId}`);
  out(`listen:  https://${status.listen.host}:${status.listen.port}`);
  out(`pin:     ${status.spkiPin}`);
  out(`key:     ${status.bridgeKey}`);
  out(`dsh:     ${status.dsh.state} at ${status.dsh.url}`);
  out(`relay:   ${status.relay.url ?? 'disabled (LAN only)'}`);
  for (const connector of status.relay.connectors) {
    out(`  tunnel ${connector.deviceId}  ${connector.state}  in=${connector.framesIn} out=${connector.framesOut}`);
    if (connector.lastError !== undefined && connector.lastError !== null) {
      out(`         last error: ${connector.lastError}`);
    }
  }
  out(`devices: ${status.activeDevices} active / ${status.devices} total`);
  out(`stream:  bseq ${status.stream.lastBseq}, ${status.stream.subscribers} subscriber(s), ${status.stream.pending} pending approval(s)`);
  if (status.pairingOpen) out('pairing: a window is open');
}

interface StatusPayload {
  bridgeId: string;
  bridgeVersion: string;
  bridgeKey: string;
  spkiPin: string;
  listen: { host: string; port: number };
  dsh: { url: string; state: string };
  relay: {
    url: string | null;
    connectors: { deviceId: string; state: string; framesIn: number; framesOut: number; lastError?: string | null }[];
  };
  stream: { lastBseq: number; subscribers: number; pending: number };
  devices: number;
  activeDevices: number;
  pairingOpen: boolean;
}

// ── relay ───────────────────────────────────────────────────────────────────

function commandRelay(flags: Flags): void {
  const value = flags.positional[0];
  if (value === undefined) fail('relay requires a URL or `off`');
  const store = IdentityStore.open(stateDirFrom(flags));

  if (value === 'off') {
    store.setRelayUrl(undefined);
    out('Relay disabled. Restart the bridge for this to take effect.');
    return;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return fail(`not a URL: ${value}`);
  }
  if (parsed.protocol !== 'wss:' && parsed.protocol !== 'ws:') {
    fail('relay URL must be wss:// (ws:// is accepted only for local testing)');
  }
  if (parsed.protocol === 'ws:' && parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
    // A plaintext relay would expose the sealed handshake's metadata and give an
    // on-path attacker a free denial of service. The sealed layer still protects
    // payloads, but there is no reason to accept this off the loopback.
    fail('ws:// is only allowed for 127.0.0.1 or localhost; use wss:// for a real relay');
  }
  store.setRelayUrl(value);
  out(`Relay set to ${value}. Restart the bridge for this to take effect.`);
  out('Pair with `pair --relay` to give a device a tunnel.');
}

/** Send one request, resolve its `ok` value, throw on `error`. */
async function requestOnce(socket: import('node:net').Socket, request: unknown): Promise<unknown> {
  socket.write(`${JSON.stringify(request)}\n`);
  let value: unknown;
  let failure: string | undefined;
  await readResponses(socket, (message) => {
    if (message.type === 'ok') {
      value = message.value;
      return true;
    }
    if (message.type === 'error') {
      failure = message.message;
      return true;
    }
    return false;
  });
  if (failure !== undefined) fail(failure);
  return value;
}

// ── entry point ─────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;
  const flags = parseFlags(rest);

  switch (command) {
    case 'start':
      await commandStart(flags);
      return;
    case 'pair':
      await commandPair(flags);
      return;
    case 'list':
      await commandList(flags);
      return;
    case 'revoke':
      await commandRevoke(flags);
      return;
    case 'status':
      await commandStatus(flags);
      return;
    case 'relay':
      commandRelay(flags);
      return;
    case 'paths':
      // Useful when writing a client: prints the routes without needing the docs.
      out(JSON.stringify(M1_PATHS, null, 2));
      return;
    case undefined:
    case '--help':
    case '-h':
    case 'help':
      process.stdout.write(USAGE);
      return;
    case '--version':
    case 'version':
      out(BRIDGE_VERSION);
      return;
    default:
      process.stderr.write(USAGE);
      fail(`unknown command: ${command}`);
  }
}

void main().catch((error: unknown) => {
  console.error(`error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

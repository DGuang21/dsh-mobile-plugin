/**
 * Relay entry point. `node --experimental-strip-types bridge/src/relay/main.ts`
 *
 * This is the one component meant to run somewhere the operator does not control
 * — a small VPS, a container, a friend's box. Everything about it is shaped by the
 * assumption that whoever runs it may be hostile:
 *
 *   - It never holds a key and cannot decrypt. It moves sealed records between two
 *     routing ids and that is the whole program.
 *   - It stores nothing. No accounts, no database, no log of who talked to whom.
 *   - It has no admin surface. There is nothing to authenticate to, so there is no
 *     credential to steal and no privileged endpoint to find.
 *   - `/relay/health` returns liveness and a peer count. Nothing else is exposed.
 *
 * TLS TERMINATION IS INTENTIONALLY NOT HERE
 *
 * Run this behind a reverse proxy that terminates TLS (Caddy, nginx, a load
 * balancer). Not because relay TLS would be hard, but because the relay is not a
 * confidentiality boundary: the records are already sealed end to end, and TLS on
 * this hop protects metadata, not content. Making the relay own certificates would
 * add renewal, private key storage, and a reason to give it filesystem trust — all
 * for a hop whose payload is already opaque to it. Let the proxy do proxy things.
 *
 * The phone still verifies the relay's TLS as a transport matter, and the seal is
 * what actually authenticates the bridge. A relay that swapped itself in learns
 * nothing: the bridge's static Ed25519 key is pinned in the pairing payload.
 */

import { RelayServer } from './server.ts';

interface Options {
  port: number;
  host: string;
  maxPeers: number;
  frameRatePerMinute: number;
  verbose: boolean;
}

function usage(): string {
  return [
    'dsh mobile relay',
    '',
    'Forwards sealed frames between a bridge and a phone. Holds no keys, stores',
    'nothing, and cannot read what it carries.',
    '',
    'Usage:',
    '  relay [options]',
    '',
    'Options:',
    '  --port <n>          Listen port (default 8787, or $PORT)',
    '  --host <addr>       Listen address (default 0.0.0.0)',
    '  --max-peers <n>     Max simultaneous registered peers (default 1000)',
    '  --frame-rate <n>    Max sealed records per peer per minute (default 3000)',
    '  --verbose           Log one line per lifecycle event (metadata only)',
    '  --help              Show this',
    '',
    'Run behind a TLS-terminating reverse proxy. The relay speaks plain HTTP by',
    'design: the records it carries are already sealed end to end, so TLS on this',
    'hop protects metadata, not content.',
    '',
  ].join('\n');
}

function parseArgs(argv: string[]): Options | { help: true } | { error: string } {
  const options: Options = {
    // $PORT first: every container platform injects it, and an operator who set it
    // should not have to discover a flag.
    port: Number(process.env.PORT ?? 8787),
    host: '0.0.0.0',
    maxPeers: 1_000,
    frameRatePerMinute: 3_000,
    verbose: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const next = (): string | undefined => argv[++index];
    switch (argument) {
      case '--help':
      case '-h':
        return { help: true };
      case '--verbose':
        options.verbose = true;
        break;
      case '--port': {
        const value = Number(next());
        if (!Number.isInteger(value) || value < 0 || value > 65535) return { error: '--port must be 0-65535' };
        options.port = value;
        break;
      }
      case '--host': {
        const value = next();
        if (value === undefined || value.length === 0) return { error: '--host requires a value' };
        options.host = value;
        break;
      }
      case '--max-peers': {
        const value = Number(next());
        if (!Number.isInteger(value) || value < 2) return { error: '--max-peers must be at least 2' };
        options.maxPeers = value;
        break;
      }
      case '--frame-rate': {
        const value = Number(next());
        if (!Number.isInteger(value) || value < 1) return { error: '--frame-rate must be a positive integer' };
        options.frameRatePerMinute = value;
        break;
      }
      default:
        return { error: `unknown argument: ${String(argument)}` };
    }
  }
  return options;
}

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  if ('help' in parsed) {
    process.stdout.write(usage());
    return;
  }
  if ('error' in parsed) {
    process.stderr.write(`relay: ${parsed.error}\n\n${usage()}`);
    process.exitCode = 2;
    return;
  }

  const relay = new RelayServer({
    maxPeers: parsed.maxPeers,
    frameRatePerMinute: parsed.frameRatePerMinute,
    verbose: parsed.verbose,
  });

  const port = await relay.listen(parsed.port, parsed.host);
  process.stdout.write(
    `relay listening on ${parsed.host}:${port} (path /relay/v1, health /relay/health)\n` +
      `  max peers ${parsed.maxPeers}, ${parsed.frameRatePerMinute} records/peer/minute\n` +
      '  this process holds no keys and cannot read the frames it forwards\n',
  );

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    // Guarded: a second Ctrl-C during a slow close would otherwise start a second
    // shutdown and race the first one's socket teardown.
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdout.write(`\nrelay: ${signal}, closing ${relay.stats().peers} peer connection(s)\n`);
    void relay.close().then(() => {
      process.exit(0);
    });
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

void main();

import { describe, expect, it } from 'vitest';
import { DEFAULT_LIMITS, PolicyGate, isSlashCommandPrompt } from '../src/policy/gate.ts';
import type { DevicePolicy } from '../src/policy/gate.ts';
import {
  DEFAULT_ALLOWED_METHODS,
  DENIED_METHODS,
  KNOWN_METHODS,
  OPT_IN_METHODS,
} from '../src/policy/methods.ts';

const gate = new PolicyGate();
const DEFAULT: DevicePolicy = { tier: 'default', allowSlashCommands: true };
const EXTENDED: DevicePolicy = { tier: 'extended', allowSlashCommands: true };

/**
 * The 15 methods upstream pins to loopback, verified from
 * packages/client/connection/src/index.ts on 2026-08-15. The bridge is ON
 * loopback, so upstream would allow these; we must deny them ourselves.
 */
const UPSTREAM_PRIVILEGED = [
  'agentPreset.read',
  'agentPreset.copy',
  'agentPreset.openDocument',
  'agentPreset.remove',
  'host.pickDirectory',
  'host.openPath',
  'settings.describe',
  'settings.openDocument',
  'settings.update',
  'settings.replace',
  'settings.mutate',
  'credentials.describe',
  'credentials.set',
  'credentials.unset',
  'llm.discoverModels',
];

describe('deny list', () => {
  it('covers exactly the 15 upstream privileged methods', () => {
    expect(DENIED_METHODS.size).toBe(15);
    expect([...DENIED_METHODS].sort()).toEqual([...UPSTREAM_PRIVILEGED].sort());
  });

  it('denies every one of them at both tiers', () => {
    for (const method of UPSTREAM_PRIVILEGED) {
      for (const policy of [DEFAULT, EXTENDED]) {
        const decision = gate.evaluate(method, {}, policy);
        expect(decision.allowed, method).toBe(false);
        if (!decision.allowed) expect(decision.reason).toBe('method-denied');
      }
    }
  });

  it('keeps agentPreset.list and agentPreset.select out of the deny list, matching upstream', () => {
    expect(DENIED_METHODS.has('agentPreset.list')).toBe(false);
    expect(DENIED_METHODS.has('agentPreset.select')).toBe(false);
    expect(gate.evaluate('agentPreset.list', {}, DEFAULT).allowed).toBe(true);
    expect(gate.evaluate('agentPreset.select', { agentPreset: 'default' }, DEFAULT).allowed).toBe(true);
  });

  it('keeps the model catalog readable, matching upstream reasoning', () => {
    // llm.providers/llm.models carry ids and names, not endpoints or key state,
    // and a mobile model picker legitimately needs them.
    expect(gate.evaluate('llm.providers', {}, DEFAULT).allowed).toBe(true);
    expect(gate.evaluate('llm.models', {}, DEFAULT).allowed).toBe(true);
    // llm.discoverModels is the one that makes the host probe a chosen URL.
    expect(gate.evaluate('llm.discoverModels', {}, EXTENDED).allowed).toBe(false);
  });

  it('has no overlap between deny, default-allow, and opt-in', () => {
    for (const method of DENIED_METHODS) {
      expect(DEFAULT_ALLOWED_METHODS.has(method), method).toBe(false);
      expect(OPT_IN_METHODS.has(method), method).toBe(false);
    }
    for (const method of OPT_IN_METHODS) {
      expect(DEFAULT_ALLOWED_METHODS.has(method), method).toBe(false);
    }
  });
});

describe('unknown methods', () => {
  it('rejects a method dsh may add later rather than forwarding it', () => {
    const decision = gate.evaluate('session.selfDestruct', {}, EXTENDED);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('method-unknown');
  });

  it('rejects path-traversal and injection shapes in the method slot', () => {
    for (const method of ['../respond', 'session.list/../../settings.update', '', 'session.list ']) {
      const decision = gate.evaluate(method, {}, EXTENDED);
      expect(decision.allowed, method).toBe(false);
    }
  });
});

describe('scope tiers', () => {
  it('withholds opt-in methods from the default tier', () => {
    for (const method of OPT_IN_METHODS) {
      const decision = gate.evaluate(method, { workspaceId: 'w1', path: '/tmp' }, DEFAULT);
      expect(decision.allowed, method).toBe(false);
      if (!decision.allowed) expect(decision.reason).toBe('method-out-of-scope');
    }
  });

  it('grants them at the extended tier', () => {
    for (const method of OPT_IN_METHODS) {
      expect(gate.evaluate(method, { workspaceId: 'w1', path: '/tmp' }, EXTENDED).allowed, method).toBe(true);
    }
  });

  it('allows the whole default surface at the default tier', () => {
    for (const method of DEFAULT_ALLOWED_METHODS) {
      const payload =
        method === 'session.prompt' || method === 'subagent.prompt'
          ? { sessionId: 's1', mode: 'queue', content: [{ type: 'text', text: 'hello' }] }
          : {};
      expect(gate.evaluate(method, payload, DEFAULT).allowed, method).toBe(true);
    }
  });
});

describe('payload limits', () => {
  it('rejects a payload over the byte cap before forwarding', () => {
    const decision = gate.evaluate('session.search', { query: 'x'.repeat(DEFAULT_LIMITS.maxPayloadBytes) }, DEFAULT);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('payload-too-large');
  });

  it('caps prompt text length', () => {
    const decision = gate.evaluate(
      'session.prompt',
      { sessionId: 's1', mode: 'queue', content: [{ type: 'text', text: 'x'.repeat(DEFAULT_LIMITS.maxPromptTextLength + 1) }] },
      DEFAULT,
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('payload-too-large');
  });

  it('accepts the four verified image media types and rejects others', () => {
    for (const mediaType of ['image/png', 'image/jpeg', 'image/webp', 'image/gif']) {
      const decision = gate.evaluate(
        'session.prompt',
        { sessionId: 's1', mode: 'queue', content: [{ type: 'image', mediaType, data: 'AAAA' }] },
        DEFAULT,
      );
      expect(decision.allowed, mediaType).toBe(true);
    }
    for (const mediaType of ['image/svg+xml', 'image/bmp', 'text/html', 'application/pdf']) {
      const decision = gate.evaluate(
        'session.prompt',
        { sessionId: 's1', mode: 'queue', content: [{ type: 'image', mediaType, data: 'AAAA' }] },
        DEFAULT,
      );
      expect(decision.allowed, mediaType).toBe(false);
      if (!decision.allowed) expect(decision.reason).toBe('payload-invalid');
    }
  });

  it('rejects a malformed content shape before it reaches dsh', () => {
    const bad: unknown[] = [
      { sessionId: 's1', content: 'just a string' },
      { sessionId: 's1', content: [] },
      { sessionId: 's1', content: [{ type: 'video', data: 'x' }] },
      { sessionId: 's1', content: [{ type: 'text' }] },
      { sessionId: 's1', content: [{ type: 'text', text: 'hi' }], mode: 'shout' },
    ];
    for (const payload of bad) {
      expect(gate.evaluate('session.prompt', payload, DEFAULT).allowed, JSON.stringify(payload)).toBe(false);
    }
  });
});

describe('slash commands', () => {
  it('detects exactly one leading-/ text block, per the verified rule', () => {
    expect(isSlashCommandPrompt({ content: [{ type: 'text', text: '/compact' }] })).toBe(true);
    // Two blocks is an ordinary prompt, not a command.
    expect(
      isSlashCommandPrompt({ content: [{ type: 'text', text: '/compact' }, { type: 'text', text: 'also this' }] }),
    ).toBe(false);
    expect(isSlashCommandPrompt({ content: [{ type: 'text', text: 'not /a command' }] })).toBe(false);
    expect(isSlashCommandPrompt({ content: [{ type: 'image', mediaType: 'image/png', data: 'A' }] })).toBe(false);
  });

  it('classifies a slash command as its own capability for the audit log', () => {
    const decision = gate.evaluate(
      'session.prompt',
      { sessionId: 's1', mode: 'queue', content: [{ type: 'text', text: '/compact' }] },
      DEFAULT,
    );
    expect(decision).toEqual({ allowed: true, capability: 'slash-command' });

    const ordinary = gate.evaluate(
      'session.prompt',
      { sessionId: 's1', mode: 'queue', content: [{ type: 'text', text: 'hello' }] },
      DEFAULT,
    );
    expect(ordinary).toEqual({ allowed: true, capability: 'prompt' });
  });

  it('can be disabled per device without disabling ordinary prompts', () => {
    const policy: DevicePolicy = { tier: 'default', allowSlashCommands: false };
    const command = gate.evaluate(
      'session.prompt',
      { sessionId: 's1', mode: 'queue', content: [{ type: 'text', text: '/compact' }] },
      policy,
    );
    expect(command.allowed).toBe(false);
    if (!command.allowed) expect(command.reason).toBe('slash-command-disabled');

    expect(
      gate.evaluate('session.prompt', { sessionId: 's1', mode: 'queue', content: [{ type: 'text', text: 'hi' }] }, policy)
        .allowed,
    ).toBe(true);
  });
});

describe('table integrity', () => {
  it('KNOWN_METHODS is the union of the three tables', () => {
    const union = new Set([...DENIED_METHODS, ...DEFAULT_ALLOWED_METHODS, ...OPT_IN_METHODS]);
    expect(KNOWN_METHODS.size).toBe(union.size);
    for (const method of union) expect(KNOWN_METHODS.has(method), method).toBe(true);
  });

  it('covers every method in the verified upstream RPC map, plus respond', () => {
    // Verified from packages/host/apiproxy/src/api/rpc-map.ts on 2026-08-15.
    // `respond` is absent upstream because it is a client-response.
    const upstreamRpcMap = [
      'session.list', 'session.search', 'session.create', 'session.history', 'session.models',
      'session.selectModel', 'session.rename', 'session.fork', 'session.prompt', 'session.attachment',
      'session.updateQueue', 'session.cancel',
      'subagent.list', 'subagent.history', 'subagent.prompt', 'subagent.interrupt',
      'host.describe', 'host.pickDirectory', 'host.listDirectory', 'host.createDirectory', 'host.openPath',
      'workspace.list', 'workspace.create', 'workspace.rename', 'workspace.delete',
      'workspace.insertBefore', 'workspace.insertSessionBefore', 'workspace.archiveSession',
      'skill.list',
      'agentPreset.list', 'agentPreset.select', 'agentPreset.read', 'agentPreset.copy',
      'agentPreset.openDocument', 'agentPreset.remove',
      'goal.create', 'goal.edit', 'goal.pause', 'goal.resume', 'goal.complete', 'goal.clear',
      'settings.describe', 'settings.openDocument', 'settings.update', 'settings.replace', 'settings.mutate',
      'credentials.describe', 'credentials.set', 'credentials.unset',
      'llm.providers', 'llm.models', 'llm.discoverModels',
    ];

    // Every upstream method is classified somewhere: nothing is unaccounted for.
    for (const method of upstreamRpcMap) {
      expect(KNOWN_METHODS.has(method), `unclassified upstream method: ${method}`).toBe(true);
    }
    // And we invent nothing beyond the map except `respond`.
    for (const method of KNOWN_METHODS) {
      if (method === 'respond') continue;
      expect(upstreamRpcMap.includes(method), `unknown-to-upstream method: ${method}`).toBe(true);
    }
  });
});

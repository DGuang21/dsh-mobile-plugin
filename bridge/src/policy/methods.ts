/**
 * [OUR DESIGN] Method policy tables.
 *
 * These are the bridge's own authorization tables, not dsh's. dsh pins its 15
 * privileged methods to loopback — and the bridge IS on loopback, so upstream
 * would happily let us call them. We deny them ourselves.
 *
 * The load-bearing fact: reaching `/api` is equivalent to arbitrary code
 * execution as the workstation user, and the default agent already carries
 * `bash` plus filesystem tools. So the allow-list is not a security boundary
 * against a compromised session — it is a boundary against the *phone* being
 * used to reconfigure the workstation, read its credential provenance, or drive
 * its desktop.
 */

/**
 * Hard deny-list. Never overridable by config, by scope tier, or by a flag.
 *
 * These are exactly the 15 methods upstream pins to loopback
 * (`PRIVILEGED_METHODS` in packages/client/connection/src/index.ts), verified
 * 2026-08-15. Each reads or mutates host configuration, probes credential
 * provenance, drives the host desktop, or is reconnaissance on the plugins a
 * session runs. A phone has no business reaching any of them.
 */
export const DENIED_METHODS: ReadonlySet<string> = new Set([
  // Native dialogs and desktop control: act on the machine, not the session.
  'host.pickDirectory',
  'host.openPath',
  // Configuration plane: reading is as privileged as writing, because
  // `settings.describe` returns every exposed namespace's configuration.
  'settings.describe',
  'settings.openDocument',
  'settings.update',
  'settings.replace',
  'settings.mutate',
  // Credential plane: `credentials.describe` reports whether an arbitrary env
  // var is configured and where from — reconnaissance for an anonymous caller.
  'credentials.describe',
  'credentials.set',
  'credentials.unset',
  // Preset management: reading a composition names the plugins a session runs.
  // Note `agentPreset.list` and `agentPreset.select` are deliberately NOT here,
  // matching upstream: `session.create` already accepts an `agentPreset`, so
  // pinning only the switch would be a fence beside an open gate.
  'agentPreset.read',
  'agentPreset.copy',
  'agentPreset.openDocument',
  'agentPreset.remove',
  // Makes the HOST issue a GET to a caller-chosen URL and reports the result:
  // an outbound probe for whatever the workstation can reach.
  'llm.discoverModels',
]);

/**
 * Default allow-list: the read and conversational surface a phone needs.
 *
 * `respond` is included even though it is absent from the upstream RPC map,
 * because it is a client-*response*, not a client-request. Our `/m1/respond`
 * endpoint maps onto it and the gate must be able to name it.
 */
export const DEFAULT_ALLOWED_METHODS: ReadonlySet<string> = new Set([
  'session.list',
  'session.search',
  'session.history',
  'session.create',
  'session.prompt',
  'session.cancel',
  'session.rename',
  'session.fork',
  'session.models',
  'session.selectModel',
  'session.updateQueue',
  'session.attachment',
  'subagent.list',
  'subagent.history',
  'subagent.prompt',
  'subagent.interrupt',
  'host.describe',
  'workspace.list',
  'skill.list',
  'agentPreset.list',
  'agentPreset.select',
  'goal.create',
  'goal.edit',
  'goal.pause',
  'goal.resume',
  'goal.complete',
  'goal.clear',
  'llm.providers',
  'llm.models',
  'respond',
]);

/**
 * Opt-in tier: off by default, enabled per device on the workstation.
 *
 * These mutate durable workspace structure or read the host filesystem. They are
 * legitimate for a trusted phone but are not something a fresh pairing grants.
 */
export const OPT_IN_METHODS: ReadonlySet<string> = new Set([
  'workspace.create',
  'workspace.rename',
  'workspace.delete',
  'workspace.insertBefore',
  'workspace.insertSessionBefore',
  'workspace.archiveSession',
  'host.listDirectory',
  'host.createDirectory',
]);

/** Scope tiers a device can hold. */
export type ScopeTier = 'default' | 'extended';

/**
 * Every method the bridge knows about. A method outside this set is rejected as
 * unknown rather than forwarded: dsh is a developer preview that will add
 * methods, and a new one must be reviewed in, never auto-allowed.
 */
export const KNOWN_METHODS: ReadonlySet<string> = new Set([
  ...DENIED_METHODS,
  ...DEFAULT_ALLOWED_METHODS,
  ...OPT_IN_METHODS,
]);

/** Methods reachable by a device holding `tier`. */
export function allowedMethodsForTier(tier: ScopeTier): ReadonlySet<string> {
  if (tier === 'extended') return new Set([...DEFAULT_ALLOWED_METHODS, ...OPT_IN_METHODS]);
  return DEFAULT_ALLOWED_METHODS;
}

/**
 * [OUR DESIGN] The policy gate.
 *
 * Every phone-originated method call passes through `evaluate` before it reaches
 * dsh. The gate is deliberately dumb and total: it decides from the method name,
 * the device's scope tier, and the payload shape, with no I/O and no dsh
 * knowledge beyond the verified wire contract. That makes it exhaustively
 * testable, which is the point — this is the component standing between a phone
 * and an RCE-equivalent endpoint.
 *
 * Order matters. The deny-list is checked before anything else so no future
 * config, tier, or payload quirk can route around it.
 */

import { IMAGE_MEDIA_TYPES } from '../dsh/types.ts';
import type { ImageMediaType } from '../dsh/types.ts';
import { DENIED_METHODS, KNOWN_METHODS, allowedMethodsForTier } from './methods.ts';
import type { ScopeTier } from './methods.ts';

/** Why a call was refused. Mapped to `/m1` error codes by the server. */
export type DenyReason =
  | 'method-denied'
  | 'method-unknown'
  | 'method-out-of-scope'
  | 'payload-too-large'
  | 'payload-invalid'
  | 'slash-command-disabled';

export type PolicyDecision =
  | { allowed: true; capability: Capability }
  | { allowed: false; reason: DenyReason; message: string };

/**
 * What a call is doing, for the audit log and for per-device toggles. A slash
 * command is called out separately because it is executed by the host command
 * registry rather than the model — a materially different capability that a
 * user may want to withhold from a phone.
 */
export type Capability = 'read' | 'prompt' | 'slash-command' | 'mutate' | 'respond';

export interface PolicyLimits {
  /**
   * Cap on a single serialized request payload. Default 8 MiB, far under
   * upstream's 160 MiB resident bound, because a phone has no legitimate reason
   * to push a body that large and the bridge buffers it in memory.
   */
  maxPayloadBytes: number;
  /** Cap on one image block's base64 payload. */
  maxImageBytes: number;
  /** Cap on text in a single prompt block. */
  maxPromptTextLength: number;
}

export const DEFAULT_LIMITS: PolicyLimits = {
  maxPayloadBytes: 8 * 1024 * 1024,
  maxImageBytes: 6 * 1024 * 1024,
  maxPromptTextLength: 200_000,
};

/** Per-device policy inputs. */
export interface DevicePolicy {
  tier: ScopeTier;
  /**
   * Whether this device may run slash commands. Off means a leading-`/` prompt
   * is refused rather than silently sent to the model, because those are not
   * equivalent: the registry may run host-side work the user did not intend to
   * delegate to a phone.
   */
  allowSlashCommands: boolean;
}

export const DEFAULT_DEVICE_POLICY: DevicePolicy = {
  tier: 'default',
  allowSlashCommands: true,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function deny(reason: DenyReason, message: string): PolicyDecision {
  return { allowed: false, reason, message };
}

/** Classify a method into a capability for auditing. */
function capabilityFor(method: string, isSlashCommand: boolean): Capability {
  if (method === 'respond') return 'respond';
  if (method === 'session.prompt' || method === 'subagent.prompt') {
    return isSlashCommand ? 'slash-command' : 'prompt';
  }
  if (method.startsWith('session.') || method.startsWith('subagent.')) {
    const reads = ['session.list', 'session.search', 'session.history', 'session.models', 'subagent.list', 'subagent.history'];
    return reads.includes(method) ? 'read' : 'mutate';
  }
  const reads = ['host.describe', 'workspace.list', 'skill.list', 'agentPreset.list', 'llm.providers', 'llm.models'];
  return reads.includes(method) ? 'read' : 'mutate';
}

/**
 * Detect a slash command. Verified rule: a prompt whose content is exactly ONE
 * text block starting with `/` is dispatched by the host command registry and
 * never reaches the model. Two blocks, or a leading image, is an ordinary prompt.
 */
export function isSlashCommandPrompt(payload: unknown): boolean {
  if (!isRecord(payload)) return false;
  const content = payload.content;
  if (!Array.isArray(content) || content.length !== 1) return false;
  const block = content[0];
  if (!isRecord(block) || block.type !== 'text') return false;
  return typeof block.text === 'string' && block.text.startsWith('/');
}

/** Validate prompt `content` against the verified narrow wire shape. */
function validatePromptContent(payload: unknown, limits: PolicyLimits): PolicyDecision | undefined {
  if (!isRecord(payload)) return deny('payload-invalid', 'payload must be an object');
  const content = payload.content;
  if (!Array.isArray(content)) return deny('payload-invalid', 'content must be an array');
  if (content.length === 0) return deny('payload-invalid', 'content must not be empty');

  for (const block of content) {
    if (!isRecord(block)) return deny('payload-invalid', 'content block must be an object');
    if (block.type === 'text') {
      if (typeof block.text !== 'string') return deny('payload-invalid', 'text block requires a string text');
      if (block.text.length > limits.maxPromptTextLength) {
        return deny('payload-too-large', `text block exceeds ${String(limits.maxPromptTextLength)} characters`);
      }
      continue;
    }
    if (block.type === 'image') {
      // Validated against the verified media-type set before it reaches dsh, so
      // a rejection is a clear client error rather than an upstream 200 +
      // bad-request we would have to translate back.
      if (typeof block.mediaType !== 'string' || !IMAGE_MEDIA_TYPES.includes(block.mediaType as ImageMediaType)) {
        return deny('payload-invalid', `image mediaType must be one of ${IMAGE_MEDIA_TYPES.join(', ')}`);
      }
      if (typeof block.data !== 'string') return deny('payload-invalid', 'image block requires base64 data');
      if (block.data.length > limits.maxImageBytes) {
        return deny('payload-too-large', `image block exceeds ${String(limits.maxImageBytes)} bytes`);
      }
      continue;
    }
    return deny('payload-invalid', `unsupported content block type: ${String(block.type)}`);
  }

  if (payload.mode !== undefined && payload.mode !== 'queue' && payload.mode !== 'steer') {
    return deny('payload-invalid', 'mode must be "queue" or "steer"');
  }
  return undefined;
}

export class PolicyGate {
  private readonly limits: PolicyLimits;

  constructor(limits: PolicyLimits = DEFAULT_LIMITS) {
    this.limits = limits;
  }

  /**
   * Decide whether a device may make this call.
   *
   * @param method - dsh wire method name, or `respond`.
   * @param payload - the payload as received from the phone.
   * @param policy - the device's tier and toggles.
   */
  evaluate(method: string, payload: unknown, policy: DevicePolicy = DEFAULT_DEVICE_POLICY): PolicyDecision {
    // 1. Hard deny first. Nothing below can re-admit these.
    if (DENIED_METHODS.has(method)) {
      return deny('method-denied', `${method} is permanently denied to mobile devices`);
    }

    // 2. Unknown methods are rejected, not forwarded. A new upstream method must
    //    be reviewed in; auto-allowing would grant capabilities we never audited.
    if (!KNOWN_METHODS.has(method)) {
      return deny('method-unknown', `${method} is not a method this bridge knows`);
    }

    // 3. Scope tier.
    if (!allowedMethodsForTier(policy.tier).has(method)) {
      return deny('method-out-of-scope', `${method} requires the extended scope tier`);
    }

    // 4. Size, before any structural work and before forwarding.
    const size = payloadSize(payload);
    if (size > this.limits.maxPayloadBytes) {
      return deny('payload-too-large', `payload of ${String(size)} bytes exceeds ${String(this.limits.maxPayloadBytes)}`);
    }

    // 5. Structural checks for the methods whose shape we know and care about.
    const isSlash = (method === 'session.prompt' || method === 'subagent.prompt') && isSlashCommandPrompt(payload);
    if (method === 'session.prompt' || method === 'subagent.prompt') {
      const invalid = validatePromptContent(payload, this.limits);
      if (invalid !== undefined) return invalid;
      if (isSlash && !policy.allowSlashCommands) {
        return deny('slash-command-disabled', 'slash commands are disabled for this device');
      }
    }

    return { allowed: true, capability: capabilityFor(method, isSlash) };
  }

  getLimits(): PolicyLimits {
    return this.limits;
  }
}

/** Serialized size of a payload in bytes. */
export function payloadSize(payload: unknown): number {
  if (payload === undefined) return 0;
  return Buffer.byteLength(JSON.stringify(payload) ?? '', 'utf8');
}

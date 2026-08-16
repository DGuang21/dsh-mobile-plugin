/**
 * Small runtime shims for APIs that exist in Node 22 but are absent from the
 * TypeScript 5.3 DOM lib this repo pins (the version Expo 52 expects).
 *
 * These are not polyfills: the runtime already has the API. They exist so we do
 * not have to bump TypeScript, which would be a change to the app's toolchain
 * for a bridge-only concern.
 */

interface AbortSignalWithAny {
  any(signals: AbortSignal[]): AbortSignal;
}

/**
 * Combine abort signals, aborting when the first of them aborts.
 *
 * Uses `AbortSignal.any` (Node ≥ 20) and falls back to manual wiring so the
 * bridge still behaves correctly on a runtime without it.
 */
export function anySignal(signals: (AbortSignal | undefined)[]): AbortSignal | undefined {
  const present = signals.filter((signal): signal is AbortSignal => signal !== undefined);
  if (present.length === 0) return undefined;
  if (present.length === 1) return present[0];

  const native = (AbortSignal as unknown as Partial<AbortSignalWithAny>).any;
  if (typeof native === 'function') return native.call(AbortSignal, present);

  const controller = new AbortController();
  for (const signal of present) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      return controller.signal;
    }
    signal.addEventListener('abort', () => controller.abort(signal.reason), { once: true });
  }
  return controller.signal;
}

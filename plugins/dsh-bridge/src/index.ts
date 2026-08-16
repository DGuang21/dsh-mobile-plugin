/**
 * `dsh-mobile-bridge` — a Cordis plugin that runs the mobile bridge inside the
 * `dsh web` process.
 *
 * WHY IN-PROCESS AND NOT A SIDECAR
 *
 * The bridge must forward to dsh's `/api`, and the only sanctioned way to learn
 * where dsh is actually listening is to ask the harness. As a plugin we read
 * `ctx.webServer.host` and `ctx.webServer.port`, which means:
 *
 *   - The bridge follows dsh's bind automatically, including `port: 0`.
 *   - We never write to dsh's webserver config. Milestone 8's requirement — start
 *     alongside `dsh web` without changing dsh bind settings — is satisfied by
 *     construction, because this plugin has no write path to that config.
 *   - The bridge dies with dsh. A `ctx.effect` disposer stops the listener, so an
 *     orphaned bridge cannot outlive the harness it was authorizing access to.
 *
 * WHAT THIS PLUGIN DELIBERATELY DOES NOT DO
 *
 * It does not put the PHONE surface on dsh's webserver. The bridge listens on its
 * own port with its own TLS identity. Sharing dsh's listener would put the phone's
 * surface behind dsh's trust fence — which upstream documents as a reachability
 * policy, not authentication — and would mean an operator who exposed the bridge
 * to the LAN had also exposed `/api`. Two listeners is the entire point.
 *
 * PAIRING: CLI, OR THE MANAGEMENT PANEL
 *
 * Pairing requires an operator to compare a 6-digit SAS, and there is no terminal
 * attached to a plugin. So it stays out of the phone-facing surface — but the
 * plugin also starts an operator management panel (see `bridge/src/panel/`). The
 * panel is exactly the operator-attended surface a bare plugin lacks, so pairing is
 * available there as well as through the CLI (`dsh-bridge pair`) against the control
 * socket. Both drive the same in-memory pairing state machine on the running bridge.
 *
 * WHERE THE PANEL LIVES — and why it is safe either way. The panel is *more*
 * privileged than the phone surface (it mints access, revokes devices, opens
 * pairing), so unlike the phone surface it does NOT depend on where it is served:
 * it carries its own four-check fence (loopback peer, local Host, per-boot bearer
 * token, JSON content-type; see `bridge/src/panel/server.ts`). That lets it take the
 * SUPPORTED upstream client-injection path — a same-origin route on dsh's own
 * webserver via `ctx.webServer.register({kind:'prefix', path:'/mobile-bridge'})` —
 * WHEN dsh is loopback-bound, so an operator finds it at `<dsh-origin>/mobile-bridge/`
 * right next to the dsh web UI. WHEN dsh binds the LAN (0.0.0.0), or the host predates
 * `webServer.register`, the plugin instead brings up a dedicated 127.0.0.1 listener
 * so the panel is not even TCP-reachable from another host. In both modes the fence
 * is identical and fails closed for any non-loopback peer. `panelPort <= 0` disables
 * the panel entirely. See docs/DSH_PLUGIN_PANEL_CONTRACT.md §1/§6.
 *
 * INTEGRATION-TESTED. This file was loaded by a real `dsh web` at upstream
 * `47f9438` on 2026-08-16: `dsh plugin add` linked the package, the Cordis loader
 * mounted this module, and the bridge it starts reached `dshState: connected` on
 * its own TLS listener. The plugin contract (`name`, `inject`, `Config`, `apply`)
 * and the `webServer` accessors were confirmed against a live host, not only read
 * from source. Reproduce with `plugins/dsh-bridge/scripts/integration-test`; the
 * deterministic CI guard is `bridge/tests/dsh-plugin-loader.test.ts`. Still
 * point-in-time: this is one revision, not a standing compatibility guarantee.
 */

import { buildBridge, type BuiltBridge } from '../../../bridge/src/bridge.ts';
import { mountPanel, attachPanel } from '../../../bridge/src/panel/mount.ts';
import { fileURLToPath } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * The slice of Cordis this plugin uses.
 *
 * Declared locally rather than imported from `@deepseek-ai/cordis`. That package
 * is not a dependency of this repo and must not become one: the tree is shared
 * with an Expo app, and the instruction to keep dependencies compatible with the
 * existing setup rules out pulling the harness's plugin framework in for a file
 * that only ever runs inside a dsh profile install. In that install the real
 * types are present; here the surface is narrow enough to state exactly.
 */
export interface MinimalContext {
  webServer: {
    readonly host: string;
    readonly port: number;
    /**
     * Register a named route on dsh's own webserver. Optional here because a host
     * that predates it (or a test fake) simply lacks it, in which case the panel
     * falls back to its dedicated loopback listener. The real signature is
     * `register(route: WebRoute): () => void` (upstream
     * `packages/host/webserver`); `kind: 'prefix'` claims `path` and everything
     * under `path/`, and the disposer removes it.
     */
    register?(route: {
      kind: 'exact' | 'prefix';
      path: string;
      handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
    }): () => void;
  };
  /** Registers a side effect and its disposer. */
  effect(setup: () => () => void, label?: string): void;
  logger?: (namespace: string) => { info(message: string): void; error(message: string): void };
}

/** Stable Cordis plugin name. */
export const name = 'mobile-bridge';

/**
 * The bridge cannot resolve dsh's origin until the carrier is listening, so the
 * webserver service is a hard requirement rather than an optional read.
 */
export const inject = ['webServer'];

export interface Config {
  /** State directory: identity, TLS material, device registry, audit log. */
  stateDir: string;
  /** Interface for the phone-facing listener. `0.0.0.0` serves the LAN. */
  host?: string;
  /** Port for the phone-facing listener. */
  port?: number;
  /** SAN entries for the self-signed certificate. */
  certHosts?: string[];
  /** Relay to dial out to. Omitted means LAN-only. */
  relayUrl?: string;
  bridgeName?: string;
  rateLimitPerMinute?: number;
  /**
   * Enables the operator management panel and, in dedicated-listener mode, sets
   * its loopback port. `0` (or negative) disables the panel entirely.
   *
   * MOUNT MODE IS CHOSEN FROM dsh's BIND, not from this value:
   *   - dsh loopback-bound AND `webServer.register` available → the panel is a
   *     same-origin route at `<dsh-origin>/mobile-bridge/` (this port is unused).
   *   - dsh LAN-bound (0.0.0.0), or no `register` → a dedicated 127.0.0.1 listener
   *     on this port, so the panel is not even TCP-reachable from another host.
   * Either way the panel binds/serves loopback only and enforces its bearer fence;
   * it never rides the phone-facing bridge. See docs/DSH_PLUGIN_PANEL_CONTRACT.md.
   */
  panelPort?: number;
}

/**
 * Start the bridge alongside dsh.
 *
 * Startup is deliberately asynchronous-but-unawaited inside a synchronous
 * `effect`: Cordis wants a disposer immediately, and a listener that is still
 * binding must still be stoppable. The `stopped` flag closes the race where
 * disposal arrives before `start()` resolves — without it, a fast shutdown would
 * leak a listening socket that nothing holds a reference to.
 */
export function apply(ctx: MinimalContext, config: Config): void {
  const log = ctx.logger?.('mobile-bridge');

  ctx.effect(() => {
    let built: BuiltBridge | undefined;
    let stopPanel: (() => void | Promise<void>) | undefined;
    let stopped = false;

    // dsh's own bind, read from dsh. `0.0.0.0` is normalized to loopback for our
    // outbound calls: the bridge talks to dsh over loopback even when dsh is
    // serving the LAN, because a request to the all-interfaces address is not a
    // meaningful destination.
    const dshHost = ctx.webServer.host === '0.0.0.0' ? '127.0.0.1' : ctx.webServer.host;
    const dshUrl = `http://${dshHost}:${ctx.webServer.port}`;

    void (async () => {
      try {
        const bridge = buildBridge({
          stateDir: config.stateDir,
          dshUrl,
          host: config.host ?? '127.0.0.1',
          port: config.port ?? 8765,
          ...(config.certHosts === undefined ? {} : { certHosts: config.certHosts }),
          // A relay set through this plugin's config is a PIN: it overrides any
          // value the operator saved from the panel, at every start. Tagging the
          // source lets the panel refuse a doomed edit and name where the relay is
          // actually controlled instead of promising a restart it cannot honor. The
          // default overlay sources `relayUrl` from `DSH_MOBILE_BRIDGE_RELAY`
          // (cordis.patch.yml), so an env value reads as `env`; anything else came
          // from the profile/plugin config literal.
          ...(config.relayUrl === undefined
            ? {}
            : {
                relayUrl: config.relayUrl,
                relaySource: config.relayUrl === process.env.DSH_MOBILE_BRIDGE_RELAY ? 'env' : 'config',
              }),
          ...(config.bridgeName === undefined ? {} : { bridgeName: config.bridgeName }),
          ...(config.rateLimitPerMinute === undefined ? {} : { rateLimitPerMinute: config.rateLimitPerMinute }),
        });
        if (stopped) return;
        built = bridge;
        await bridge.start();
        if (stopped) {
          await bridge.stop();
          return;
        }
        log?.info(
          `bridge ${bridge.identity.bridgeId} listening on ${config.host ?? '127.0.0.1'}:${config.port ?? 8765}` +
            ` → dsh ${dshUrl} (spki ${bridge.tlsFingerprint})`,
        );

        // Operator management panel. This is where pairing becomes possible under
        // `dsh web`: the panel is the operator-attended surface a plugin otherwise
        // lacks (there is no terminal to compare the SAS at), so it can drive the
        // same pairing state machine the CLI does — but only ever from loopback,
        // token-gated. `panelPort <= 0` disables it entirely.
        const panelPort = config.panelPort ?? 8766;
        if (panelPort > 0) {
          try {
            // `panel-ui/` sits one level up from this `src/` file, and ships with
            // the package. Resolved from import.meta so it works both in-repo and
            // from a pnpm-linked profile install.
            const assetsDir = fileURLToPath(new URL('../panel-ui', import.meta.url));

            // SAME-ORIGIN when dsh is loopback-bound and exposes the supported
            // route API: the panel rides dsh's own webserver at
            // `<dsh-origin>/mobile-bridge/` — the real client-injection contract,
            // no dsh source change. The fence still refuses any non-loopback peer,
            // so this is safe even though the route shares dsh's listener.
            //
            // DEDICATED 127.0.0.1 LISTENER otherwise (dsh bound the LAN, or an
            // older host with no `register`): a second loopback server keeps the
            // panel not-even-TCP-reachable from another host. `0.0.0.0` is the only
            // non-loopback bind dsh supports, so testing it is the whole condition.
            const dshLoopbackBound = ctx.webServer.host !== '0.0.0.0';
            const register = ctx.webServer.register?.bind(ctx.webServer);

            if (dshLoopbackBound && register !== undefined) {
              const attached = attachPanel(
                { register },
                { bridge, assetsDir, stateDir: config.stateDir },
              );
              if (stopped) {
                attached.dispose();
                return;
              }
              stopPanel = () => attached.dispose();
              log?.info(
                `bridge management panel (same-origin) at ${dshUrl}${attached.basePath}/` +
                  ` (token in ${config.stateDir}/panel-token)`,
              );
            } else {
              const mounted = mountPanel({
                bridge,
                assetsDir,
                stateDir: config.stateDir,
                host: '127.0.0.1',
                port: panelPort,
              });
              await mounted.start();
              if (stopped) {
                await mounted.stop();
                return;
              }
              stopPanel = () => mounted.stop();
              log?.info(`bridge management panel on ${mounted.url} (token in ${config.stateDir}/panel-token)`);
            }
          } catch (error) {
            // The panel is a convenience; a bridge that serves paired phones is
            // useful without it. Never let a panel mount failure stop the bridge.
            log?.error(`bridge panel failed to start: ${error instanceof Error ? error.message : String(error)}`);
          }
        }
      } catch (error) {
        // A bridge that cannot start must not take dsh down with it: the harness
        // is useful without a phone attached, and the operator can read the
        // reason and retry. Reported, not thrown.
        log?.error(`bridge failed to start: ${error instanceof Error ? error.message : String(error)}`);
      }
    })();

    return () => {
      stopped = true;
      void stopPanel?.();
      void built?.stop();
    };
  }, 'mobile-bridge: phone-facing listener');
}

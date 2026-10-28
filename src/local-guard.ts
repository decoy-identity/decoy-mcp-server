// H7 — local-only request guard for the MCP bridge.
//
// The bridge holds the user's agent token and, at Full access, its tools
// auto-approve unlocks. It is meant to serve ONE local MCP client (Claude
// Desktop/Code, etc.) over loopback. Two things must not happen:
//   1. LAN peers reaching the port (fixed by binding 127.0.0.1).
//   2. A web page the user visits driving the bridge — directly via cross-origin
//      fetch, or via DNS-rebinding (a page whose hostname resolves to 127.0.0.1).
//
// The SDK's own DNS-rebinding option is off by default and doesn't check Origin, so we
// enforce both here. Native MCP clients send NO Origin header and a loopback Host
// (localhost:PORT / 127.0.0.1:PORT); browsers always attach an Origin. So:
//   - Host must be an allowed loopback authority (a rebind page arrives with the
//     attacker's Host, not localhost → blocked).
//   - Any Origin present must be loopback (or explicitly allow-listed) → a real
//     web page's Origin is rejected.

import { ConfigError } from './api-config.js';

export interface GuardOptions {
  port: number;
  /** Extra Host authorities to accept (e.g. a hosted deploy behind a proxy). */
  allowedHosts?: string[];
  /** Extra exact Origins to accept (for a non-loopback deployment). */
  allowedOrigins?: string[];
}

/** The interface the bridge listens on: loopback only. There is no off-machine mode — the
 *  bridge holds the owner's token and decrypts locally, so anything that reaches the port acts
 *  as the owner. */
export function resolveBindHost(requested: string | undefined): string {
  const host = (requested ?? '127.0.0.1').trim();
  if (!isLoopbackHostname(host)) {
    throw new ConfigError('MCP_BIND_HOST', `MCP_BIND_HOST=${host} is not a loopback address. The Decoy bridge only listens on 127.0.0.1, ::1 or localhost.`);
  }
  return host;
}

/** How to open a URL in the user's browser without a shell: the URL is one argument. */
export function browserCommand(platform: NodeJS.Platform, url: string): { file: string; args: string[]; shell: false } {
  if (platform === 'win32') return { file: 'rundll32', args: ['url.dll,FileProtocolHandler', url], shell: false };
  if (platform === 'darwin') return { file: 'open', args: [url], shell: false };
  return { file: 'xdg-open', args: [url], shell: false };
}

function isLoopbackHostname(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

/**
 * Decide whether an incoming HTTP request may drive the bridge. Pure function of
 * the request headers — unit-testable, no I/O.
 */
export function isLocalRequestAllowed(
  headers: { host?: string | null; origin?: string | null },
  opts: GuardOptions,
): boolean {
  const host = (headers.host ?? '').toLowerCase().trim();
  if (!host) return false;

  const allowedHosts = new Set<string>([
    `localhost:${opts.port}`,
    `127.0.0.1:${opts.port}`,
    `[::1]:${opts.port}`,
    ...(opts.allowedHosts ?? []).map((h) => h.toLowerCase().trim()).filter(Boolean),
  ]);
  if (!allowedHosts.has(host)) return false;

  // Origin is optional (native clients omit it). If present it must be loopback
  // or explicitly allow-listed — never an arbitrary web page.
  const origin = headers.origin?.trim();
  if (origin) {
    const allowedOrigins = new Set((opts.allowedOrigins ?? []).map((o) => o.trim()).filter(Boolean));
    if (allowedOrigins.has(origin)) return true;
    try {
      if (!isLoopbackHostname(new URL(origin).hostname)) return false;
    } catch {
      return false; // malformed Origin
    }
  }
  return true;
}

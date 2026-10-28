/**
 * Where the bridge connects. Production is the default; any other host is explicit and
 * validated, and it needs its own pairing page, because the public page pairs production only.
 */
export const DEFAULT_API_URL = 'https://api.decoys.me/api/agent';
const DEFAULT_CONNECT_URL = 'https://decoys.me/connect';
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** A setting the bridge refuses. `variable` is the environment variable to look at; its value is not kept here. */
export class ConfigError extends Error {
  constructor(readonly variable: string, message: string) { super(message); this.name = 'ConfigError'; }
}

export interface ApiConfig { agentApiUrl: string; connectFrontendUrl: string; apiHost: string; isProduction: boolean }

export function resolveApiConfig(env: Record<string, string | undefined>): ApiConfig {
  if (env.DEV_MODE !== undefined && env.DEV_MODE !== '') {
    throw new ConfigError('DEV_MODE', 'DEV_MODE was removed in decoy-mcp-server 1.1.0. To use another Decoy environment, set ' +
      'DECOY_AGENT_API_URL (and DECOY_CONNECT_URL), and keep its credentials in a separate HOME from production.');
  }
  const raw = (env.DECOY_AGENT_API_URL ?? '').trim() || DEFAULT_API_URL;
  let url: URL;
  try { url = new URL(raw); } catch { throw new ConfigError('DECOY_AGENT_API_URL', `DECOY_AGENT_API_URL is not a valid URL: ${JSON.stringify(raw)}`); }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    throw new ConfigError('DECOY_AGENT_API_URL', 'DECOY_AGENT_API_URL must use https (plain http is allowed only on localhost).');
  }
  const isProduction = url.host === new URL(DEFAULT_API_URL).host;
  const connect = (env.DECOY_CONNECT_URL ?? '').trim();
  if (!isProduction && !connect) {
    throw new ConfigError('DECOY_CONNECT_URL', `DECOY_AGENT_API_URL points at ${url.host}; also set DECOY_CONNECT_URL to that environment's pairing page.`);
  }
  return { agentApiUrl: raw.replace(/\/$/, ''), connectFrontendUrl: connect || DEFAULT_CONNECT_URL, apiHost: url.host, isProduction };
}

/** The pairing page link: the page's own query is kept; code and agent are set safely. */
export function pairingPageUrl(connectFrontendUrl: string, code: string, agentFor: string): string {
  const u = new URL(connectFrontendUrl);
  u.searchParams.set('code', code);
  u.searchParams.set('for', agentFor);
  return u.toString();
}

/** The local port: DECOY_MCP_PORT, else PORT (kept for older setups), else 3001. */
export function parsePort(env: Record<string, string | undefined>): number {
  const name = env.DECOY_MCP_PORT?.trim() ? 'DECOY_MCP_PORT' : env.PORT?.trim() ? 'PORT' : null;
  if (!name) return 3001;
  const raw = env[name]!.trim();
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ConfigError(name, `${name} must be a port number (1-65535), not ${JSON.stringify(raw)}.`);
  return port;
}

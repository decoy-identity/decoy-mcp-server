/**
 * Saved connection credentials and the agent key. Credentials record the API host that issued
 * them and are never sent anywhere else; files from before 1.1.0 (no host) are production's.
 * An agent key file that can't be read stops the bridge: a new key would leave the saved
 * connection unable to open anything sealed to the old one.
 */
import { DEFAULT_API_URL } from './api-config.js';

const PRODUCTION_HOST = new URL(DEFAULT_API_URL).host;

export interface SavedCredentials { access_token: string; refresh_token?: string }
export interface AgentKeyPair { publicKeySpki: string; privateKeyPem: string }

/** `keyFingerprint` (SHA-256 of the agent's SPKI public key, hex) records which key the tokens
 *  belong to, so a token beside another key is noticed at start. Not a secret. */
export function serializeCredentials(accessToken: string, refreshToken: string | undefined, apiHost: string, keyFingerprint?: string): string {
  return JSON.stringify({
    access_token: accessToken, ...(refreshToken && { refresh_token: refreshToken }), api_host: apiHost,
    ...(keyFingerprint && { key_fingerprint: keyFingerprint }),
  }) + '\n';
}

/** The key fingerprint a saved token file records (null for one written before 1.2.1, or unreadable). */
export function savedKeyFingerprint(raw: string): string | null {
  try {
    const p = JSON.parse(raw.trim()) as { key_fingerprint?: unknown };
    return typeof p.key_fingerprint === 'string' && p.key_fingerprint ? p.key_fingerprint : null;
  } catch { return null; }
}

/** Shaped like an access token: three base64url segments whose first two decode to JSON objects.
 *  Anything else in a token file (null, [], garbage, a token cut short) is damage, not a token. */
export function isTokenShaped(t: unknown): t is string {
  if (typeof t !== 'string') return false;
  const parts = t.split('.');
  if (parts.length !== 3 || !parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p))) return false;
  try {
    return parts.slice(0, 2).every((p) => { const v: unknown = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); return !!v && typeof v === 'object' && !Array.isArray(v); });
  } catch { return false; }
}

/** The saved pair, or null when the file holds no token (empty, damaged, not token-shaped). */
export function parseSavedCredentials(raw: string, apiHost: string): SavedCredentials | null {
  const text = raw.trim();
  if (!text) return null;
  let creds: SavedCredentials & { api_host?: string };
  if (text.startsWith('{')) {
    let parsed: Partial<SavedCredentials & { api_host: string }>;
    try { parsed = JSON.parse(text) as typeof parsed; } catch { return null; }
    if (!isTokenShaped(parsed.access_token)) return null;
    creds = { access_token: parsed.access_token, refresh_token: typeof parsed.refresh_token === 'string' ? parsed.refresh_token : undefined, api_host: typeof parsed.api_host === 'string' ? parsed.api_host : undefined };
  } else {
    if (!isTokenShaped(text)) return null;   // a bare token: a file from before refresh tokens
    creds = { access_token: text };
  }
  const issuedBy = creds.api_host ?? PRODUCTION_HOST;
  if (issuedBy !== apiHost) {
    throw new Error(`The saved Decoy connection belongs to ${issuedBy}, but this bridge is set to ${apiHost}. ` +
      'Use a separate HOME for each environment (or run --logout to remove the saved connection).');
  }
  return creds.refresh_token ? { access_token: creds.access_token, refresh_token: creds.refresh_token } : { access_token: creds.access_token };
}

export function parseKeyFile(raw: string): AgentKeyPair {
  let parsed: Partial<AgentKeyPair>;
  try { parsed = JSON.parse(raw); } catch { throw new Error('The agent key file (~/.decoy/mcp-agent-key.json) is unreadable; restore it from a backup, or run --logout and pair again (a new connection).'); }
  if (!parsed.publicKeySpki || !parsed.privateKeyPem) throw new Error('The agent key file (~/.decoy/mcp-agent-key.json) is incomplete; restore it from a backup, or run --logout and pair again (a new connection).');
  return { publicKeySpki: parsed.publicKeySpki, privateKeyPem: parsed.privateKeyPem };
}

export interface HostedCredentials extends SavedCredentials { api_host: string }

/** The saved connection with the host that issued it, for --logout (null if unreadable). */
export function readAnyCredentials(raw: string): HostedCredentials | null {
  const text = raw.trim();
  if (!text) return null;
  try {
    if (!text.startsWith('{')) return isTokenShaped(text) ? { access_token: text, api_host: PRODUCTION_HOST } : null;
    const p = JSON.parse(text) as Partial<HostedCredentials>;
    if (!isTokenShaped(p.access_token)) return null;
    return { access_token: p.access_token, ...(p.refresh_token && { refresh_token: p.refresh_token }), api_host: p.api_host ?? PRODUCTION_HOST };
  } catch { return null; }
}

/** Revoke the refresh token (the long-lived one) and the access token, at the issuing host. */
export function revokeRequests(c: HostedCredentials, oauthBaseUrl?: string): [string, RequestInit][] {
  // Saved credentials name the host that issued them; a connection from the environment belongs
  // to the API this bridge is configured for, whose OAuth base is passed in.
  const url = oauthBaseUrl ? `${oauthBaseUrl}/revoke` : `https://${c.api_host}/api/oauth/revoke`;
  const req = (token: string, hint: string): [string, RequestInit] =>
    [url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, token_type_hint: hint }), redirect: 'error', signal: AbortSignal.timeout(10_000) }];
  return [...(c.refresh_token ? [req(c.refresh_token, 'refresh_token')] : []), req(c.access_token, 'access_token')];
}

/**
 * What a session does on a 401. Only sessions that started on the shared (saved) token act, and once.
 *
 *   adopt        another session of this process already holds a newer token: use it
 *   adopt-saved  the token FILE holds a different token from the one refused (another bridge
 *                renewed it, or a reconnect replaced it): use that — whatever the refusal said,
 *                and without renewing, so two bridges never spend one refresh token in turn
 *   refresh      the file holds the very token that was refused, and it can be renewed
 *   fail         anything else (revoked with nothing newer on disk, a session on an explicit token)
 */
export function onUnauthorized(o: { status: number; recovery?: string; retried: boolean; usesShared: boolean; bearer: string; shared: string; saved?: string | null }): 'adopt' | 'adopt-saved' | 'refresh' | 'fail' {
  if (o.status !== 401 || o.retried || !o.usesShared) return 'fail';
  if (o.shared && o.shared !== o.bearer) return 'adopt';
  if (o.saved && o.saved !== o.bearer) return 'adopt-saved';
  return o.recovery === 'refresh' ? 'refresh' : 'fail';
}

/**
 * At start, bring the connection's icon in line with this bridge's configuration
 * (DECOY_AGENT_FOR / DECOY_AGENT_URI / DECOY_AGENT_ICON, see agent-identity.ts), with no new
 * pairing: PATCH /api/agent/identity { client_uri?, icon? }.
 *
 * The server takes `icon` at any time and `client_uri` only within the site domain the owner
 * approved; another domain answers 409 CLIENT_URI_DOMAIN_CHANGE_NEEDS_RECONNECT, and then the icon
 * is sent alone and one line says the site changes with --reconnect.
 *
 * It asks only when the configuration (with the API host) differs from the last one the server
 * answered for that connection: one fingerprint per connection (hashes only, no values) in
 * identity-applied.json (0600), kept where that connection's own files are (identityStateFile).
 * A connection with nowhere of its own keeps none and asks at each start. A refusal of
 * the values themselves is recorded too, so it is not resent every start; a missing route, a
 * limit, a server error or no network records nothing and the next start tries again. It never
 * throws and never logs the token or the file.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { AgentIdentity } from './agent-identity.js';
import { writeSecretFile, writeSecretFileIn, readSecretFileIn } from './secret-file.js';

/** A fingerprint of what the server last answered for, per connection. */
export const IDENTITY_APPLIED_FILE = 'identity-applied.json';
/** Connections one record holds at most (the oldest go first). */
const MAX_CONNECTIONS = 20;

/** The record's file. `own`: in ~/.decoy, the bridge's own directory. Otherwise a folder the user
 *  chose: its permissions are never changed, and it is used only if it is safe to write secrets in
 *  (secret-file checkSecretDir), as for the session records. */
export interface IdentityStateFile { file: string; own: boolean }

/** Where a connection's record is kept: the saved connection in ~/.decoy; a credentials file's
 *  beside it (or in DECOY_STATE_DIR); an environment connection's in DECOY_STATE_DIR or beside the
 *  file it writes renewals to. Never ~/.decoy for a connection that is not the saved one: null
 *  when it has nowhere of its own, or when DECOY_STATE_DIR is not an absolute path (the one-shot
 *  commands refuse it too). */
export function identityStateFile(o: { source: string; decoyDir: string; credentialsFile: string | null; stateDir: string | null }): IdentityStateFile | null {
  if (o.source === 'files' || o.source === 'none') return { file: path.join(o.decoyDir, IDENTITY_APPLIED_FILE), own: true };
  if (o.stateDir && !path.isAbsolute(o.stateDir)) return null;
  const dir = o.stateDir || (o.credentialsFile ? path.dirname(o.credentialsFile) : null);
  return dir ? { file: path.join(dir, IDENTITY_APPLIED_FILE), own: false } : null;
}

/** A connection's key in the record: a hash, never the value it was made from. */
const keyOf = (connection: string) => crypto.createHash('sha256').update(`decoy-identity-connection:${connection}`).digest('hex').slice(0, 32);

/** Forget one connection's record (a logout of that connection). */
export function forgetIdentity(file: IdentityStateFile | null, connection: string): void {
  if (!file) return;
  const all = readAll(file);
  if (!(keyOf(connection) in all)) return;
  delete all[keyOf(connection)];
  write(file, all);
}

export type SyncOutcome = 'nothing' | 'unchanged' | 'applied' | 'icon_only' | 'refused' | 'skipped';

export async function syncIdentity(o: {
  identity: AgentIdentity;
  token: string;
  agentApiUrl: string;
  /** Where the record is kept (identityStateFile); null: nowhere, nothing is kept. */
  stateFile: IdentityStateFile | null;
  /** Which connection this is (its key's fingerprint): each connection has its own record. */
  connection?: string;
  fetchImpl?: typeof fetch;
  log?: (line: string) => void;
}): Promise<SyncOutcome> {
  const log = o.log ?? ((l: string) => console.error(l));
  try {
    const want: { client_uri?: string; icon?: string } = {};
    if (o.identity.client_uri) want.client_uri = o.identity.client_uri;
    if (o.identity.icon) want.icon = o.identity.icon;
    if (!want.client_uri && !want.icon) return 'nothing';
    const host = new URL(o.agentApiUrl).host;
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify({ v: 1, host, ...want })).digest('hex');
    const who = keyOf(o.connection ?? '');
    const recordIt = () => { if (o.stateFile) { const all = readAll(o.stateFile); delete all[who]; all[who] = fingerprint; write(o.stateFile, all); } };
    if (o.stateFile && readAll(o.stateFile)[who] === fingerprint) return 'unchanged';

    const send = async (body: typeof want) => (o.fetchImpl ?? fetch)(`${o.agentApiUrl}/identity`, {
      method: 'PATCH',
      headers: { authorization: `Bearer ${o.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    let res = await send(want);
    let outcome: SyncOutcome = 'applied';
    if (res.status === 409 && want.client_uri) {
      const code = ((await res.json().catch(() => ({}))) as { code?: string }).code;
      if (code === 'CLIENT_URI_DOMAIN_CHANGE_NEEDS_RECONNECT') {
        log('[Decoy] The configured site is on another domain than the one approved for this connection, so only its icon was updated. To show the new site, run with --reconnect and approve the Reconnect in the Decoy app.');
        if (!want.icon) { recordIt(); return 'icon_only'; }
        res = await send({ icon: want.icon });
        outcome = 'icon_only';
      }
    }
    if (res.ok) { recordIt(); return outcome; }
    if (res.status === 400 || res.status === 403) { recordIt(); return 'refused'; }
    return 'skipped';
  } catch {
    return 'skipped';
  }
}

/** The record: connection key → fingerprint, both hex. Anything else in the file is not used. */
function readAll(at: IdentityStateFile): Record<string, string> {
  try {
    const raw = at.own ? fs.readFileSync(at.file, 'utf8') : readSecretFileIn(at.file);
    if (raw === null) return {};
    const j = JSON.parse(raw) as { v?: unknown; applied?: unknown };
    if (j.v !== 2 || !j.applied || typeof j.applied !== 'object' || Array.isArray(j.applied)) return {};
    return Object.fromEntries(Object.entries(j.applied as Record<string, unknown>)
      .filter((e): e is [string, string] => /^[0-9a-f]{32}$/.test(e[0]) && typeof e[1] === 'string' && /^[0-9a-f]{64}$/.test(e[1])));
  } catch {
    return {};
  }
}

function write(at: IdentityStateFile, all: Record<string, string>): void {
  try {
    const data = JSON.stringify({ v: 2, applied: Object.fromEntries(Object.entries(all).slice(-MAX_CONNECTIONS)) });
    // ~/.decoy is the bridge's own and kept owner-only; a folder the user chose is written into
    // only when it is safe for secrets, and never changed.
    if (at.own) writeSecretFile(at.file, data); else writeSecretFileIn(at.file, data);
  } catch { /* the next start asks again */ }
}

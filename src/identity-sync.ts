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
 *
 * The site the bridge worked out itself (agent-identity.ts detectedAgent, for a connection with no
 * site configured) goes through syncDetectedIdentity: once per connection, with its own fingerprint
 * in the same record, and only to a connection that shows the robot, or a known provider's matching
 * fallback on an already approved site. Decoy takes a site only from a connection that has none yet, or one on the same domain
 * as its own (lib/agent-icon-update.ts, ruling 2026-10-27 B); any other connection answers 409 and
 * keeps its site, and nothing more is sent or said. The detected icon is sent only when the
 * connection still shows the robot after that (no favicon could be fetched). A missing favicon is
 * retried once on a later UTC day; it is not recorded as a permanent success.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_AGENT_ICON, detectedAgent, type AgentIdentity, type DetectedAgent } from './agent-identity.js';
import { writeSecretFile, writeSecretFileIn, readSecretFileIn } from './secret-file.js';

/** A fingerprint of what the server last answered for, per connection. */
export const IDENTITY_APPLIED_FILE = 'identity-applied.json';
/** Entries one record holds at most, three per connection (the oldest go first). */
const MAX_ENTRIES = 60;

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
/** The key of the site the bridge worked out for that connection (syncDetectedIdentity). */
const detectedKeyOf = (connection: string) => crypto.createHash('sha256').update(`decoy-identity-detected:${connection}`).digest('hex').slice(0, 32);
/** The key of the look at that connection's name (syncNamedIdentity). */
const namedKeyOf = (connection: string) => crypto.createHash('sha256').update(`decoy-identity-named:${connection}`).digest('hex').slice(0, 32);

/** Forget one connection's record (a logout of that connection). */
export function forgetIdentity(file: IdentityStateFile | null, connection: string): void {
  if (!file) return;
  const all = readAll(file);
  const keys = [keyOf(connection), detectedKeyOf(connection), namedKeyOf(connection)].filter((k) => k in all);
  if (!keys.length) return;
  for (const k of keys) delete all[k];
  write(file, all);
}

/** A record kept for one key: whether it already holds this fingerprint (or one of `also`), and how to keep it. */
function recordFor(stateFile: IdentityStateFile | null, key: string, fingerprint: string, also: string[] = []) {
  return {
    seen: () => { if (!stateFile) return false; const held = readAll(stateFile)[key]; return held === fingerprint || also.includes(held); },
    keep: (as: string = fingerprint) => { if (stateFile) { const all = readAll(stateFile); delete all[key]; all[key] = as; write(stateFile, all); } },
  };
}

export type SyncOutcome = 'nothing' | 'unchanged' | 'applied' | 'icon_only' | 'refused' | 'skipped';
/** `kept`: the connection has a site on another domain and keeps it. */
export type DetectedSyncOutcome = 'nothing' | 'unchanged' | 'applied' | 'retry_later' | 'kept' | 'refused' | 'skipped';

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
  now?: () => Date;
}): Promise<SyncOutcome> {
  const log = o.log ?? ((l: string) => console.error(l));
  try {
    const want: { client_uri?: string; icon?: string } = {};
    if (o.identity.client_uri) want.client_uri = o.identity.client_uri;
    if (o.identity.icon) want.icon = o.identity.icon;
    if (!want.client_uri && !want.icon) return 'nothing';
    const host = new URL(o.agentApiUrl).host;
    const fp = (extra: object) => crypto.createHash('sha256').update(JSON.stringify({ v: 2, host, ...want, ...extra })).digest('hex');
    const retryToday = fp({ pending: today(o.now) });
    const record = recordFor(o.stateFile, keyOf(o.connection ?? ''), fp({}), [retryToday]);
    const recordIt = record.keep;
    if (record.seen()) return 'unchanged';

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
    if (res.ok) {
      const after = await res.json().catch(() => ({})) as ConnectionShows;
      if (want.client_uri && outcome === 'applied' && after.has_favicon === false) record.keep(retryToday);
      else recordIt();
      return outcome;
    }
    if (res.status === 400 || res.status === 403) { recordIt(); return 'refused'; }
    return 'skipped';
  } catch {
    return 'skipped';
  }
}

/** What GET /api/agent/identity says the connection shows. */
export interface ConnectionShows { name?: unknown; icon?: unknown; has_favicon?: unknown; has_site?: unknown }

/** It shows the robot: no favicon, and no picked icon but the robot. */
const showsRobot = (s: ConnectionShows): boolean => s.has_favicon !== true && (s.icon === null || s.icon === undefined || s.icon === DEFAULT_AGENT_ICON);

/** A known provider's fallback on a site already approved for this connection. The connection's
 * own name, not just the current MCP host, must identify the same provider. A site-free picked
 * icon, a renamed connection, a custom glyph or an existing favicon is kept. Only the site is
 * resent: the server checks its approved domain before fetching; neither the glyph nor name is
 * replaced. There is no assertion that a matching glyph was automatically chosen. */
function showsProviderFallback(s: ConnectionShows, d: DetectedAgent): boolean {
  if (s.has_favicon === true || s.has_site !== true || !d.icon || s.icon !== d.icon) return false;
  const own = typeof s.name === 'string' ? detectedAgent({ name: s.name }) : null;
  return own?.client_uri === d.client_uri && own.icon === d.icon;
}

const today = (now?: () => Date): string => (now ?? (() => new Date()))().toISOString().slice(0, 10);

/** GET /api/agent/identity: what the connection shows, `absent` for a server without the read, or `skip`. */
async function readShows(o: { token: string; agentApiUrl: string; fetchImpl?: typeof fetch }): Promise<ConnectionShows | 'absent' | 'refused' | 'skip'> {
  const res = await (o.fetchImpl ?? fetch)(`${o.agentApiUrl}/identity`, { method: 'GET', headers: { authorization: `Bearer ${o.token}` } });
  if (res.status === 404 || res.status === 405) return 'absent';
  if (res.status === 403) return 'refused';
  if (!res.ok) return 'skip';
  const shows = (await res.json().catch(() => null)) as ConnectionShows | null;
  return shows && typeof shows === 'object' && typeof shows.name === 'string' ? shows : 'skip';
}

/**
 * Send the site the bridge worked out (agent-identity.ts detectedIdentity: already without what is
 * configured) to a connection that shows the robot or an eligible known provider fallback.
 * What the connection shows is read first (GET /api/agent/identity, or `shows` when the caller read
 * it): an existing favicon or unrelated picked icon is left as it is. Then PATCH { client_uri } alone, and { icon } only
 * when the answer says it still shows the robot. A 409 (a site on another domain) leaves it as it
 * is, says nothing, and is recorded; a refusal (400, 403) is recorded. A server without the read
 * (404, 405) or without the site rule yet (503) is asked again the next day (UTC); a limit, an
 * error, an expired token or no network records nothing. A successful site response without a
 * favicon is retried on a later UTC day. Never throws, never logs.
 */
export async function syncDetectedIdentity(o: {
  detected: DetectedAgent | null;
  token: string;
  agentApiUrl: string;
  stateFile: IdentityStateFile | null;
  connection?: string;
  fetchImpl?: typeof fetch;
  /** What the connection shows, when the caller already read it. */
  shows?: ConnectionShows;
  /** Test seam: the clock for the day a server that cannot take a site is asked again. */
  now?: () => Date;
}): Promise<DetectedSyncOutcome> {
  try {
    const d = o.detected;
    if (!d?.client_uri) return 'nothing';
    const host = new URL(o.agentApiUrl).host;
    // v2 reconsiders the old permanent "kept" record for a provider fallback with no favicon.
    const fp = (extra: object) => crypto.createHash('sha256').update(JSON.stringify({ v: 2, detected: true, host, client_uri: d.client_uri, icon: d.icon ?? null, ...extra })).digest('hex');
    const notYetToday = fp({ absent: today(o.now) });
    const record = recordFor(o.stateFile, detectedKeyOf(o.connection ?? ''), fp({}), [notYetToday]);
    if (record.seen()) return 'unchanged';

    const shows = o.shows ?? await readShows(o);
    if (shows === 'absent') { record.keep(notYetToday); return 'nothing'; }
    if (shows === 'refused') { record.keep(); return 'refused'; }
    if (shows === 'skip') return 'skipped';
    if (!showsRobot(shows) && !showsProviderFallback(shows, d)) { record.keep(); return 'kept'; }

    const send = async (body: { client_uri?: string; icon?: string }) => (o.fetchImpl ?? fetch)(`${o.agentApiUrl}/identity`, {
      method: 'PATCH',
      headers: { authorization: `Bearer ${o.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const res = await send({ client_uri: d.client_uri });
    if (res.status === 409 || res.status === 503) {
      const code = ((await res.json().catch(() => ({}))) as { code?: string }).code;
      if (code === 'CLIENT_URI_DOMAIN_CHANGE_NEEDS_RECONNECT') { record.keep(); return 'kept'; }
      if (code === 'IDENTITY_SITE_UNAVAILABLE') { record.keep(notYetToday); return 'nothing'; }
      return 'skipped';
    }
    if (res.status === 400 || res.status === 403) { record.keep(); return 'refused'; }
    if (!res.ok) return 'skipped';
    const after = (await res.json().catch(() => ({}))) as ConnectionShows;
    if (d.icon && after.has_favicon === false && showsRobot(after) && d.icon !== after.icon) {
      const r = await send({ icon: d.icon });
      if (!r.ok && r.status !== 400 && r.status !== 403) return 'skipped';
    }
    // The site can be accepted while its favicon fetch fails, is limited, or is still pending.
    // Retain one daily attempt, not a permanent success. The next run re-reads identity before
    // doing anything, and existing favicons/customizations still win.
    if (after.has_favicon !== true) { record.keep(notYetToday); return 'retry_later'; }
    record.keep();
    return 'applied';
  } catch {
    return 'skipped';
  }
}

/**
 * With nothing else to go on, the site the connection's own name says: GET /api/agent/identity answers
 * the name the owner approved (or renamed the connection to) and what it shows. A connection that
 * shows the robot or an eligible known fallback and whose name `known` maps to a site gets it through syncDetectedIdentity; any
 * other is left as it is. Asked once per connection and `table` (the known agents: a bridge that
 * knows more asks again). A server without the read yet (404, 405) is asked again the next day
 * (UTC); a limit, an error, an expired token or no network records nothing, nor does a site that did
 * not land. Never throws.
 */
export async function syncNamedIdentity(o: {
  /** The site a connection name says (detectedIdentity of detectedAgent({ name })), or null. */
  known: (name: string) => DetectedAgent | null;
  /** What `known` knows, as a string: a change asks again. */
  table: string;
  token: string;
  agentApiUrl: string;
  stateFile: IdentityStateFile | null;
  connection?: string;
  fetchImpl?: typeof fetch;
  /** Test seam: the clock for the day a missing route is asked again. */
  now?: () => Date;
}): Promise<DetectedSyncOutcome> {
  try {
    const host = new URL(o.agentApiUrl).host;
    const fp = (extra: object) => crypto.createHash('sha256').update(JSON.stringify({ v: 2, named: true, host, table: o.table, ...extra })).digest('hex');
    const absentToday = fp({ absent: today(o.now) });
    const record = recordFor(o.stateFile, namedKeyOf(o.connection ?? ''), fp({}), [absentToday]);
    if (record.seen()) return 'unchanged';
    const shows = await readShows(o);
    if (shows === 'absent') { record.keep(absentToday); return 'nothing'; }
    if (shows === 'refused') { record.keep(); return 'refused'; }
    if (shows === 'skip') return 'skipped';
    if (shows.has_favicon === true) { record.keep(); return 'kept'; }
    const detected = o.known(shows.name as string);
    if (!detected) { record.keep(); return 'nothing'; }
    const out = await syncDetectedIdentity({ detected, shows, token: o.token, agentApiUrl: o.agentApiUrl, stateFile: o.stateFile, connection: o.connection, fetchImpl: o.fetchImpl, now: o.now });
    // An alternate launch may already have tried the same detected identity today. Its
    // "unchanged" result is not evidence a favicon landed, so do not turn it into a permanent
    // name-only success. This path just read a missing favicon; look again on a later day.
    if (out === 'retry_later' || out === 'nothing' || out === 'unchanged') record.keep(absentToday);
    else if (out !== 'skipped') record.keep();
    return out;
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
    const data = JSON.stringify({ v: 2, applied: Object.fromEntries(Object.entries(all).slice(-MAX_ENTRIES)) });
    // ~/.decoy is the bridge's own and kept owner-only; a folder the user chose is written into
    // only when it is safe for secrets, and never changed.
    if (at.own) writeSecretFile(at.file, data); else writeSecretFileIn(at.file, data);
  } catch { /* the next start asks again */ }
}

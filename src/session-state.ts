// One session's memory habits, kept between runs of `decoy-mcp-server call`.
//
// A connected MCP client is one session, and the bridge keeps its habits in memory
// (src/memory-hygiene.ts): the summary once, a reminder to read after 3 calls, a reminder to save
// after 8, the counts in my_permissions. A `call` is one process per tool call, so the same
// numbers are kept in one small file and a sequence of calls is one session.
//
// The file: <dir>/mcp-session.<key>.<session>.json
//   <dir>      DECOY_STATE_DIR when set; else the directory of DECOY_CREDENTIALS_FILE when the
//              connection comes from one; else ~/.decoy
//   <key>      the first 16 hex characters of the agent key's fingerprint (not a secret)
//   <session>  "default", or "s-" and 16 hex characters of a hash of DECOY_SESSION
//
// What it holds: counts, yes/no flags, times, and the fingerprint of the access last seen (a
// version number or a hash). Never memory text, a name, the id of a memory, topic or account, a
// token or a key, and never DECOY_SESSION itself. It is read strictly: a file that is not exactly
// this shape is a new session. Written like the files beside it (src/secret-file.ts): owner-only,
// a temp file renamed into place, never through a link, under a lock so runs at the same time
// each count.
//
// When a session ends: one named by DECOY_SESSION, when the host stops using that name. The
// default one, after SESSION_IDLE_MS without a call (the time after which the running bridge
// drops an idle MCP session). Files not written for SESSION_KEEP_MS are removed, and at most
// SESSION_MAX_FILES are kept.

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { ConfigError } from './api-config.js';
import { readSecretFile, readSecretFileIn, writeSecretFile, writeSecretFileIn, removeLeftoverTemps, withFileLock } from './secret-file.js';
import type { MemoryCounts } from './memory-hygiene.js';

export const SESSION_ENV = { dir: 'DECOY_STATE_DIR', session: 'DECOY_SESSION' } as const;
/** The default session ends after this long with no call. */
export const SESSION_IDLE_MS = 60 * 60_000;
/** A session file nobody wrote for this long is removed. */
export const SESSION_KEEP_MS = 7 * 24 * 60 * 60_000;
/** At most this many session files are kept in one directory: the oldest go first. */
export const SESSION_MAX_FILES = 32;
/** A file larger than this is not a session record. */
export const SESSION_MAX_BYTES = 1024;
/** How long a run waits for another run's update of the same file, and when a lock counts as left behind. */
const LOCK = { waitMs: 2_000, staleMs: 10_000, pollMs: 20 };

const SUMMARY = ['not_started', 'delivered', 'nothing_to_send', 'not_sent'] as const;
export interface SessionState {
  v: 1;
  /** When this session's first run started, and when its last one ended. */
  started_at: string;
  last_call_at: string;
  tool_calls: number;
  /** Tool calls that are not memory tools. */
  other_calls: number;
  memory_reads: number;
  memory_saves: number;
  /** Links written with connect_topics (the session's limit holds across runs). */
  links_added: number;
  /** When a memory was last saved or corrected in this session. */
  last_save_at: string | null;
  /** The summary of memories: not sent yet, sent, nothing to send, or not sent because the session read memory first. */
  summary: typeof SUMMARY[number];
  /** A result said the summary was still loading. */
  summary_loading_said: boolean;
  read_reminder_sent: boolean;
  save_reminder_sent: boolean;
  first_step_said: boolean;
  /** When a `--context` run of this session last read Decoy. */
  context_at: string | null;
  /** The fingerprint of the access this session last saw (src/access-summary.ts accessFingerprint). */
  access: string | null;
}

const TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const FINGERPRINT = /^[hv]:[\w.:-]{1,128}$/;
const KEYS: ReadonlyArray<keyof SessionState> = ['v', 'started_at', 'last_call_at', 'tool_calls', 'other_calls', 'memory_reads', 'memory_saves', 'links_added', 'last_save_at',
  'summary', 'summary_loading_said', 'read_reminder_sent', 'save_reminder_sent', 'first_step_said', 'context_at', 'access'];

export function freshSession(now: Date): SessionState {
  const at = now.toISOString();
  return { v: 1, started_at: at, last_call_at: at, tool_calls: 0, other_calls: 0, memory_reads: 0, memory_saves: 0, links_added: 0, last_save_at: null,
    summary: 'not_started', summary_loading_said: false, read_reminder_sent: false, save_reminder_sent: false, first_step_said: false, context_at: null, access: null };
}

export function serializeSessionState(s: SessionState): string {
  return JSON.stringify(Object.fromEntries(KEYS.map((k) => [k, s[k]]))) + '\n';
}

/** The file's contents as a session record, or null when they are anything else. Every field is
 *  checked: a number is a count, a time is a time, and nothing else is carried. */
export function parseSessionState(text: string): SessionState | null {
  if (text.length > SESSION_MAX_BYTES) return null;
  let p: Record<string, unknown>;
  try { const j: unknown = JSON.parse(text); if (!j || typeof j !== 'object' || Array.isArray(j)) return null; p = j as Record<string, unknown>; } catch { return null; }
  const names = Object.keys(p);
  if (names.length !== KEYS.length || !KEYS.every((k) => Object.hasOwn(p, k))) return null;
  const count = (v: unknown) => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 1_000_000_000;
  const time = (v: unknown) => typeof v === 'string' && TIME.test(v) && Number.isFinite(Date.parse(v));
  const flag = (v: unknown) => typeof v === 'boolean';
  if (p.v !== 1 || !time(p.started_at) || !time(p.last_call_at)) return null;
  if (![p.tool_calls, p.other_calls, p.memory_reads, p.memory_saves, p.links_added].every(count)) return null;
  if (![p.summary_loading_said, p.read_reminder_sent, p.save_reminder_sent, p.first_step_said].every(flag)) return null;
  if (typeof p.summary !== 'string' || !(SUMMARY as readonly string[]).includes(p.summary)) return null;
  if (p.last_save_at !== null && !time(p.last_save_at)) return null;
  if (p.context_at !== null && !time(p.context_at)) return null;
  if (p.access !== null && !(typeof p.access === 'string' && FINGERPRINT.test(p.access))) return null;
  return Object.fromEntries(KEYS.map((k) => [k, p[k]])) as unknown as SessionState;
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
/** The session file's name for an agent key and a session (`sessionId`: DECOY_SESSION, when set). */
export function sessionFileName(keyFingerprint: string, sessionId?: string): string {
  const key = /^[0-9a-f]{16,}$/.test(keyFingerprint) ? keyFingerprint.slice(0, 16) : sha256(keyFingerprint).slice(0, 16);
  return `mcp-session.${key}.${sessionId ? `s-${sha256(sessionId).slice(0, 16)}` : 'default'}.json`;
}
const SESSION_FILE = /^mcp-session\.[0-9a-f]{16}\.(default|s-[0-9a-f]{16})\.json$/;

/** Where the session file goes. `own`: the bridge's own directory (~/.decoy), which it keeps
 *  owner-only; any other directory is the caller's, and is checked instead (src/secret-file.ts). */
export function sessionDir(env: Record<string, string | undefined>, home: string, credentialsFile: string | null): { dir: string; own: boolean } {
  const set = env[SESSION_ENV.dir]?.trim();
  if (set) {
    if (!path.isAbsolute(set)) throw new ConfigError(SESSION_ENV.dir, `${SESSION_ENV.dir} must be an absolute path to a directory this process may write.`);
    return { dir: set, own: false };
  }
  return credentialsFile ? { dir: path.dirname(credentialsFile), own: false } : { dir: path.join(home, '.decoy'), own: true };
}

export interface SessionStore {
  readonly file: string;
  /** The session as the file has it now; a new one when there is no file, when it is not a
   *  session record, or when the default session has sat idle. Never throws. */
  load(): SessionState;
  /** Change the record: read again under the lock, apply, write. false when it was not written
   *  (the directory cannot be used, or another run kept the lock): the caller carries on. */
  update(change: (now: SessionState) => SessionState, lock?: { waitMs?: number }): Promise<boolean>;
}

export function openSessionStore(o: { dir: string; own: boolean; keyFingerprint: string; sessionId?: string; now?: () => number }): SessionStore {
  const file = path.join(o.dir, sessionFileName(o.keyFingerprint, o.sessionId));
  const now = o.now ?? Date.now;
  const read = (): SessionState => {
    let state: SessionState | null = null;
    try { state = parseSessionState((o.own ? readSecretFile(file) : readSecretFileIn(file)) ?? ''); } catch { /* a link, another user's file: not read */ }
    const at = now();
    // A named session is the host's to end. The default one ends by the clock (and one dated in
    // the future is not this session's either).
    if (state && !o.sessionId && (at - Date.parse(state.last_call_at) > SESSION_IDLE_MS || Date.parse(state.last_call_at) - at > 60_000)) state = null;
    return state ?? freshSession(new Date(at));
  };
  /** Old session files, their locks and temp files; then the oldest beyond the limit. Only files named as session files. */
  const prune = (): void => {
    let names: string[];
    try { names = fs.readdirSync(o.dir).filter((n) => SESSION_FILE.test(n)); } catch { return; }
    const found: Array<{ full: string; at: number }> = [];
    for (const name of names) {
      const full = path.join(o.dir, name);
      try { const st = fs.lstatSync(full); if (st.isFile()) found.push({ full, at: st.mtimeMs }); } catch { /* gone */ }
    }
    found.sort((a, b) => b.at - a.at);
    const drop = (full: string) => {
      try { fs.rmSync(full, { force: true }); fs.rmSync(`${full}.lock`, { force: true }); removeLeftoverTemps(full, 0); } catch { /* not ours to remove */ }
    };
    for (const [i, f] of found.entries()) if (f.full !== file && (now() - f.at > SESSION_KEEP_MS || i >= SESSION_MAX_FILES)) drop(f.full);
  };
  return {
    file,
    load: () => { try { return read(); } catch { return freshSession(new Date(now())); } },
    async update(change, lock) {
      try {
        const got = await withFileLock(file, async () => {
          const next = serializeSessionState(change(read()));
          if (o.own) writeSecretFile(file, next); else writeSecretFileIn(file, next);
          removeLeftoverTemps(file);
          prune();
        }, { ...LOCK, ...lock });
        return got.held;
      } catch { return false; }
    },
  };
}

/** A session record as the counts a MemorySession starts from. */
export function countsOf(s: SessionState): MemoryCounts {
  return { toolCalls: s.tool_calls, otherCalls: s.other_calls, reads: s.memory_reads, saves: s.memory_saves, brief: s.summary, toldLoading: s.summary_loading_said,
    readNudged: s.read_reminder_sent, saveNudged: s.save_reminder_sent, firstStepSaid: s.first_step_said, links: s.links_added };
}

/** The record after one run: what the run added to the counts it started from (`before` → `after`)
 *  is added to what the file holds now, so runs at the same time each count. A flag once set
 *  stays set, and the summary's state moves only when this run moved it. */
export function afterRun(held: SessionState, before: MemoryCounts, after: MemoryCounts, at: Date, access: string | null): SessionState {
  const add = (n: number, was: number, is: number) => Math.min(1_000_000_000, n + Math.max(0, is - was));
  const saved = after.saves > before.saves;
  return {
    ...held,
    last_call_at: at.toISOString(),
    tool_calls: add(held.tool_calls, before.toolCalls, after.toolCalls),
    other_calls: add(held.other_calls, before.otherCalls, after.otherCalls),
    memory_reads: add(held.memory_reads, before.reads, after.reads),
    memory_saves: add(held.memory_saves, before.saves, after.saves),
    links_added: add(held.links_added, before.links, after.links),
    last_save_at: saved ? at.toISOString() : held.last_save_at,
    summary: after.brief !== before.brief ? after.brief : held.summary,
    summary_loading_said: held.summary_loading_said || after.toldLoading,
    read_reminder_sent: held.read_reminder_sent || after.readNudged,
    save_reminder_sent: held.save_reminder_sent || after.saveNudged,
    first_step_said: held.first_step_said || after.firstStepSaid,
    access: access && FINGERPRINT.test(access) ? access : held.access,
  };
}

/** Remove the session files in a directory (all of them, or one agent key's), with a lock or temp
 *  file left beside them. Nothing else there is touched. Returns what was removed. */
export function removeSessionFiles(dir: string, keyFingerprint?: string): string[] {
  const removed: string[] = [];
  let names: string[];
  try { names = fs.readdirSync(dir).filter((n) => SESSION_FILE.test(n)); } catch { return removed; }
  const only = keyFingerprint ? `mcp-session.${keyFingerprint.slice(0, 16)}.` : null;
  for (const name of names) {
    if (only && !name.startsWith(only)) continue;
    const full = path.join(dir, name);
    try {
      if (!fs.lstatSync(full).isFile()) continue;
      fs.rmSync(full, { force: true }); fs.rmSync(`${full}.lock`, { force: true }); removeLeftoverTemps(full, 0);
      removed.push(full);
    } catch { /* gone, or not ours */ }
  }
  return removed;
}

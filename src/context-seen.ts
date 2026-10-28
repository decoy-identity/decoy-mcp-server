// What the last `--context` run on this machine saw, kept so the next run can say what changed
// since, and so a session can tell whether the first step has ever been run here.
//
// One small file beside the token: ~/.decoy/mcp-context-seen
//   line 1  when that run finished (UTC)
//   line 2  how many memories it could read ("-" when the connection could not read memories)
//   line 3  the time of the newest change among them, as the server gave it ("-" when none)
//   line 4  a hash of their ids and revisions
//   line 5  the fingerprint of the access it saw (src/access-summary.ts accessFingerprint; "-" when none)
//   line 6  the fingerprint of this agent's key, so a file written for another connection is ignored
// A run that ended at its time limit before Decoy answered is recorded too, when no run is
// recorded yet: line 2 is "?", lines 3 to 5 are "-". It says that the first step is run on this
// machine, and is nothing a later run compares itself with.
// No memory text, name, category or id is in it, and nothing in it is a secret. It is written and
// read like the files beside it (src/secret-file.ts): owner-only, a temp file renamed into place,
// never through a link. Nothing else reads it, and the token, key and id files are never touched
// from here. A connection supplied by the environment has no file: nothing is kept for it.

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { keyFingerprint, type Connection } from './connection.js';
import { readSecretFile, writeSecretFile } from './secret-file.js';

export const CONTEXT_SEEN_FILE = 'mcp-context-seen';

export interface ContextSeen {
  /** When the run finished. */
  at: string;
  /** How many memories it could read; null when the connection could not read memories. */
  count: number | null;
  /** The newest change among them (the server's time), or null when there were none. */
  latest: string | null;
  /** A hash of their ids and revisions: 32 hex characters. */
  ids: string;
  /** The access fingerprint it saw, or null. */
  access: string | null;
}
export interface ContextSeenStore {
  /** What the last run that got an answer saw; null when there is none. */
  load(): ContextSeen | null;
  save(seen: ContextSeen): void;
  /** Whether any run is recorded: one that got an answer, or one that ended at its time limit. */
  ran(): boolean;
  /** Record a run that ended at its time limit. A record that is already there is left as it is. */
  saveUnanswered(at: Date): void;
}

const TIME = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$/;
const HASH = /^[0-9a-f]{32}$/;
const FINGERPRINT = /^[hv]:[\w.:-]{1,128}$/;

/** What a run saw, from the memories it read: nothing of what they say. */
export function memoriesSeen(records: readonly { id: string; rev: number; updatedAt: string }[], at: Date, access: string | null): ContextSeen {
  const ids = createHash('sha256').update(records.map(r => `${r.id}:${r.rev}`).sort().join('\n')).digest('hex').slice(0, 32);
  const times = records.map(r => Date.parse(r.updatedAt)).filter(Number.isFinite);
  const latest = times.length ? new Date(Math.max(...times)).toISOString() : null;
  return { at: at.toISOString(), count: records.length, latest, ids, access: access && FINGERPRINT.test(access) ? access : null };
}

/** What a run saw on a connection that could not read memories: that it ran, and the access. */
export function noMemoriesSeen(at: Date, access: string | null): ContextSeen {
  return { ...memoriesSeen([], at, access), count: null };
}

export function serializeContextSeen(seen: ContextSeen, key: string): string {
  return `${seen.at}\n${seen.count ?? '-'}\n${seen.latest ?? '-'}\n${seen.ids}\n${seen.access ?? '-'}\n${key}\n`;
}

/** The file's contents as what a run saw; null when it is not one, or was written for another key. */
export function parseContextSeen(text: string, key: string): ContextSeen | null {
  const [at, count, latest, ids, access, forKey] = text.split('\n').map(l => l.trim());
  if (forKey !== key || !TIME.test(at ?? '') || !/^(\d{1,9}|-)$/.test(count ?? '') || !HASH.test(ids ?? '')) return null;
  if (latest !== '-' && !TIME.test(latest ?? '')) return null;
  if (access !== '-' && !FINGERPRINT.test(access ?? '')) return null;
  return { at, count: count === '-' ? null : Number(count), latest: latest === '-' ? null : latest, ids, access: access === '-' ? null : access };
}

/** The record of a run that ended at its time limit before Decoy answered: when, and for which key. */
export const serializeUnansweredRun = (at: Date, key: string): string => `${at.toISOString()}\n?\n-\n-\n-\n${key}\n`;
export function isUnansweredRun(text: string, key: string): boolean {
  const [at, count, , , , forKey] = text.split('\n').map(l => l.trim());
  return forKey === key && count === '?' && TIME.test(at ?? '');
}

export function contextSeenStore(c: Connection): ContextSeenStore | undefined {
  if (c.source === 'environment' || c.source === 'environment-token' || !c.keyPair) return undefined;
  const file = path.join(path.dirname(c.paths.tokenFile), CONTEXT_SEEN_FILE);
  const key = keyFingerprint(c.keyPair);
  // Only beside a connection that is itself saved: nothing is written for one held in memory.
  const write = (text: string) => { if (!c.unsaved() && fs.existsSync(c.paths.tokenFile)) writeSecretFile(file, text); };
  const store: ContextSeenStore = {
    load() { return parseContextSeen(readSecretFile(file) ?? '', key); },
    save(seen) { write(serializeContextSeen(seen, key)); },
    ran() { const text = readSecretFile(file) ?? ''; return parseContextSeen(text, key) !== null || isUnansweredRun(text, key); },
    saveUnanswered(at) { if (!store.ran()) write(serializeUnansweredRun(at, key)); },
  };
  return store;
}

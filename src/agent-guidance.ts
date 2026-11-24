// Decoy's guidance for agents changes; a connection is told the newest change once.
//
// The newest entry of www.decoys.me/agent-guidance.json (`changes`: { date, summary, pages }) becomes
// one line of the brief asking to re-read its pages and keep memories and pages current. It is said
// until this connection has been shown it, then not again until a newer change is published.
//
// The file is fetched with a plain GET (no token, no cookie, nothing about the person), at most
// once an hour on this computer: the answer (or that there was none) is kept with its time in
// ~/.decoy/cache/guidance-latest, which every bridge process reads first. An answer that is not
// that file is no change. A brief never waits long for it: what has not arrived in time is said
// the next time.
//
// What was shown is kept per agent key, one line, in ~/.decoy/cache/guidance-seen-<24 hex>
// (owner-only, like the files beside it): the change's date and a hash of its summary, nothing
// else. Without a key it is kept in this process only. A file that cannot be read or written never
// fails anything: the line is then said again.

import path from 'node:path';
import { createHash } from 'node:crypto';
import { oneLine } from './context-graph.js';
import { readSecretFile, writeSecretFile } from './secret-file.js';
import { PLAIN_VERSION } from './api-error.js';

/** Where Decoy publishes its guidance for agents. */
export const GUIDANCE_URL = 'https://www.decoys.me/agent-guidance.json';
/** The site a change's page is read on. */
const SITE = 'https://www.decoys.me';
/** The longest summary said in the line. */
export const GUIDANCE_SUMMARY_CHARS = 300;
/** The largest answer read as the guidance file. */
const MAX_CHARS = 512 * 1024;
/** How long the request may take. */
const FETCH_TIMEOUT_MS = 5000;
/** How long an answer (or no answer) is used before the file is asked for again. */
export const GUIDANCE_KEEP_MS = 60 * 60_000;

export interface GuidanceChange {
  /** The day it was published (YYYY-MM-DD). */
  date: string;
  /** What changed, on one line. */
  summary: string;
  /** The page to read: the first one the change names, or the guidance file. */
  url: string;
  /** The date and a hash of the summary: what is kept once it is shown. */
  key: string;
}

const DATE = /^\d{4}-\d\d-\d\d$/;
/** A page on the site: a plain path (never `//`, which would name another host), with an optional anchor. */
const PAGE = /^\/(?!\/)[A-Za-z0-9._~\/-]{0,200}(#[A-Za-z0-9._-]{1,100})?$/;

/** The newest change in a guidance file: the latest date, the first listed on that date. */
export function newestChange(doc: unknown): GuidanceChange | null {
  const changes = doc && typeof doc === 'object' ? (doc as { changes?: unknown }).changes : null;
  if (!Array.isArray(changes)) return null;
  let best: { date: string; summary: string; pages: unknown } | null = null;
  for (const c of changes) {
    if (!c || typeof c !== 'object') continue;
    const { date, summary, pages } = c as { date?: unknown; summary?: unknown; pages?: unknown };
    if (typeof date !== 'string' || !DATE.test(date) || typeof summary !== 'string') continue;
    if (!best || date > best.date) best = { date, summary, pages };
  }
  if (!best) return null;
  const summary = oneLine(best.summary, GUIDANCE_SUMMARY_CHARS);
  if (!summary) return null;
  const first = Array.isArray(best.pages) ? best.pages.find((p): p is string => typeof p === 'string' && PAGE.test(p)) : undefined;
  const key = `${best.date}:${createHash('sha256').update(summary).digest('hex').slice(0, 16)}`;
  return { date: best.date, summary, url: first ? `${SITE}${first}` : GUIDANCE_URL, key };
}

/** The brief's line for a change. */
export const guidanceLine = (c: GuidanceChange): string => `Decoy's guidance changed on ${c.date}. Re-read the pages at ${c.url} and bring the person's memories and pages up to date.`;

/** Whether a change is newer than the one last shown (null: none shown yet). */
export function isNewer(change: GuidanceChange, shown: string | null): boolean {
  if (!shown) return true;
  const [date] = shown.split(':');
  return change.date > date || (change.date === date && change.key !== shown);
}

export interface GuidanceFeed {
  /** The newest change, when it has arrived within `waitMs`; null when there is none or not yet. */
  newest(waitMs: number): Promise<GuidanceChange | null>;
  /** A released bridge version from the same document, independent of its change history. */
  latestBridge?(waitMs: number): Promise<string | null>;
}

/** The guidance file, fetched when first asked for and then at most once per GUIDANCE_KEEP_MS. */
export function guidanceFeed(opts: { url?: string; fetch?: typeof fetch; now?: () => number;
  /** Where the last answer is kept between processes (GUIDANCE_LATEST_FILE in the cache folder); none: this process only. */
  cacheFile?: string | null } = {}): GuidanceFeed {
  const url = opts.url ?? GUIDANCE_URL;
  const now = opts.now ?? Date.now;
  type Facts = { change: GuidanceChange | null; latest: string | null };
  const release = (v: unknown): string | null => typeof v === 'string' && PLAIN_VERSION.test(v) ? v : null;
  const empty: Facts = { change: null, latest: null };
  let held: { at: number; answer: Promise<Facts> } | null = null;
  /** What another process fetched within the hour, if anything is kept. */
  const kept = (): { at: number; facts: Facts } | null => {
    if (!opts.cacheFile) return null;
    try {
      const o = JSON.parse(readSecretFile(opts.cacheFile) ?? 'null') as { at?: unknown; change?: unknown; latest?: unknown } | null;
      if (!o || typeof o.at !== 'number' || !Number.isFinite(o.at) || o.at > now()) return null;
      // Read back through the same checks as the file itself.
      const change = o.change === null ? null : newestChange({ changes: [o.change] });
      if (o.change !== null && !change) return null;
      return { at: o.at, facts: { change, latest: release(o.latest) } };
    } catch { return null; }
  };
  const keep = (at: number, { change, latest }: Facts) => {
    if (!opts.cacheFile) return;
    const raw = change ? { date: change.date, summary: change.summary, pages: [change.url.startsWith(`${SITE}/`) && change.url !== GUIDANCE_URL ? change.url.slice(SITE.length) : ''] } : null;
    try { writeSecretFile(opts.cacheFile, `${JSON.stringify({ at, change: raw, latest })}\n`); } catch { /* this process only */ }
  };
  const load = async (): Promise<Facts> => {
    try {
      const res = await (opts.fetch ?? fetch)(url, { headers: { accept: 'application/json' }, redirect: 'follow', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      // Only Decoy's own site answers for it, after any redirect.
      const from = res.url ? new URL(res.url) : new URL(url);
      if (!res.ok || from.protocol !== 'https:' || !/(^|\.)decoys\.me$/.test(from.hostname)) return empty;
      // Said too large before it is read, when the answer says how large it is.
      if (Number(res.headers?.get?.('content-length') ?? 0) > MAX_CHARS) return empty;
      const text = await res.text();
      if (text.length > MAX_CHARS) return empty;
      const doc = JSON.parse(text);
      return { change: newestChange(doc), latest: release(doc?.bridge?.latest) };
    } catch { return empty; }
  };
  const facts = async (waitMs: number): Promise<Facts> => {
    if (!held || now() - held.at >= GUIDANCE_KEEP_MS) {
      const k = kept();
      if (k && now() - k.at < GUIDANCE_KEEP_MS) held = { at: k.at, answer: Promise.resolve(k.facts) };
      else {
        const at = now();
        held = { at, answer: load().then((c) => { keep(at, c); return c; }) };
      }
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([held.answer, new Promise<Facts>((resolve) => { timer = setTimeout(() => resolve(empty), waitMs); timer.unref?.(); })]);
    } finally { if (timer) clearTimeout(timer); }
  };
  return {
    newest: async waitMs => (await facts(waitMs)).change,
    latestBridge: async waitMs => (await facts(waitMs)).latest,
  };
}

export interface GuidanceSeenStore {
  /** The key of the change last shown to this connection, or null. */
  load(): string | null;
  save(key: string): void;
}

const SEEN_LINE = /^\d{4}-\d\d-\d\d:[0-9a-f]{16}$/;
/** The file name for one agent key, under the cache folder. */
export const guidanceSeenFileName = (keyFingerprint: string): string =>
  `guidance-seen-${createHash('sha256').update(`guidance-seen:${keyFingerprint}`).digest('hex').slice(0, 24)}`;
/** Its name, and the file the last answer is kept in, as a pattern (for removing them at logout),
 *  with the temporary name a write that was cut short leaves (src/secret-file.ts). */
export const GUIDANCE_SEEN_FILE = /^\.?(guidance-seen-[0-9a-f]{24}|guidance-latest)(\.[0-9a-f]+\.tmp)?$/;
/** The file the last answer is kept in, in the cache folder. */
export const GUIDANCE_LATEST_FILE = 'guidance-latest';

/** The record of what was shown: a file per agent key in `dir`, or this process only without a key. */
export function guidanceSeenStore(dir: string | null, keyFingerprint: string | null): GuidanceSeenStore {
  let kept: string | null = null;
  const file = dir && keyFingerprint ? path.join(dir, guidanceSeenFileName(keyFingerprint)) : null;
  return {
    load() {
      if (!file) return kept;
      try {
        const line = (readSecretFile(file) ?? '').trim();
        return SEEN_LINE.test(line) ? line : kept;
      } catch { return kept; }
    },
    save(key) {
      if (!SEEN_LINE.test(key)) return;
      kept = key;
      if (!file) return;
      try { writeSecretFile(file, `${key}\n`); } catch { /* kept in this process only */ }
    },
  };
}

/** The line to add to a brief, if a change is due; `shown()` records it once it was delivered. */
export async function dueGuidance(feed: GuidanceFeed | null | undefined, seen: GuidanceSeenStore | null | undefined, waitMs: number):
  Promise<{ line: string; shown: () => void } | null> {
  if (!feed) return null;
  const change = await feed.newest(waitMs).catch(() => null);
  if (!change) return null;
  let last: string | null = null;
  try { last = seen?.load() ?? null; } catch { /* nothing kept */ }
  if (!isNewer(change, last)) return null;
  return { line: guidanceLine(change), shown: () => { try { seen?.save(change.key); } catch { /* said again next time */ } } };
}

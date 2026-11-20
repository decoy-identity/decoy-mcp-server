// Pages, as the Decoy app reads them.
//
// A topic's page is the memory filed on that topic whose title is the topic's name; the person's
// own page is the memory on no topic and no account titled "You". Titles and names compare with
// whitespace collapsed and case ignored. When there are several, the newest is the page (the
// lowest id on a tie). A page carries no categories: only an agent that reads its whole topic (or
// every memory) can read it, and that agent can already read every fact on it.
//
// What is worked out here is from what this connection can read, and nothing else: no request,
// nothing written.

import { nameKey, type MemoryRecord } from './context-graph.js';

/** The title of the person's own page. */
export const YOU_PAGE_TITLE = 'You';

/** How a title and a topic's name compare: whitespace collapsed, case ignored (the app's rule). */
export const pageKey = (s: string): string => s.split(/\s+/).filter(Boolean).join(' ').toLowerCase();

/** Whether a memory with this title, filed on this topic (null: on none) and account, is a page. */
export function isPage(title: string | undefined | null, place: { topicName: string | null; accountId: string | null }): boolean {
  if (!title || !title.trim() || place.accountId) return false;
  return pageKey(title) === pageKey(place.topicName ?? YOU_PAGE_TITLE);
}

/** Whether a stored memory is a page. */
export const isPageRecord = (r: Pick<MemoryRecord, 'title' | 'topic' | 'accountId'>): boolean =>
  isPage(r.title, { topicName: r.topic?.name ?? null, accountId: r.accountId });

/** A topic's page as list_topics shows it. */
export interface PageRef { memory_id: string; updated_at: string }

/** What this connection can tell about one topic's page (topics are keyed by `nameKey`). */
export interface PageMark {
  /** The page it can read, if any. */
  page: PageRef | null;
  /** A memory on the topic that it can read was added since the page was last written. */
  outOfDate: boolean;
  /** It reads the whole topic (every memory, or the topic itself), so "no page" is known, not a guess. */
  whole: boolean;
  /** How many memories on the topic that it can read the page does not link (0 with no page). */
  notOnPage: number;
}

/** The person's own page ("You"), whether it needs creating, and the facts an existing page omits. */
export interface YouMark { page: PageRef | null; noPage: boolean; notOnPage: number }

/** "See also" → "see-also": a heading as the app compares it (MemoryWiki.slug). */
const slug = (s: string): string => s.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean).join('-');

/** A heading line's level and words (`## Flights` → 2, "Flights"), or null (MemoryWiki.heading). */
function heading(line: string): { level: number; title: string } | null {
  const m = /^(#{1,6}) (.*)$/.exec(line);
  if (!m) return null;
  const title = m[2].trim().replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replaceAll('**', '').replaceAll('`', '');
  return title ? { level: m[1].length, title } : null;
}

/**
 * The memory ids a page's writing links to, as the app reads a page (MemoryWiki.scan): every
 * `](memory:<id>)` outside code blocks and outside its `## See also` section. Links to other pages
 * are among them.
 */
export function pageLinks(text: string): Set<string> {
  const out = new Set<string>();
  let inSeeAlso = false, inCode = false;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/^[ \t]+/, '');
    if (!line) continue;
    if (line.startsWith('```') || line.startsWith('~~~')) { inCode = !inCode; continue; }
    if (inCode) continue;
    const h = heading(line);
    if (h) { if (h.level <= 2) inSeeAlso = slug(h.title) === 'see-also'; continue; }
    if (inSeeAlso) continue;
    for (const m of line.matchAll(/\]\(memory:([^)#\s]+)/g)) out.add(m[1]);
  }
  return out;
}

/** The page of a memory's place: its topic (by name key), or the person's page (null). Undefined for
 *  a page itself, an account without a topic, and an unmatched account hint. */
function placeOf(r: MemoryRecord): string | null | undefined {
  if ((!r.topic && r.accountId) || r.aboutHint || isPageRecord(r)) return undefined;
  return r.topic ? nameKey(r.topic.name) : null;
}

/**
 * For each memory this connection reads that belongs on a page, whether that page links it: a
 * memory on a topic, its topic's page; one on no topic and no account, the person's page ("You").
 * A place with no page links nothing. Pages, accounts without a topic and unmatched account hints are left out.
 */
export function onPage(records: readonly MemoryRecord[]): Map<string, boolean> {
  const pages = newestPages(records);
  const links = new Map([...pages].map(([k, p]) => [k, pageLinks(p.text)] as const));
  const out = new Map<string, boolean>();
  for (const r of records) {
    const k = placeOf(r);
    if (k !== undefined) out.set(r.id, links.get(k)?.has(r.id) ?? false);
  }
  return out;
}

/** Each place's page: by topic name key, and the person's page under null (the newest wins). */
function newestPages(records: readonly MemoryRecord[]): Map<string | null, MemoryRecord> {
  const pages = new Map<string | null, MemoryRecord>();
  for (const r of records) {
    if (r.accountId || (!r.topic && r.aboutHint) || !isPageRecord(r)) continue;
    const k = r.topic ? nameKey(r.topic.name) : null;
    const p = pages.get(k);
    if (!p || newer(r, p)) pages.set(k, r);
  }
  return pages;
}

/**
 * What add_memory says about pages for the facts it just saved (`written`), from the memories as
 * they were before (`before`): a fact on a topic that has a page goes on that page in the same
 * turn; a fact on no topic is the person's own, so their page ("You") links it, unless it is about a
 * subject, which goes under its topic. Null
 * when there is nothing to say. A listed connector offers the work to the person.
 */
export function savedFactsPageLine(written: readonly MemoryRecord[], before: readonly MemoryRecord[], opts: { listing?: boolean } = {}): string | null {
  const pages = newestPages(before);
  const onTopic = new Map<string, { page: MemoryRecord; ids: string[] }>();
  const loose: string[] = [];
  for (const r of written) {
    if (isPageRecord(r)) continue;
    if (!r.topic) { if (!r.accountId && !r.aboutHint) loose.push(r.id); continue; }
    const page = pages.get(nameKey(r.topic.name));
    if (!page) continue;
    const e = onTopic.get(page.id) ?? { page, ids: [] };
    e.ids.push(r.id);
    onTopic.set(page.id, e);
  }
  const add = opts.listing ? 'Offer the person to add' : 'Add';
  const lines = [...onTopic.values()].map(({ page, ids }) =>
    `${JSON.stringify(page.topic!.name)} has a page (memory ${page.id}). ${add} ${ids.length === 1 ? 'this fact' : 'these facts'} to it in this turn with update_memory, linking ${ids.map(id => `[its words](memory:${id})`).join(', ')}.`);
  // A fact on no topic is about the person, so their page links it: said when they have a page
  // (with none, list_topics and the brief say the person has no page).
  const you = pages.get(null);
  if (loose.length && you) {
    const one = loose.length === 1;
    const which = one ? `Memory ${loose[0]} is` : `Memories ${loose.join(', ')} are`;
    const links = loose.map(id => `[its words](memory:${id})`).join(', ');
    lines.push(opts.listing
      ? `${which} on no topic, so about the person: offer the person to add ${one ? 'it' : 'them'} to their page ("You", memory ${you.id}). If one is about a subject instead, offer to move it under that subject's topic.`
      : `${which} on no topic, so about the person: add ${one ? 'it' : 'them'} to their page ("You", memory ${you.id}) in this turn with update_memory, linking ${links}. If one is about a subject instead (a project, a trip, a person, an organisation), move it under that subject's topic with move_memories, a new one when none fits.`);
  }
  return lines.length ? lines.join(' ') : null;
}

/** The person's page and the memories on no topic it does not link, from what this connection reads
 *  (said only to one that reads every memory: the caller checks). */
export function youMark(records: readonly MemoryRecord[], linked: ReadonlyMap<string, boolean> = onPage(records)): YouMark {
  let page: MemoryRecord | undefined, notOnPage = 0;
  for (const r of records) {
    if (r.topic || r.accountId || r.aboutHint) continue;
    if (isPageRecord(r)) { if (!page || newer(r, page)) page = r; } else if (linked.get(r.id) === false) notOnPage++;
  }
  return { page: page ? { memory_id: page.id, updated_at: page.updatedAt } : null,
    noPage: !page && notOnPage > 0, notOnPage: page ? notOnPage : 0 };
}

/** A time as the server gives it, comparable; one that does not parse is the oldest. */
const time = (iso: string): number => { const t = Date.parse(iso); return Number.isFinite(t) ? t : 0; };
/** The newer of two memories as the app picks a page: newest change, then the lower id. */
const newer = (a: MemoryRecord, b: MemoryRecord): boolean => time(a.updatedAt) !== time(b.updatedAt) ? time(a.updatedAt) > time(b.updatedAt) : a.id < b.id;

/**
 * Each topic's mark, by the topic's name key. A topic only appears when this connection can read
 * at least one memory on it. It reads the whole topic when a memory on it reaches it through all
 * memories or through that topic itself (`via`), not only through a category or as its own.
 */
export function pageMarks(records: readonly MemoryRecord[], linked: ReadonlyMap<string, boolean> = onPage(records)): Map<string, PageMark> {
  const groups = new Map<string, MemoryRecord[]>();
  for (const r of records) {
    if (!r.topic) continue;
    const k = nameKey(r.topic.name);
    const list = groups.get(k);
    if (list) list.push(r); else groups.set(k, [r]);
  }
  const marks = new Map<string, PageMark>();
  for (const [k, list] of groups) {
    let page: MemoryRecord | undefined;
    for (const r of list) if (isPageRecord(r) && (!page || newer(r, page))) page = r;
    // Same-name topics are one entry: it is read whole only when each of them is.
    const whole = [...new Set(list.map(r => r.topic!.id))].every(id => list.some(r => r.topic!.id === id && reachedWhole(r)));
    // Out of date: a memory added on the topic since the page was last written. (A change to a
    // memory is not counted: the owner's app re-seals memories to tag them or under a new key,
    // which says nothing new; an agent that changes a fact updates the page in the same turn.)
    const since = page ? time(page.updatedAt) : Infinity;
    const outOfDate = !!page && list.some(r => r.id !== page!.id && time(r.createdAt) > since);
    const notOnPage = page ? list.filter(r => linked.get(r.id) === false).length : 0;
    marks.set(k, { page: page ? { memory_id: page.id, updated_at: page.updatedAt } : null, outOfDate, whole, notOnPage });
  }
  return marks;
}

/** A memory this connection reads through all memories, or through the topic it is filed on. */
const reachedWhole = (r: MemoryRecord): boolean => r.via.some(v => v === 'all' || (v.startsWith('topic:') && r.about.includes(v)));

/**
 * Who may make a memory a page. A page states every fact on its topic, and whoever saved a memory
 * keeps reading it, so only a connection whose own read grant covers every memory, or every memory
 * on that topic (`readsWhole`, ContextGraph.readsWhole), makes one: what others later write into
 * it is then already its to read. Creating a topic gives no such grant. Null when it may; otherwise
 * why not, in the agent's words (`verb`: what did not happen).
 */
export function pageRefusal(readsWhole: boolean, topicName: string | null, verb: 'saved' | 'changed' = 'saved'): string | null {
  if (readsWhole) return null;
  return wholeRefusal(topicName, verb);
}

/** Why a memory another connection saved is never made a page: its saver keeps reading it. */
export const FOREIGN_PAGE_REFUSAL = 'Not changed: this memory was saved by another connection (or by the owner), and whoever saved it keeps reading it, so only a memory this connection saved is made a page. Save the page as a new memory instead.';

function wholeRefusal(topicName: string | null, verb: 'saved' | 'changed'): string {
  const instead = verb === 'saved' ? 'Save the fact on its own, with a title other than' : 'Keep a title other than';
  return topicName === null
    ? `Not ${verb}: the person's page ("You") states what is known about them, so only a connection that may read every memory writes it. ${instead} "You".`
    : `Not ${verb}: a topic's page states every fact filed on its topic, so only a connection that may read every memory on ${JSON.stringify(topicName)} writes it. ${instead} the topic's name.`;
}

/** What the pages need, in counts. */
export interface PageCounts {
  /** Topics read whole that have no page. */
  noPage: number;
  /** Pages older than a memory on their topic. */
  outOfDate: number;
  /** Memories on topics read whole that their topic's page does not link. */
  notOnPage: number;
  /** Personal facts exist, but the person has no page (false when not known). */
  youNoPage: boolean;
  /** Memories on no topic that the person's existing page does not link (0 with no page or unknown). */
  youNotOnPage: number;
}

/** The counts, from the topics' marks and (to a connection that reads every memory) the person's page. */
export function pageCounts(marks: ReadonlyMap<string, PageMark>, you: YouMark | null = null): PageCounts {
  let noPage = 0, outOfDate = 0, notOnPage = 0;
  for (const m of marks.values()) {
    if (!m.page && m.whole) noPage++;
    if (m.outOfDate) outOfDate++;
    if (m.whole) notOnPage += m.notOnPage;
  }
  return { noPage, outOfDate, notOnPage, youNoPage: you?.noPage ?? false, youNotOnPage: you?.notOnPage ?? 0 };
}

const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** get_memories' filter for the memories a page does not link yet. */
export const NOT_ON_PAGE_FILTER = '{"on_page": false}';

/**
 * The brief's line about pages, or null when every topic read whole has a page that links every
 * memory on it, and the person's page links every memory on no topic. A listed connector
 * (DECOY_LISTING=true) offers the work to the person: it saves only when they ask or agree.
 * `inList`: said in list_topics' own result.
 */
export function pagesLine(counts: PageCounts, opts: { listing?: boolean; inList?: boolean } = {}): string | null {
  const parts = [
    counts.noPage ? `${count(counts.noPage, 'topic has', 'topics have')} no page` : '',
    counts.youNoPage ? 'the person has no page' : '',
    counts.notOnPage ? `${count(counts.notOnPage, 'memory is', 'memories are')} not on ${counts.notOnPage === 1 ? 'its' : 'their'} topic's page` : '',
    counts.youNotOnPage ? `${count(counts.youNotOnPage, 'memory', 'memories')} on no topic ${counts.youNotOnPage === 1 ? 'is' : 'are'} not on the person's page` : '',
  ].filter(Boolean);
  if (!parts.length) return null;
  const listed = counts.notOnPage || counts.youNotOnPage ? `; get_memories with filters ${NOT_ON_PAGE_FILTER} lists them` : '';
  const what = `${parts.length > 1 ? `${parts.slice(0, -1).join(', ')}, and ${parts[parts.length - 1]}` : parts[0]} (${opts.inList ? (counts.youNoPage || counts.youNotOnPage ? 'marked in topics and you' : 'marked in topics') : 'list_topics marks them'}${listed})`;
  return opts.listing
    ? `Decoy pages: ${what}. Offer the person to write or update them; do it only when they agree.`
    : `Decoy pages: ${what}. Write or update each as add_memory and update_memory describe: a page links every memory on its topic; a memory on no topic that is not about the person goes under a topic (move_memories), a new one when none fits.`;
}

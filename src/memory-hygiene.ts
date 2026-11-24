// Memory habits the bridge keeps for the agent, instead of asking it to remember them.
//
// The instructions tell an agent to read memory before it starts and to save as it goes. Agents
// do neither reliably, so the tools do it: per session (one connected client), in memory only.
//
//   - The summary of what is known about the person arrives with the first tool result, without
//     being asked for, when the connection can read memories.
//   - A session that keeps working without reading memory, or without saving anything, is told
//     so once, in a line after a tool result.
//   - my_permissions says what this session has done with memory, in numbers.
//
// A note is always its own text block after a tool's result, never inside the JSON a client
// parses, never on an error, and at most one of these per result. Nothing here is written to
// disk, and nothing is fetched that the rule itself does not need.
//
// A one-shot `call` is one process per tool call. There a session starts from the counts the
// last call left (`initial`) and hands back its own (`counts()`); src/session-state.ts keeps them.

import { MEMORY_FACT_PHRASE } from './agent-setup.js';

/** Tool calls that are not memory tools, with no memory read, before the session is told to read. */
export const READ_NUDGE_AFTER = 3;
/** The same, for a session that was sent the summary: it has just been handed what is known. */
export const READ_NUDGE_AFTER_BRIEF = 6;
/** Tool calls of any kind, with nothing saved, before a session that may save is told to save. */
export const SAVE_NUDGE_AFTER = 8;
/** How long the first tool result waits for the summary before saying it is still loading (ms). */
export const BRIEF_WAIT_MS = 1000;

/** Tools that read memories. */
export const MEMORY_READ_TOOLS: ReadonlySet<string> = new Set([
  'search_memories', 'get_memories', 'get_memory', 'list_topics', 'read_topic', 'list_entities', 'read_graph', 'search_nodes', 'open_nodes',
]);
/** Tools that save or correct a memory (a save is counted only when something was written). */
export const MEMORY_SAVE_TOOLS: ReadonlySet<string> = new Set([
  'add_memory', 'update_memory', 'create_entities', 'create_relations', 'add_observations',
  // A link, a move of a topic, memories filed under a topic: each is a write (move_memories answers
  // with an error when it moved nothing, so it counts only when something moved).
  'connect_topics', 'set_topic_parent', 'move_memories',
]);
/** Every memory tool: none of them counts as "working without memory". */
export const MEMORY_TOOLS: ReadonlySet<string> = new Set([
  ...MEMORY_READ_TOOLS, ...MEMORY_SAVE_TOOLS, 'list_duplicate_topics', 'disconnect_topics', 'delete_memory', 'delete_all_memories', 'delete_entities', 'delete_observations', 'delete_relations',
]);

export const READ_NUDGE = 'Decoy memory: not read in this session, so you may redo or contradict what is already known. One call: search_memories({ query: "<this task\'s subject>" }).';
export const SAVE_NUDGE = 'Decoy memory: if the owner has told you anything worth keeping in this task, save it now with add_memory. Sessions end without warning.';
export const BRIEF_LOADING = 'Decoy memory: the summary of what is known about this person is still loading. It comes with your next tool result.';
export const BRIEF_FOOTER = '(From Decoy, once per session. Before a new task, search_memories for its subject.)';

/** What the connection may do with memories, as far as the bridge has seen. null = not known. */
export interface MemoryAbility {
  read: boolean; save: boolean;
  /** It may edit every memory (`write` is all). The Decoy app shows a page only while its last
   *  writer is the owner or a connection whose edit grant covers it (every memory, or its topic); an
   *  edit grant on some categories or accounts never covers a page, which has neither. */
  edit: boolean;
}

/** `access.memories` of a GET /policies answer, as yes/no answers. */
export function memoryAbility(access: unknown): MemoryAbility | null {
  const m = access && typeof access === 'object' ? (access as { memories?: unknown }).memories : null;
  if (!m || typeof m !== 'object') return null;
  const { read, save, write } = m as { read?: unknown; save?: unknown; write?: unknown };
  return { read: typeof read === 'string' && read !== 'none', save: save === true, edit: write === 'all' };
}

/** Whether it is worth telling a connection what pages need: it may save, and edit every memory
 *  (so the app shows the pages it writes). */
export const writesPages = (a: MemoryAbility | null): boolean | null => (a ? a.save && a.edit : null);

/** Whether `access.memories` says the connection reads all memories (not some, and not unknown). */
export function readsAllMemories(access: unknown): boolean {
  const m = access && typeof access === 'object' ? (access as { memories?: unknown }).memories : null;
  return !!m && typeof m === 'object' && (m as { read?: unknown }).read === 'all';
}

/** Data from this connection's GET /policies answer, never server-authored advice. */
export interface MemoryHabit {
  /** Absent on older APIs. */
  connected_at?: string;
  last_saved_at: string | null;
  active_days_since_last_save: number;
  active_days_last_7: number;
}
export function memoryHabit(answer: unknown): MemoryHabit | null {
  const h = answer && typeof answer === 'object' ? (answer as { memory_habit?: unknown }).memory_habit : null;
  if (!h || typeof h !== 'object' || Array.isArray(h)) return null;
  const { connected_at: connected, last_saved_at: at, active_days_since_last_save: since, active_days_last_7: week } = h as Record<string, unknown>;
  const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  const date = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(v) && Number.isFinite(Date.parse(v));
  if ((at !== null && !date(at)) || (connected !== undefined && !date(connected))) return null;
  if (!count(since) || !count(week) || week > 7) return null;
  return { ...(connected === undefined ? {} : { connected_at: connected as string }), last_saved_at: at as string | null, active_days_since_last_save: since, active_days_last_7: week };
}
/** The bridge owns every word; only validated dates and counts come from the API. */
export function saveDueLine(h: MemoryHabit | null, ability: MemoryAbility | null, now = Date.now()): string | null {
  if (!ability?.save || !h) return null;
  // Reading policies is current connection use. The first recorded day must not hide an old
  // connection's history just because activity counting started at deployment.
  const oldOnReturn = h.active_days_since_last_save > 0 && h.active_days_last_7 > 0 &&
    (h.last_saved_at !== null ? now - Date.parse(h.last_saved_at) > 7 * 86_400_000
      : h.connected_at !== undefined && now - Date.parse(h.connected_at) > 2 * 86_400_000);
  if (h.active_days_since_last_save < 2 && !oldOnReturn) return null;
  const days = h.active_days_since_last_save;
  const age = h.last_saved_at === null ? null : Math.max(0, Math.floor((now - Date.parse(h.last_saved_at)) / 86_400_000));
  const when = age === null ? `has never saved and has been used on ${days} active ${days === 1 ? 'day' : 'days'}`
    : `last saved ${age} ${age === 1 ? 'day' : 'days'} ago and has been used on ${days} ${days === 1 ? 'day' : 'days'} since`;
  return `Decoy memory: this connection ${when}. Before you finish this task, save what you have learned about the owner since then: from this chat, from your own saved memory of them, and from earlier chats you can see. Save ${MEMORY_FACT_PHRASE}.`;
}

type BriefState = 'not_started' | 'loading' | 'told_loading' | 'delivered' | 'nothing_to_send' | 'not_sent';

/** A session's numbers and flags, as they can be handed from one process to the next. The summary
 *  is 'not_started' while it has not been sent or ruled out, whatever was loading when the process ended. */
export interface MemoryCounts {
  toolCalls: number; otherCalls: number; reads: number; saves: number;
  brief: 'not_started' | 'delivered' | 'nothing_to_send' | 'not_sent';
  /** A result has said the summary was still loading. */
  toldLoading: boolean;
  readNudged: boolean; saveNudged: boolean; firstStepSaid: boolean;
  /** Links this session wrote with connect_topics (mem0-tools CONNECT_LINKS_MAX). */
  links: number;
}

export class MemorySession {
  toolCalls = 0;
  otherCalls = 0;
  reads = 0;
  saves = 0;
  private links = 0;
  private brief: BriefState = 'not_started';
  private briefText: string | null | undefined; // undefined until the summary has been produced
  private briefDone: Promise<void> = Promise.resolve();
  private readNudged = false;
  private saveNudged = false;
  /** A memory read came before any other work: any tool of this server but a memory tool or
   *  my_permissions (a look at the connection's own access, which agents are told to take first). */
  private readFirst = false;
  /** A tool that is other work has run. */
  private didOtherWork = false;
  private firstStepSaid = false;
  private toldLoading = false;
  private ability: MemoryAbility | null = null;
  private habit: MemoryHabit | null = null;
  private abilityKnown!: (a: MemoryAbility | null) => void;
  private readonly firstAbility = new Promise<MemoryAbility | null>((resolve) => { this.abilityKnown = resolve; });

  constructor(private readonly opts: {
    /** A listed hosted connector: nothing is ever added after a result (no summary, no reminder,
     *  no first-step line); the session's numbers are still counted. */
    quiet?: boolean;
    now?: () => number;
    /** The summary (empty when there are no memories), given what the connection may do with
     *  memories when that is known. Called at most once. */
    brief: (ability: MemoryAbility | null) => Promise<string>;
    /** The summary has gone out with a tool result. */
    delivered?: () => void;
    waitMs?: number;
    wait?: (ms: number) => Promise<void>;
    /** The line that says how to set up the first step, while it is owed; null once it is not. */
    firstStep?: () => string | null;
    /** Where an earlier process of this session left off. */
    initial?: MemoryCounts;
  }) {
    const i = opts.initial;
    if (!i) return;
    this.toolCalls = i.toolCalls; this.otherCalls = i.otherCalls; this.reads = i.reads; this.saves = i.saves;
    this.brief = i.brief; this.toldLoading = i.toldLoading;
    this.readNudged = i.readNudged; this.saveNudged = i.saveNudged; this.firstStepSaid = i.firstStepSaid;
    this.links = i.links ?? 0;
    this.didOtherWork = i.otherCalls > 0;
  }

  /** connect_topics wrote one more link in this session. */
  linkAdded(): void { this.links++; }

  /** This session's numbers and flags now, for the next process of the same session. */
  counts(): MemoryCounts {
    const brief = this.brief === 'loading' || this.brief === 'told_loading' ? 'not_started' : this.brief;
    return { toolCalls: this.toolCalls, otherCalls: this.otherCalls, reads: this.reads, saves: this.saves, brief, toldLoading: this.toldLoading,
      readNudged: this.readNudged, saveNudged: this.saveNudged, firstStepSaid: this.firstStepSaid, links: this.links };
  }

  /** How to set up the first step, when that is still owed: at most once per session, and never to
   *  a connection that cannot read memories. It goes with the summary sent with the first result,
   *  or after my_permissions, whichever comes first. */
  firstStep(): string | null {
    if (this.firstStepSaid || this.opts.quiet) return null;
    // The first step reads memories: a connection that cannot read them is not told to set it up.
    if (this.ability && !this.ability.read) return null;
    let line: string | null = null;
    try { line = this.opts.firstStep?.() ?? null; } catch { /* not known: nothing is said */ }
    if (line) this.firstStepSaid = true;
    return line;
  }

  /** The bridge has looked at its access (null: the look failed, nothing is known). */
  sawAccess(ability: MemoryAbility | null): void {
    if (ability) this.ability = ability;
    this.abilityKnown(ability);
  }

  /** The most recent validated saving data for this connection. */
  sawHabit(habit: MemoryHabit | null): void { if (habit) this.habit = habit; }

  /** What the connection may do with memories, waiting for the first look if it has not answered. */
  async abilityNow(): Promise<MemoryAbility | null> {
    return this.ability ?? this.firstAbility;
  }

  /** A tool is about to run. */
  begin(tool: string): void {
    this.toolCalls++;
    if (!MEMORY_TOOLS.has(tool)) {
      this.otherCalls++;
      if (tool !== 'my_permissions') this.didOtherWork = true;
    }
    if (MEMORY_READ_TOOLS.has(tool) && !this.didOtherWork) this.readFirst = true;
    if (this.brief !== 'not_started') return;
    if (this.opts.quiet) { this.brief = 'not_sent'; return; }
    // An agent whose first act is to read memory needs no summary pushed at it.
    if (MEMORY_READ_TOOLS.has(tool)) { this.brief = 'not_sent'; return; }
    this.brief = 'loading';
    this.briefDone = this.firstAbility
      .then((a) => (a?.read ? this.opts.brief(a) : ''))
      .then((text) => { this.briefText = text.trim() ? text : null; }, () => { this.briefText = null; });
  }

  /** Something was written to memory (a save or a correction). */
  saved(): void { this.saves++; if (this.habit) this.habit = { ...this.habit, last_saved_at: new Date((this.opts.now ?? Date.now)()).toISOString(), active_days_since_last_save: 0 }; }

  /** A tool has answered. Returns the one line (or the summary) to put after its result, if any. */
  async end(tool: string, ok: boolean): Promise<string | null> {
    // Set the existing save flag before considering the eight-call reminder. The due note can
    // share the first result's summary/read note, but replaces SAVE_NUDGE for this whole session.
    const due = ok && !this.opts.quiet && !this.saveNudged && this.saves === 0
      ? saveDueLine(this.habit, this.ability, (this.opts.now ?? Date.now)()) : null;
    if (due) this.saveNudged = true;
    const note = await this.ordinaryEnd(tool, ok);
    return [note, due].filter(Boolean).join('\n') || null;
  }

  private async ordinaryEnd(tool: string, ok: boolean): Promise<string | null> {
    if (!ok) return null;
    if (this.opts.quiet) { if (MEMORY_READ_TOOLS.has(tool)) this.reads++; return null; }
    if (MEMORY_READ_TOOLS.has(tool)) {
      this.reads++;
      // It read memory itself before the summary was ready or promised: nothing to push.
      if (this.brief === 'loading' && this.briefText === undefined) this.brief = 'not_sent';
    }
    if (this.brief === 'loading' || this.brief === 'told_loading') {
      if (this.brief === 'loading' && this.briefText === undefined) {
        const waitMs = this.opts.waitMs ?? BRIEF_WAIT_MS;
        const wait = this.opts.wait ?? ((ms: number) => new Promise<void>((r) => { const t = setTimeout(r, ms); t.unref?.(); }));
        if (waitMs > 0) await Promise.race([this.briefDone, wait(waitMs)]);
      }
      if (this.briefText === undefined) {
        // Said once per session, also when an earlier process of the session said it.
        if (this.brief === 'told_loading' || this.toldLoading) { this.brief = 'told_loading'; return null; }
        this.brief = 'told_loading'; this.toldLoading = true;
        return BRIEF_LOADING;
      }
      if (this.briefText === null) this.brief = 'nothing_to_send';
      else {
        this.brief = 'delivered';
        try { this.opts.delivered?.(); } catch { /* recorded or not, the summary goes out */ }
        const step = this.firstStep();
        return `${this.briefText}\n${BRIEF_FOOTER}${step ? `\n${step}` : ''}`;
      }
    }
    const readAfter = this.brief === 'delivered' ? READ_NUDGE_AFTER_BRIEF : READ_NUDGE_AFTER;
    if (!this.readNudged && this.ability?.read && this.reads === 0 && this.otherCalls >= readAfter) {
      this.readNudged = true;
      return READ_NUDGE;
    }
    if (!this.saveNudged && this.ability?.save && this.saves === 0 && this.toolCalls >= SAVE_NUDGE_AFTER) {
      this.saveNudged = true;
      return SAVE_NUDGE;
    }
    return null;
  }

  /** What this session did with memory, for the counts-only record (src/usage-report.ts). */
  usage(): { toolCalls: number; reads: number; saves: number; readBeforeOther: boolean; summarySent: boolean; readNudged: boolean; saveNudged: boolean } {
    return { toolCalls: this.toolCalls, reads: this.reads, saves: this.saves, readBeforeOther: this.readFirst,
      summarySent: this.brief === 'delivered', readNudged: this.readNudged, saveNudged: this.saveNudged };
  }

  /** What this session has done with memory, as one plain line (my_permissions). */
  report(): string {
    const n = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;
    const brief: Record<BriefState, string> = {
      not_started: 'not sent yet', loading: 'loading', told_loading: 'loading',
      delivered: 'sent with a tool result', nothing_to_send: 'nothing to send (no memories to read)',
      not_sent: 'not sent (this session read memory first)',
    };
    const said = [this.readNudged ? 'to read memory' : '', this.saveNudged ? 'to save' : ''].filter(Boolean);
    return `Memory in this session: ${n(this.toolCalls, 'tool call', 'tool calls')}, ${n(this.reads, 'memory read', 'memory reads')}, ` +
      `${n(this.saves, 'memory saved or corrected', 'memories saved or corrected')}. Summary of memories: ${brief[this.brief]}. ` +
      `Reminders sent: ${said.length ? said.join(', ') : 'none'}.` +
      (this.habit ? ` Last saved by this connection: ${this.habit.last_saved_at ?? 'never'}.` : '');
  }
}

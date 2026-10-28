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
export interface MemoryAbility { read: boolean; save: boolean }

/** `access.memories` of a GET /policies answer, as two yes/no answers. */
export function memoryAbility(access: unknown): MemoryAbility | null {
  const m = access && typeof access === 'object' ? (access as { memories?: unknown }).memories : null;
  if (!m || typeof m !== 'object') return null;
  const { read, save } = m as { read?: unknown; save?: unknown };
  return { read: typeof read === 'string' && read !== 'none', save: save === true };
}

/** Whether `access.memories` says the connection reads all memories (not some, and not unknown). */
export function readsAllMemories(access: unknown): boolean {
  const m = access && typeof access === 'object' ? (access as { memories?: unknown }).memories : null;
  return !!m && typeof m === 'object' && (m as { read?: unknown }).read === 'all';
}

type BriefState = 'not_started' | 'loading' | 'told_loading' | 'delivered' | 'nothing_to_send' | 'not_sent';

export class MemorySession {
  toolCalls = 0;
  otherCalls = 0;
  reads = 0;
  saves = 0;
  private brief: BriefState = 'not_started';
  private briefText: string | null | undefined; // undefined until the summary has been produced
  private briefDone: Promise<void> = Promise.resolve();
  private readNudged = false;
  private saveNudged = false;
  private firstStepSaid = false;
  private ability: MemoryAbility | null = null;
  private abilityKnown!: (a: MemoryAbility | null) => void;
  private readonly firstAbility = new Promise<MemoryAbility | null>((resolve) => { this.abilityKnown = resolve; });

  constructor(private readonly opts: {
    /** The summary (empty when there are no memories). Called at most once. */
    brief: () => Promise<string>;
    waitMs?: number;
    wait?: (ms: number) => Promise<void>;
    /** The line that says how to set up the first step, while it is owed; null once it is not. */
    firstStep?: () => string | null;
  }) {}

  /** How to set up the first step, when that is still owed: at most once per session, and never to
   *  a connection that cannot read memories. It goes with the summary sent with the first result,
   *  or after my_permissions, whichever comes first. */
  firstStep(): string | null {
    if (this.firstStepSaid) return null;
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

  /** What the connection may do with memories, waiting for the first look if it has not answered. */
  async abilityNow(): Promise<MemoryAbility | null> {
    return this.ability ?? this.firstAbility;
  }

  /** A tool is about to run. */
  begin(tool: string): void {
    this.toolCalls++;
    if (!MEMORY_TOOLS.has(tool)) this.otherCalls++;
    if (this.brief !== 'not_started') return;
    // An agent whose first act is to read memory needs no summary pushed at it.
    if (MEMORY_READ_TOOLS.has(tool)) { this.brief = 'not_sent'; return; }
    this.brief = 'loading';
    this.briefDone = this.firstAbility
      .then((a) => (a?.read ? this.opts.brief() : ''))
      .then((text) => { this.briefText = text.trim() ? text : null; }, () => { this.briefText = null; });
  }

  /** Something was written to memory (a save or a correction). */
  saved(): void { this.saves++; }

  /** A tool has answered. Returns the one line (or the summary) to put after its result, if any. */
  async end(tool: string, ok: boolean): Promise<string | null> {
    if (!ok) return null;
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
        if (this.brief === 'told_loading') return null;
        this.brief = 'told_loading';
        return BRIEF_LOADING;
      }
      if (this.briefText === null) this.brief = 'nothing_to_send';
      else {
        this.brief = 'delivered';
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
      `Reminders sent: ${said.length ? said.join(', ') : 'none'}.`;
  }
}

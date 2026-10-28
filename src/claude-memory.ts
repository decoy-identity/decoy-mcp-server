// Claude's memory tool (memory_20250818) backed by Decoy memory (Memory epic M3; agent experience 4).
//
// The memory tool gives Claude a /memories folder to view and edit. Here that folder is the
// user's Decoy memories: one file per category (preferences.md, work.md, personal.md, …; mem0's
// categories with the short names the Decoy app shows), one memory per line. Every edit goes
// through this bridge's mem0 tools, so it is encrypted, deduplicated, tagged and visible in the
// Decoy app. An agent changes what it wrote, or what it holds Read & write on; deleting a file
// removes only what it wrote.
//
// The handlers match the Anthropic TypeScript SDK's MemoryToolHandlers shape:
//   import { betaMemoryTool } from '@anthropic-ai/sdk/helpers/beta/memory';
//   const memory = betaMemoryTool(claudeMemoryHandlers(await connectDecoyMemory()));

import { CATEGORY_NAMES, FROM_OTHER_MARK, stripBullet, withoutFromMark, type ToolCaller } from './mem0-tools.js';
import { oneLine } from './context-graph.js';

/** Connect to the user's Decoy memory in-process, with this machine's paired bridge credentials
 *  (~/.decoy) or explicit ones. Returns an MCP client for claudeMemoryHandlers(). */
/** Connects to the paired bridge in-process. Call close() when done: it releases the local memory
 *  engine (an ONNX session the process must not exit with). */
export async function connectDecoyMemory(opts: { token?: string; privateKeyPem?: string } = {}): Promise<ToolCaller & { close(): Promise<void> }> {
  const { connectInProcess } = await import('./index.js');
  return connectInProcess(opts);
}

const ROOT = '/memories';
const UNSORTED = 'unsorted.md';
/** preferences.md ↔ user_preferences, work.md ↔ professional_details, … */
const FILE_OF: Record<string, string> = Object.fromEntries(Object.entries(CATEGORY_NAMES).map(([c, n]) => [c, `${n.toLowerCase()}.md`]));
const CATEGORY_OF: Record<string, string> = Object.fromEntries(Object.entries(FILE_OF).map(([c, f]) => [f, c]));

interface Item { id: string; memory: string; categories: string[] | null; agent_id?: string; metadata: Record<string, unknown> | null }

type Cmd<K extends string, T> = { command: K } & T;
export interface ClaudeMemoryHandlers {
  view(c: Cmd<'view', { path: string; view_range?: number[] | null }>): Promise<string>;
  create(c: Cmd<'create', { path: string; file_text: string }>): Promise<string>;
  str_replace(c: Cmd<'str_replace', { path: string; old_str: string; new_str: string }>): Promise<string>;
  insert(c: Cmd<'insert', { path: string; insert_line: number; insert_text: string }>): Promise<string>;
  delete(c: Cmd<'delete', { path: string }>): Promise<string>;
  rename(c: Cmd<'rename', { old_path: string; new_path: string }>): Promise<string>;
}

/** The file a path names ('' for the folder itself). Anything outside /memories is refused. */
function fileOf(path: string): string {
  const p = path.replace(/\/+$/, '');
  if (p === ROOT) return '';
  const m = new RegExp(`^${ROOT}/([A-Za-z0-9_-]+\\.md)$`).exec(p);
  if (!m) throw new Error(`Only files directly in ${ROOT} (like ${ROOT}/preferences.md) can be used.`);
  return m[1].toLowerCase();
}

/** Text typed for a memory: no list marker, and no mark of another agent (the mark is shown in
 *  a listing, and a line copied from one must not carry it into what is stored). */
const typed = (text: string) => withoutFromMark(text.trim().replace(/^- /, '')).trim();
const lines = (text: string) => text.split('\n').map((l) => withoutFromMark(stripBullet(l)).trim()).filter(Boolean);

const STORED_PART_MAX = 1000;
const NOT_SHOWN_RUN = String.raw`[\s\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Variation_Selector}\u034F\u115F\u1160\u17B4\u17B5\u2800\u3164\uFFA0]`;
/** Text as it is shown, without the joiners a shown line keeps: what typed text is found by. */
const asTyped = (text: string) => oneLine(text, Infinity).replace(/[\u200C\u200D\uFE0E\uFE0F]/g, '');
/**
 * Where text given as it is shown (`shown`, one line) lies in a memory's text as it is stored:
 * the first stretch of the stored text that is shown as that, joiners aside. Between two
 * characters of `shown` the stored text may hold characters that are not shown; where `shown`
 * has a space it holds at least one. Null when no stretch of the stored text is shown as `shown`.
 */
export function storedPart(stored: string, shown: string): { at: number; length: number } | null {
  const escaped = (c: string) => c.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
  const chars = [...shown.replace(/[\u200C\u200D\uFE0E\uFE0F]/g, '')];
  // The search costs a long pattern per character given: past this length none is found.
  if (chars.length > STORED_PART_MAX) return null;
  const pattern = chars.map((c, i) => c === ' ' ? `${NOT_SHOWN_RUN}+?` : `${escaped(c)}${i < chars.length - 1 && chars[i + 1] !== ' ' ? `${NOT_SHOWN_RUN}*?` : ''}`).join('');
  try {
    const re = new RegExp(pattern, 'gu');
    for (let m = re.exec(stored); m; m = re.exec(stored)) {
      if (asTyped(m[0]) === asTyped(shown)) return { at: m.index, length: m[0].length };
      re.lastIndex = m.index + 1;
    }
  } catch { /* a pattern the engine will not take: none found */ }
  return null;
}

export function claudeMemoryHandlers(client: ToolCaller): ClaudeMemoryHandlers {
  const call = async <T,>(name: string, args: Record<string, unknown>): Promise<T> => {
    const r = await client.callTool({ name, arguments: args }) as { content: { text: string }[]; isError?: boolean };
    const body = JSON.parse(r.content[0].text);
    if (r.isError) throw new Error(body.error ?? `${name} failed`);
    return body as T;
  };
  const all = async () => (await call<{ results: Item[] }>('get_memories', { page_size: 10_000 })).results;
  // The file a memory is listed in comes from the memory itself, which another connection may
  // have written: a file name is used only in the shape of one, a category only when it is a
  // known one, and a memory is always one line of its file.
  const fileFor = (m: Item) => {
    const named = typeof m.metadata?.file === 'string' ? m.metadata.file : '';
    if (named.length <= 64 && /^[a-z0-9_-]+\.md$/.test(named)) return named;
    const category = m.categories?.[0] ?? '';
    return Object.hasOwn(FILE_OF, category) ? FILE_OF[category] : UNSORTED;
  };
  const flat = (text: string) => oneLine(text, Infinity);
  const inFile = async (file: string) => (await all()).filter(m => fileFor(m) === file);
  const mine = (m: Item) => m.agent_id === 'this agent';
  // As the summary marks it: a memory another agent saved says so before its text.
  const mark = (m: Item) => (m.agent_id === 'another agent' ? FROM_OTHER_MARK : '');
  const add = async (file: string, texts: string[]) => {
    const category = CATEGORY_OF[file];
    let added = 0;
    for (const text of texts) {
      const r = await call<{ results: unknown[] }>('add_memory', {
        text, ...(category ? { categories: [category] } : file !== UNSORTED ? { metadata: { file } } : {}),
        confirm_new: true, // a line written to the file is its own memory; a changed line goes through update_memory
      });
      added += r.results.length;
    }
    return added;
  };

  return {
    async view({ path, view_range }) {
      const file = fileOf(path);
      if (!file) {
        const counts = new Map<string, number>();
        for (const m of await all()) counts.set(fileFor(m), (counts.get(fileFor(m)) ?? 0) + 1);
        if (!counts.size) return `${ROOT} is empty.`;
        return [`Here are the files in ${ROOT} (one memory per line; each file is a category):`,
          ...[...counts].sort(([a], [b]) => a.localeCompare(b)).map(([f, n]) => `- ${f} (${n} ${n === 1 ? 'memory' : 'memories'})`)].join('\n');
      }
      const ms = await inFile(file);
      if (!ms.length) return `${ROOT}/${file} is empty.`;
      const numbered = ms.map((m, i) => `${String(i + 1).padStart(6)}\t- ${mark(m)}${flat(m.memory)}`);
      if (!view_range || view_range.length < 2) return numbered.join('\n');
      // [start, end], 1-based and inclusive; end -1 = through the last line.
      const start = Math.max(1, view_range[0]);
      const end = view_range[1] === -1 ? numbered.length : Math.min(numbered.length, view_range[1]);
      return numbered.slice(start - 1, end).join('\n');
    },

    async create({ path, file_text }) {
      const file = fileOf(path);
      if (!file) throw new Error(`${ROOT} is a folder; create a file in it.`);
      const n = await add(file, lines(file_text));
      return `Saved ${n} ${n === 1 ? 'memory' : 'memories'} to ${ROOT}/${file}.`;
    },

    async insert({ path, insert_line, insert_text }) {
      const file = fileOf(path);
      if (!file) throw new Error(`${ROOT} is a folder; insert into a file in it.`);
      const n = await add(file, lines(insert_text));
      const saved = `Saved ${n} ${n === 1 ? 'memory' : 'memories'} to ${ROOT}/${file}.`;
      // Memories are a set, not lines in a document: a requested position can't be kept.
      return insert_line != null ? `${saved} Memories have no order, so it is listed with the others (line ${insert_line} isn't kept).` : saved;
    },

    async str_replace({ path, old_str, new_str }) {
      const file = fileOf(path);
      const find = typed(old_str);
      if (!find) return 'Give the text to replace (old_str is empty).';
      const ms = await inFile(file);
      // As stored; else as shown (a memory of several lines is shown, and then corrected, as one).
      let hit = ms.find(m => m.memory.includes(find));
      let part: { at: number; length: number } | null = hit ? { at: hit.memory.indexOf(find), length: find.length } : null;
      if (!hit && asTyped(find)) {
        hit = ms.find(m => asTyped(m.memory).includes(asTyped(find)));
        part = hit ? storedPart(hit.memory, flat(find)) : null;
      }
      if (!hit) return `No memory in ${ROOT}/${file} contains that text.`;
      // Only the matched part changes. Text that is found as shown but not in the stored text
      // is not replaced: the memory is never rewritten from the one line it is shown as.
      if (!part) return `That text is in a memory in ${ROOT}/${file} as it is shown, but not in one place in the text as it is stored, so nothing was changed. Replace a shorter part of it, or change the memory with update_memory.`;
      // Literal replacement: `$&` or `$1` in the new text are kept as typed.
      const was = hit.memory;
      const text = (was.slice(0, part.at) + typed(new_str) + was.slice(part.at + part.length)).trim();
      // Someone else's memory: the server decides by this agent's level on it.
      try {
        if (!text) { await call('delete_memory', { memory_id: hit.id }); return 'Memory deleted.'; }
        await call('update_memory', { memory_id: hit.id, text });
        return 'Memory updated.';
      } catch (err) {
        if (mine(hit)) throw err;
        return `That memory was written by someone else, so it can't be changed here (${err instanceof Error ? err.message : String(err)}). Save the corrected fact instead.`;
      }
    },

    async delete({ path }) {
      const file = fileOf(path);
      const ms = file ? await inFile(file) : await all();
      const own = ms.filter(mine);
      for (const m of own) await call('delete_memory', { memory_id: m.id });
      const kept = ms.length - own.length;
      return `Deleted ${own.length} ${own.length === 1 ? 'memory' : 'memories'} you wrote.` +
        (kept ? ` Kept ${kept} written by the user or other agents.` : '');
    },

    async rename() {
      return 'Renaming isn\'t supported: each file is a category. Save the fact in the right file instead.';
    },
  };
}

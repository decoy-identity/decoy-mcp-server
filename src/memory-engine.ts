// The retrieval engine behind mem0's tools: mem0's own Memory class (mem0ai, Apache-2.0),
// run on this machine against the memories this agent already decrypted. No memory text
// leaves the machine or is written to disk:
//
//   - search is mem0's hybrid search (semantic + BM25 keyword + entity boost)
//   - embeddings are local (fastembed). The model is downloaded once from Hugging Face
//     (Qdrant's bge-small-en-v1.5) and cached under ~/.decoy/models (a 0700 directory)
//   - the vector store is mem0's in-memory store (dbPath ':memory:'), rebuilt from the
//     decrypted rows each session; history is off (no transcripts stored anywhere)
//   - mem0's telemetry is off; its config file goes in a temp dir removed on close()
//   - fact extraction is mem0's additive extraction prompt, answered by the client's own
//     model over MCP sampling. There is no server-side or bridge-side model.
//
// mem0ai and fastembed are optional dependencies (~290 MB with the ONNX runtime). When they
// are missing, `createMemoryEngine` falls back to word-overlap search and exact-match dedupe.

import { ensurePinnedModel } from './model-pin.js';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

// mem0 reads MEM0_TELEMETRY once, when its module first loads (and otherwise posts usage
// events to PostHog). Set it here, before anything can import mem0.
process.env.MEM0_TELEMETRY = 'false';

export interface ChatMessage { role: string; content: string }

export interface MemoryEngineLike {
  /** Make the engine hold exactly these memories (row id → text). */
  mirror(records: { id: string; text: string }[]): Promise<void>;
  /** Best matches for a natural-language query, best first. */
  search(query: string, topK: number): Promise<{ id: string; score: number }[]>;
  /** The most similar existing memory by meaning (cosine similarity, 0–1), if any. */
  nearest(text: string): Promise<{ id: string; similarity: number } | null>;
  /** The existing memories most similar to a text, best first, each with its similarity (0–1).
   *  Optional: without it only `nearest` is consulted. */
  similar?(text: string, topK: number): Promise<{ id: string; similarity: number }[]>;
  /** The similarity at which this engine's numbers mean "about the same thing", when its measure
   *  is not the model's cosine similarity (the basic engine counts words in common). */
  closeAt?(): Promise<number | undefined>;
  /** Facts worth remembering from a conversation (mem0 extraction). */
  extractFacts(messages: ChatMessage[]): Promise<string[]>;
  /** mem0's categories for each text, from the client's own model (empty when it can't say). */
  categorize?(texts: string[]): Promise<string[][]>;
  /** Free native resources (the ONNX session) before the process exits. */
  close?(): Promise<void>;
}

/** mem0's default memory categories (docs.mem0.ai, custom categories: "Default Categories"). */
export const MEM0_CATEGORIES = [
  'personal_details', 'family', 'professional_details', 'sports', 'travel', 'food', 'music',
  'health', 'technology', 'hobbies', 'fashion', 'entertainment', 'milestones', 'user_preferences', 'misc',
] as const;

/** Ask a model for mem0 categories: one list per memory, only names from mem0's list. */
export async function categorizeWith(sample: Sampler, texts: string[]): Promise<string[][]> {
  if (!texts.length) return [];
  const system = `You tag memories about a user with categories. Use only these category names: ${MEM0_CATEGORIES.join(', ')}. ` +
    'A memory can have one or more categories; use misc only when nothing else fits. ' +
    'Answer with JSON only: {"categories": [[...], ...]}, one list per memory, in order.';
  const user = texts.map((t, i) => `${i + 1}. ${t}`).join('\n');
  try {
    const raw = await sample([{ role: 'system', content: system }, { role: 'user', content: user }]);
    const json = JSON.parse(raw.slice(raw.indexOf('{'), raw.lastIndexOf('}') + 1)) as { categories?: unknown };
    const lists = Array.isArray(json.categories) ? json.categories : [];
    const known = new Set<string>(MEM0_CATEGORIES);
    return texts.map((_, i) => {
      const l = Array.isArray(lists[i]) ? (lists[i] as unknown[]) : [];
      return [...new Set(l.filter((c): c is string => typeof c === 'string' && known.has(c)))];
    });
  } catch {
    return texts.map(() => []);
  }
}

/** What mem0 needs from a model: its LLM interface's generateResponse. */
export type Sampler = (messages: ChatMessage[]) => Promise<string>;

const words = (s: string) => s.toLowerCase().split(/\W+/).filter(w => w.length > 1);

/** With the basic engine, two memories are close when they share at least this part of their
 *  distinct words (words in both / words in either). */
export const CLOSE_WORD_OVERLAP = 0.5;

/** Used when mem0/fastembed are not installed: word overlap, exact-text dedupe, no extraction. */
export class BasicEngine implements MemoryEngineLike {
  private texts = new Map<string, string>();
  async mirror(records: { id: string; text: string }[]) { this.texts = new Map(records.map(r => [r.id, r.text])); }
  async search(query: string, topK: number) {
    const q = new Set(words(query));
    return [...this.texts].map(([id, t]) => ({ id, score: words(t).filter(w => q.has(w)).length / Math.max(1, q.size) }))
      .filter(h => h.score > 0).sort((a, b) => b.score - a.score).slice(0, topK);
  }
  async nearest(text: string) {
    const norm = (s: string) => words(s).join(' ');
    const hit = [...this.texts].find(([, t]) => norm(t) === norm(text));
    return hit ? { id: hit[0], similarity: 1 } : null;
  }
  async similar(text: string, topK: number) {
    const a = new Set(words(text));
    return [...this.texts].map(([id, t]) => {
      const b = new Set(words(t));
      const both = [...a].filter(w => b.has(w)).length;
      const either = new Set([...a, ...b]).size;
      return { id, similarity: either ? both / either : 0 };
    }).filter(h => h.similarity > 0).sort((x, y) => y.similarity - x.similarity).slice(0, topK);
  }
  async closeAt() { return CLOSE_WORD_OVERLAP; }
  async extractFacts(): Promise<string[]> { return []; }
  constructor(private sample?: Sampler) {}
  async categorize(texts: string[]) { return this.sample ? categorizeWith(this.sample, texts) : texts.map(() => []); }
}

const SCOPE = { user_id: 'decoy' };

// mem0 keeps its config in MEM0_DIR, one process-wide location. Unless the user set it, every engine
// shares one temp dir, removed when the LAST engine using it closes (concurrent sessions each have
// an engine; closing one must not delete the dir under the others).
let sharedMem0Dir: string | null = null;
let sharedMem0Users = 0;
function acquireMem0Dir(): boolean {
  if (process.env.MEM0_DIR && process.env.MEM0_DIR !== sharedMem0Dir) return false; // user-provided: never ours
  if (!sharedMem0Dir) sharedMem0Dir = mkdtempSync(join(tmpdir(), 'decoy-mem0-'));
  process.env.MEM0_DIR = sharedMem0Dir;
  sharedMem0Users++;
  return true;
}
function releaseMem0Dir(): void {
  if (--sharedMem0Users > 0 || !sharedMem0Dir) return;
  rmSync(sharedMem0Dir, { recursive: true, force: true });
  if (process.env.MEM0_DIR === sharedMem0Dir) delete process.env.MEM0_DIR;
  sharedMem0Dir = null;
}

/** mem0's Memory, local. `sample` answers mem0's extraction prompt (MCP sampling). */
export class Mem0Engine implements MemoryEngineLike {
  private byRow = new Map<string, { mem0Id: string; text: string }>();
  private constructor(private memory: any, private sampler: { current?: Sampler }, private model: any, private holdsDir = false) {}

  /** onnxruntime aborts the process if it exits with a live session, so release it first. */
  async close() {
    const model = this.model; this.model = null; // a second close() finds nothing to release
    const holdsDir = this.holdsDir; this.holdsDir = false;
    try { await model?.session?.release?.(); } finally { if (holdsDir) releaseMem0Dir(); }
  }

  static async create(opts: { sample?: Sampler; modelDir?: string } = {}): Promise<Mem0Engine> {
    const holdsDir = acquireMem0Dir();
    try {
      const modelDir = opts.modelDir ?? join(homedir(), '.decoy', 'models');
      mkdirSync(modelDir, { recursive: true, mode: 0o700 });
      const pkgMem0 = 'mem0ai/oss', pkgEmbed = 'fastembed';
      const { Memory } = await import(pkgMem0);
      const { FlagEmbedding, EmbeddingModel } = await import(pkgEmbed);
      await ensurePinnedModel(modelDir); // pinned commit, SHA-256 verified; fastembed skips present files
      const model = await FlagEmbedding.init({ model: EmbeddingModel.BGESmallENV15, cacheDir: modelDir });
      const collect = async (gen: AsyncIterable<number[][]>) => { const out: number[][] = []; for await (const batch of gen) out.push(...batch); return out; };
      const embeddings = {
        embedQuery: async (text: string) => Array.from(await model.queryEmbed(text)) as number[],
        embedDocuments: async (texts: string[]) => (await collect(model.passageEmbed(texts))).map(v => Array.from(v)),
      };
      const memory = new Memory({
        embedder: { provider: 'langchain', config: { model: embeddings } },
        vectorStore: { provider: 'memory', config: { collectionName: 'decoy', dbPath: ':memory:', dimension: 384 } },
        // mem0 requires an llm entry; it is replaced below by the sampling-backed one.
        llm: { provider: 'openai', config: { apiKey: 'unused' } },
        disableHistory: true,
      });
      const sampler = { current: opts.sample };
      memory.llm = {
        generateResponse: async (messages: ChatMessage[]) => {
          if (!sampler.current) throw new Error('No model to sample');
          return sampler.current(messages);
        },
        generateChat: async (messages: ChatMessage[]) => ({ content: await sampler.current!(messages), role: 'assistant' }),
      };
      return new Mem0Engine(memory, sampler, model, holdsDir);
    } catch (err) {
      if (holdsDir) releaseMem0Dir(); // never leave the shared dir claimed by an engine that never existed
      throw err;
    }
  }

  setSampler(sample: Sampler | undefined) { this.sampler.current = sample; }

  // Every mem0 tool mirrors before it runs; tools on one session can run concurrently, so mirrors
  // run one at a time (two could otherwise both add a row and orphan one embedding).
  private mirrorChain: Promise<void> = Promise.resolve();
  mirror(records: { id: string; text: string }[]): Promise<void> {
    const run = this.mirrorChain.then(() => this.mirrorNow(records));
    this.mirrorChain = run.catch(() => {});
    return run;
  }

  private async mirrorNow(records: { id: string; text: string }[]) {
    const want = new Map(records.map(r => [r.id, r.text]));
    for (const [rowId, held] of this.byRow) {
      if (want.get(rowId) === held.text) continue;
      await this.memory.delete(held.mem0Id);
      this.byRow.delete(rowId);
    }
    for (const [rowId, text] of want) {
      if (this.byRow.has(rowId)) continue;
      const r = await this.memory.add([{ role: 'user', content: text }], { userId: SCOPE.user_id, infer: false, metadata: { row_id: rowId } });
      const mem0Id = r.results?.[0]?.id;
      if (mem0Id) this.byRow.set(rowId, { mem0Id, text });
    }
  }

  private rowOf(hit: { id?: string; metadata?: Record<string, unknown>; payload?: Record<string, unknown> }): string | undefined {
    const fromMeta = (hit.metadata?.row_id ?? hit.payload?.row_id) as string | undefined;
    if (fromMeta) return fromMeta;
    for (const [rowId, held] of this.byRow) if (held.mem0Id === hit.id) return rowId;
    return undefined;
  }

  async search(query: string, topK: number) {
    if (!this.byRow.size) return [];
    const r = await this.memory.search(query, { filters: SCOPE, topK, threshold: 0 });
    return (r.results as any[]).flatMap(h => { const id = this.rowOf(h); return id ? [{ id, score: Number(h.score ?? 0) }] : []; });
  }

  async nearest(text: string) {
    if (!this.byRow.size) return null;
    await this.memory._ensureInitialized?.();
    const vector = await this.memory.embedder.embed(text, 'search');
    const [hit] = await this.memory.vectorStore.search(vector, 1, SCOPE);
    const id = hit && this.rowOf(hit);
    return id ? { id, similarity: Number(hit.score ?? 0) } : null;
  }

  /** Cosine similarity to the closest existing memories, best first. */
  async similar(text: string, topK: number) {
    if (!this.byRow.size) return [];
    await this.memory._ensureInitialized?.();
    const vector = await this.memory.embedder.embed(text, 'search');
    const hits = await this.memory.vectorStore.search(vector, topK, SCOPE) as any[];
    return hits.flatMap(h => { const id = this.rowOf(h); return id ? [{ id, similarity: Number(h.score ?? 0) }] : []; });
  }

  /** mem0's additive extraction: the model sees the conversation and the closest existing
   *  memories and returns only new facts. mem0 stores them in its scratch store; they are
   *  taken back out here, because the encrypted rows are the only store. */
  async categorize(texts: string[]) {
    return this.sampler.current ? categorizeWith(this.sampler.current, texts) : texts.map(() => []);
  }

  async extractFacts(messages: ChatMessage[]) {
    if (!this.sampler.current) return [];
    const r = await this.memory.add(messages, { userId: SCOPE.user_id, infer: true });
    const added = (r.results as any[]).filter(x => (x.metadata?.event ?? x.event ?? 'ADD') === 'ADD');
    for (const x of added) if (x.id) await this.memory.delete(x.id);
    return added.map(x => String(x.memory ?? '')).filter(Boolean);
  }
}

/** An engine created on first use, so the bridge starts without loading the model.
 *  DECOY_MEMORY_ENGINE=basic skips mem0 (no model download). */
export function lazyMemoryEngine(opts: { sample?: Sampler; modelDir?: string } = {}): MemoryEngineLike {
  let made: Promise<MemoryEngineLike> | null = null;
  const get = () => (made ??= process.env.DECOY_MEMORY_ENGINE === 'basic' ? Promise.resolve(new BasicEngine(opts.sample)) : createMemoryEngine(opts));
  return {
    mirror: async (records) => (await get()).mirror(records),
    search: async (query, topK) => (await get()).search(query, topK),
    nearest: async (text) => (await get()).nearest(text),
    similar: async (text, topK) => {
      const e = await get();
      if (e.similar) return e.similar(text, topK);
      const one = await e.nearest(text);
      return one ? [one] : [];
    },
    closeAt: async () => (await get()).closeAt?.(),
    extractFacts: async (messages) => (await get()).extractFacts(messages),
    categorize: async (texts) => (await get()).categorize?.(texts) ?? texts.map(() => []),
    close: async () => { if (made) await (await made).close?.(); },
  };
}

/** mem0's engine if its optional packages are installed, otherwise the basic one. */
export async function createMemoryEngine(opts: { sample?: Sampler; modelDir?: string } = {}): Promise<MemoryEngineLike & { setSampler?: (s: Sampler | undefined) => void }> {
  try { return await Mem0Engine.create(opts); } catch (err) {
    // Missing optional packages are expected; a model that failed to download or verify is said.
    if (/embedding model/.test((err as Error)?.message ?? '')) console.error('[Decoy] Memory search uses the basic engine:', (err as Error).message);
    return new BasicEngine(opts.sample);
  }
}

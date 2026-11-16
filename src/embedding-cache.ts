// The local search index's vectors, kept between runs.
//
// The bridge searches memories on this machine with a local embedding model (src/memory-engine.ts).
// Every new process used to embed every memory again: with a few hundred memories that is many
// seconds, for the first search of every session, every one-shot `call` and every prompt hook.
//
// The vectors are kept in one file per connection key and model, encrypted with AES-256-GCM under a
// key derived (HKDF-SHA256) from this connection's own private key, which already sits beside it
// readable by this OS user only. A vector is filed under a hash of its memory's text; the file holds
// only the memories the vault still has when it is written, never a search query. A search query's
// vector is held in memory only until the next write, and never causes one. A file that cannot be
// opened (another key, another model, damaged) is ignored and replaced at the next write. Nothing
// here is ever sent anywhere.

import { createCipheriv, createDecipheriv, createHash, createPrivateKey, hkdfSync, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

const MAGIC = Buffer.from('DEC1');
const textKey = (text: string) => createHash('sha256').update(text).digest('base64url');

export interface EmbeddingCache {
  get(text: string): number[] | undefined;
  set(text: string, vector: number[]): void;
  /** Write the vectors of `keep` (the memories' texts now) when they differ from the file's, and
   *  hold no other vector after it (a search query's). Never throws. */
  flush(keep: Set<string>): void;
}

/** Embeddings in LangChain's shape, as mem0's embedder takes them. */
export interface Embeddings {
  embedQuery(text: string): Promise<number[]>;
  embedDocuments(texts: string[]): Promise<number[][]>;
}

/** One key per connection key and model: the file is named by a hash of both, never the key itself. */
function cacheKeyAndFile(o: { dir: string; privateKeyPem: string; model: string }): { key: Buffer; file: string } {
  const der = createPrivateKey(o.privateKeyPem).export({ type: 'pkcs8', format: 'der' });
  const key = Buffer.from(hkdfSync('sha256', der, Buffer.from('decoy-embedding-cache'), Buffer.from(`v1:${o.model}`), 32));
  const id = createHash('sha256').update(key).digest('hex').slice(0, 24);
  return { key, file: join(o.dir, `embeddings-${id}.bin`) };
}

/** The file a connection's kept vectors are in, for that connection key and model. */
export const embeddingCacheFile = (o: { dir: string; privateKeyPem: string; model: string }): string => cacheKeyAndFile(o).file;

export function openEmbeddingCache(o: { dir: string; privateKeyPem: string; model: string }): EmbeddingCache {
  const { key, file } = cacheKeyAndFile(o);
  const aad = Buffer.from(`decoy-embedding-cache/v1/${o.model}`);

  const held = new Map<string, number[]>();
  try {
    const bytes = readFileSync(file);
    if (bytes.subarray(0, 4).equals(MAGIC)) {
      const iv = bytes.subarray(4, 16), tag = bytes.subarray(16, 32), body = bytes.subarray(32);
      const d = createDecipheriv('aes-256-gcm', key, iv); d.setAAD(aad); d.setAuthTag(tag);
      const plain = Buffer.concat([d.update(body), d.final()]);
      const parsed = JSON.parse(plain.toString('utf8')) as { model?: string; v?: Record<string, string> };
      if (parsed.model === o.model && parsed.v && typeof parsed.v === 'object') {
        for (const [k, b64] of Object.entries(parsed.v)) {
          const buf = Buffer.from(b64, 'base64');
          held.set(k, Array.from(new Float32Array(buf.buffer, buf.byteOffset, Math.floor(buf.length / 4))));
        }
      }
    }
  } catch { /* none yet, another key, damaged: start empty */ }
  // What the file on disk holds. A vector of the same text under the same model is the same
  // vector, so the file is written only when the set of memories it holds would change.
  const loaded = new Set(held.keys());

  return {
    get: (text) => held.get(textKey(text)),
    set(text, vector) { held.set(textKey(text), vector); },
    flush(keep) {
      try {
        const want = new Set([...keep].map(textKey));
        // A vector that is not a memory's (a search query's, a deleted memory's) goes now.
        for (const k of [...held.keys()]) if (!want.has(k)) held.delete(k);
        const kept = [...held.keys()];
        // Nothing new and nothing gone: the file on disk is already right.
        if (kept.length === loaded.size && kept.every((k) => loaded.has(k))) return;
        const v: Record<string, string> = {};
        for (const k of kept) v[k] = Buffer.from(new Float32Array(held.get(k)!).buffer).toString('base64');
        const iv = randomBytes(12);
        const c = createCipheriv('aes-256-gcm', key, iv); c.setAAD(aad);
        const body = Buffer.concat([c.update(Buffer.from(JSON.stringify({ model: o.model, v }), 'utf8')), c.final()]);
        mkdirSync(o.dir, { recursive: true, mode: 0o700 });
        try { chmodSync(o.dir, 0o700); } catch { /* not ours to change */ }
        const tmp = `${file}.${process.pid}.tmp`;
        writeFileSync(tmp, Buffer.concat([MAGIC, iv, c.getAuthTag(), body]), { mode: 0o600 });
        renameSync(tmp, file);
        loaded.clear(); for (const k of kept) loaded.add(k);
      } catch { /* the cache is a convenience: a write that fails changes nothing */ }
    },
  };
}

/** Embeddings that ask the model only for texts the cache does not hold. */
export function withEmbeddingCache(model: Embeddings, cache: EmbeddingCache): Embeddings {
  return {
    async embedQuery(text) {
      const hit = cache.get(text);
      if (hit) return hit;
      const v = await model.embedQuery(text);
      cache.set(text, v);
      return v;
    },
    async embedDocuments(texts) {
      // Hits are taken before the model runs: a write while it runs may let go of a held vector.
      const out = texts.map((t) => cache.get(t));
      const missing = [...new Set(texts.filter((_, i) => !out[i]))];
      const made = missing.length ? await model.embedDocuments(missing) : [];
      const byText = new Map(missing.map((t, i) => [t, made[i]]));
      missing.forEach((t, i) => cache.set(t, made[i]));
      return texts.map((t, i) => out[i] ?? byText.get(t)!);
    },
  };
}

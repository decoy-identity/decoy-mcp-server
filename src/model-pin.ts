/**
 * The embedding model, pinned. fastembed would fetch it from the repo's moving `main` branch
 * with no integrity check and hand it to the native ONNX runtime; instead each file comes from a
 * fixed commit and is checked against its SHA-256 before fastembed (which skips files already
 * present) ever reads it. A file that doesn't verify is never used.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

export const MODEL_REPO = 'Qdrant/bge-small-en-v1.5-onnx-Q';
export const MODEL_REVISION = 'aa8f8b060edb00e03bfdd08813a2949946c8ba55';
export const MODEL_FILES: Record<string, string> = {
  'model_optimized.onnx': '51f1bd0addd6e859e42c2c8021a5e5461385bb676a649f4b269aa445449f2431',
  'config.json': '13582bcf2effc85b7bf3d3f5532e686bc1c9ce86bb009d10f0ec33cbe92299dd',
  'special_tokens_map.json': '5d5b662e421ea9fac075174bb0688ee0d9431699900b90662acd44b2a350503a',
  'tokenizer.json': 'd241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66',
  'tokenizer_config.json': '0b29c7bfc889e53b36d9dd3e686dd4300f6525110eaa98c76a5dafceb2029f53',
};

async function sha256File(file: string): Promise<string> {
  const h = createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) h.update(chunk as Buffer);
  return h.digest('hex');
}

/** Make cacheDir/<repo as fastembed names it> hold exactly the pinned, verified files. */
export async function ensurePinnedModel(cacheDir: string, o: {
  repo?: string; revision?: string; files?: Record<string, string>; fetch?: typeof fetch; endpoint?: string;
} = {}): Promise<string> {
  const repo = o.repo ?? MODEL_REPO, revision = o.revision ?? MODEL_REVISION, files = o.files ?? MODEL_FILES;
  const doFetch = o.fetch ?? fetch;
  const endpoint = (o.endpoint ?? process.env.HF_ENDPOINT ?? 'https://huggingface.co').replace(/\/$/, '');
  const dir = path.join(cacheDir, repo.replace('/', '_'));
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const [name, expected] of Object.entries(files)) {
    const file = path.join(dir, name);
    if (fs.existsSync(file) && await sha256File(file) === expected) continue;
    fs.rmSync(file, { force: true });
    const res = await doFetch(`${endpoint}/${repo}/resolve/${revision}/${name}`);
    if (!res.ok) throw new Error(`Downloading the embedding model failed: ${name} (HTTP ${res.status}).`);
    const part = path.join(dir, `.${name}.${randomBytes(6).toString('hex')}.part`);
    try {
      fs.writeFileSync(part, Buffer.from(await res.arrayBuffer()), { mode: 0o600, flag: 'wx' });
      if (await sha256File(part) !== expected) throw new Error(`The embedding model file ${name} failed verification; it was not used.`);
      fs.renameSync(part, file);
    } finally {
      fs.rmSync(part, { force: true });
    }
  }
  return dir;
}

// Refresh the committed setup source. The bridge reads it locally and never fetches it at runtime.
import { mkdir, readFile, writeFile } from 'node:fs/promises';

const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--from' || !args[1])) {
  throw new Error('Usage: node scripts/sync-agent-setup.mjs [--from <file>]');
}
const source = args[1] ?? 'https://www.decoys.me/agent-setup.json';
let bytes;
if (args.length) {
  bytes = await readFile(source);
} else {
  const response = await fetch(source, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`Could not fetch agent setup: HTTP ${response.status}`);
  bytes = Buffer.from(await response.arrayBuffer());
}
const setup = JSON.parse(bytes.toString('utf8'));
for (const field of ['firstSave', 'postConnectionSetup', 'any']) {
  if (typeof setup?.[field] !== 'string' || !setup[field].trim()) {
    throw new Error(`Agent setup must contain a nonempty ${field} string`);
  }
}
if (!setup.agents || typeof setup.agents !== 'object' || Array.isArray(setup.agents)) {
  throw new Error('Agent setup must contain an agents object');
}
const details = setup.firstConnect?.authorization_details;
if (!Array.isArray(details) || !details.length || details.some((row) =>
  row?.type !== 'https://decoys.me/oauth/types/unlock'
  || !Array.isArray(row.permissions) || !row.permissions.length
  || row.permissions.some((name) => typeof name !== 'string' || !name.trim()))) {
  throw new Error('Agent setup must contain nonempty firstConnect.authorization_details with named permissions');
}
if (!setup.any.match(/^2\. [^\n]*facts, ([^,\n]+), with/m)?.[1]
    || !setup.firstSave.match(/\. ([^.,]+,[^.,]+), filed [^.]+\.$/)?.[1]) {
  throw new Error('Agent setup memory rule structure changed; review the bridge wording before syncing');
}
const vendor = new URL('../vendor/', import.meta.url);
await mkdir(vendor, { recursive: true });
await writeFile(new URL('agent-setup.json', vendor), bytes);
console.log(`Saved ${bytes.length} unchanged bytes from ${source}`);

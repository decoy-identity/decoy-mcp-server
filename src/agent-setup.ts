import { readFileSync } from 'node:fs';

/** The website's published setup, shipped with the bridge; never fetched while it runs. */
export const AGENT_SETUP = JSON.parse(readFileSync(new URL('../vendor/agent-setup.json', import.meta.url), 'utf8')) as {
  firstSave: string;
  postConnectionSetup: string;
  any: string;
  agents: Record<string, string>;
  firstConnect: {
    authorization_details: Array<{
      type: 'https://decoys.me/oauth/types/unlock';
      permissions: string[];
    }>;
  };
};

const details = AGENT_SETUP.firstConnect?.authorization_details;
if (!Array.isArray(details) || !details.length || details.some((row) =>
  row?.type !== 'https://decoys.me/oauth/types/unlock'
  || !Array.isArray(row.permissions) || !row.permissions.length
  || row.permissions.some((name) => typeof name !== 'string' || !name.trim()))) {
  throw new Error('The bundled agent setup must contain nonempty firstConnect.authorization_details with named permissions.');
}

// The short recurring rule already used by reminders and the operating rules. Read its wording
// from the setup too, without turning a recurring reminder into a request for the initial save.
function fragment(text: string, pattern: RegExp): string {
  const found = text.match(pattern)?.[1];
  if (!found) throw new Error('The vendored agent setup has an unsupported memory-rule format.');
  return found;
}
export const MEMORY_FACT_PHRASE = fragment(AGENT_SETUP.any, /^2\. [^\n]*facts, ([^,\n]+), with/m);
export const MEMORY_FACT_HEADING = fragment(AGENT_SETUP.firstSave, /\. ([^.,]+,[^.,]+), filed [^.]+\.$/).toUpperCase();

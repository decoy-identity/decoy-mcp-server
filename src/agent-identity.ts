/**
 * The agent's identity at pairing, so the Decoy app shows its icon instead of its letter.
 *
 * POST /api/connect takes `client_uri` (RFC 7591: the agent's https site; Decoy uses only its host
 * and shows that site's favicon) and `icon` (one Phosphor name from the server's list, shown when
 * there is no favicon). The app shows favicon, else the picked icon.
 *
 * Known `DECOY_AGENT_FOR` slugs map to their site and a picked icon (KNOWN_AGENTS); any other slug
 * sends neither. DECOY_AGENT_URI (https only) and DECOY_AGENT_ICON (a listed name) override. An
 * override that is not valid is left out with a log line; the pairing goes ahead either way.
 * A first pairing that names no icon sends DEFAULT_AGENT_ICON (pairingBase only: the start-up sync sends
 * only what is configured, so it never adds a request for a bridge with nothing set). A pairing with a
 * stored client_id may be a Reconnect, which keeps the connection's stored icon unless the pairing names
 * one, so it sends no default; an id made for this pairing (`newClientId`) is a first pairing.
 *
 * With no site configured, the bridge works the agent out itself (detectedAgent): the site the MCP
 * client gives at initialize (clientInfo.websiteUrl), else what its name is (SITE_NAMES: the
 * product's own name as a whole word), else what the connection's name is (DECOY_AGENT_NAME, the name it
 * was approved under; with none of these, the name Decoy holds for the connection, which the owner may
 * have renamed: identity-sync.ts syncNamedIdentity). Only a host in KNOWN_AGENTS has a site: nothing
 * is ever guessed. That site
 * goes with a first pairing (pairingIdentity) and, for a connection made without one, once to
 * PATCH /api/agent/identity (identity-sync.ts syncDetectedIdentity), where Decoy takes it only from
 * a connection that has no site yet. It never replaces a configured site or icon (detectedIdentity).
 */
import { normalizedClientName } from './usage-report.js';


/** The Phosphor names the server accepts for `icon`: the same list as the Decoy API's
 *  (a test checks they match). */
export const AGENT_ICON_NAMES = [
  'airplane-tilt', 'bank', 'barbell', 'bed', 'bell', 'book-open', 'books', 'brain', 'briefcase', 'bug',
  'calendar', 'calendar-check', 'camera', 'car', 'chart-bar', 'chart-line', 'chat-circle', 'chat-teardrop-text',
  'check-square', 'clock', 'cloud', 'code', 'coffee', 'compass', 'cpu', 'credit-card', 'crown', 'database',
  'envelope', 'envelope-simple', 'file-text', 'film-slate', 'first-aid', 'flask', 'folder', 'fork-knife',
  'game-controller', 'gear', 'gift', 'globe', 'golf', 'graduation-cap', 'handshake', 'heart', 'heartbeat', 'house',
  'image', 'key', 'leaf', 'lightbulb', 'lightning', 'list-checks', 'lock-key', 'magnifying-glass',
  'map-trifold', 'megaphone', 'microphone', 'music-notes', 'newspaper', 'note-pencil', 'notebook', 'package',
  'palette', 'paw-print', 'pencil-simple', 'phone', 'puzzle-piece', 'receipt', 'robot', 'rocket-launch',
  'shield-check', 'shopping-bag', 'shopping-cart', 'smiley', 'sparkle', 'star', 'storefront', 'tag',
  'terminal-window', 'ticket', 'train', 'translate', 'tray', 'truck', 'user-circle', 'users', 'wallet',
] as const;
export type AgentIconName = (typeof AGENT_ICON_NAMES)[number];
const ICON_SET: ReadonlySet<string> = new Set(AGENT_ICON_NAMES);

/** The icon a pairing sends when nothing names one, so the app never shows a letter. */
export const DEFAULT_AGENT_ICON: AgentIconName = 'robot';

/** Each known `?for=` slug: its site (whose favicon Decoy shows) and the icon shown without one. */
export const KNOWN_AGENTS: Readonly<Record<string, { uri: string; icon: AgentIconName }>> = Object.freeze({
  cursor: { uri: 'https://cursor.com', icon: 'code' },
  'claude-code': { uri: 'https://claude.ai', icon: 'terminal-window' },
  claude: { uri: 'https://claude.ai', icon: 'sparkle' },
  codex: { uri: 'https://openai.com', icon: 'terminal-window' },
  openai: { uri: 'https://openai.com', icon: 'sparkle' },
  gemini: { uri: 'https://gemini.google.com', icon: 'sparkle' },
  windsurf: { uri: 'https://windsurf.com', icon: 'code' },
  // The hosts hostFamily tells apart (usage-report.ts), under the same words, so an MCP client or a
  // connection's name finds its site here too. A host with no entry has no site the bridge sends.
  'claude-desktop': { uri: 'https://claude.ai', icon: 'sparkle' },
  'claude-ai': { uri: 'https://claude.ai', icon: 'sparkle' },
  'gemini-cli': { uri: 'https://gemini.google.com', icon: 'terminal-window' },
  vscode: { uri: 'https://code.visualstudio.com', icon: 'code' },
  // The same sites Decoy's hosted connector names these apps by.
  chatgpt: { uri: 'https://chatgpt.com', icon: 'chat-circle' },
  grok: { uri: 'https://grok.com', icon: 'sparkle' },
  muse: { uri: 'https://muse.ai', icon: 'sparkle' },
  antigravity: { uri: 'https://antigravity.google', icon: 'code' },
  instinct: { uri: 'https://instinct.com', icon: 'lightning' },
});

export interface AgentIdentity {
  client_uri?: string;
  icon?: AgentIconName;
  /** Log lines for an override that was left out. Never the value itself. */
  notes: string[];
}

type Env = Record<string, string | undefined>;

/** `client_uri` and `icon` for this bridge's pairing, from DECOY_AGENT_FOR and the overrides. */
export function agentIdentity(env: Env): AgentIdentity {
  const slug = (env.DECOY_AGENT_FOR ?? '').trim().toLowerCase();
  const known = Object.hasOwn(KNOWN_AGENTS, slug) ? KNOWN_AGENTS[slug] : undefined;
  const id: AgentIdentity = { notes: [] };
  if (known) { id.client_uri = known.uri; id.icon = known.icon; }

  const uri = env.DECOY_AGENT_URI?.trim();
  if (uri) {
    if (isHttpsSite(uri)) id.client_uri = uri;
    else {
      delete id.client_uri;
      id.notes.push('[Decoy] DECOY_AGENT_URI is not an https address of a site, so no site is sent with the pairing.');
    }
  }
  const icon = env.DECOY_AGENT_ICON?.trim().toLowerCase();
  if (icon) {
    if (ICON_SET.has(icon)) id.icon = icon as AgentIconName;
    else {
      delete id.icon;
      id.notes.push(`[Decoy] DECOY_AGENT_ICON is not one of the icon names Decoy lists, so it is left out: a first pairing shows ${DEFAULT_AGENT_ICON}, and a Reconnect keeps the connection's icon.`);
    }
  }
  return id;
}

function isHttpsSite(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && !!u.hostname && !u.username && !u.password;
  } catch { return false; }
}

/** The longest site taken from an MCP client (Decoy's own limit for client_uri is lower still). */
const MAX_CLIENT_SITE = 2048;

/** What an MCP client says about itself at initialize (MCP `Implementation`): only these two are read. */
export interface ClientInfoLike { name?: unknown; websiteUrl?: unknown }

/** The site (and the icon shown without its favicon) the bridge worked out for the agent. */
export interface DetectedAgent { client_uri: string; icon?: AgentIconName }

/** A whole word of a client's name (normalizedClientName): never part of another word. */
const word = (w: string) => new RegExp(`(^|[-./@])(?:${w})($|[-./@])`);

/**
 * The names that are a known agent, first match wins: the words the agents give themselves (MCP
 * client names such as cursor-vscode, codex-mcp-client, openai-mcp, gemini-cli-mcp-client, and
 * connection names such as Claude Code or Muse). Unlike the usage counts' hostFamily, a site is taken
 * only from the product's own name, as a whole word: no alias for another product (Copilot, Devin,
 * Meta AI, an xAI or OpenAI SDK) and no word inside another word.
 */
const SITE_NAMES: ReadonlyArray<readonly [RegExp, string]> = [
  [word('claude-code'), 'claude-code'],
  [word('cursor'), 'cursor'],
  [word('codex'), 'codex'],
  [/(^|[-./@])chatgpt($|[-./@])|^openai-mcp$/, 'chatgpt'],
  [word('antigravity|agy'), 'antigravity'],
  [word('gemini'), 'gemini-cli'],
  [word('visual-studio-code|vscode'), 'vscode'],
  [word('windsurf'), 'windsurf'],
  [word('muse'), 'muse'],
  [word('grok'), 'grok'],
  [word('instinct'), 'instinct'],
  [word('claude'), 'claude-desktop'],
];

/** The known agent a name is (SITE_NAMES), if any. The bridge's own in-process clients are none. */
function knownByName(name: unknown): { uri: string; icon: AgentIconName } | undefined {
  if (typeof name !== 'string' || !name.trim() || /^decoy-/i.test(name.trim())) return undefined;
  const n = normalizedClientName(name.trim());
  const slug = SITE_NAMES.find(([re]) => re.test(n))?.[1];
  return slug !== undefined && Object.hasOwn(KNOWN_AGENTS, slug) ? KNOWN_AGENTS[slug] : undefined;
}

/**
 * The agent's site, worked out with no configuration: the MCP client's own site (an https
 * `websiteUrl`), else the known agent its name is, else the known agent the connection's name is
 * (DECOY_AGENT_NAME). Null when none of them says: nothing is ever guessed.
 */
export function detectedAgent(o: { client?: ClientInfoLike | null; name?: string | null }): DetectedAgent | null {
  const client = o.client ?? null;
  const fromClient = knownByName(client?.name);
  const site = typeof client?.websiteUrl === 'string' ? client.websiteUrl.trim() : '';
  if (site && site.length <= MAX_CLIENT_SITE && isHttpsSite(site)) return { client_uri: site, ...(fromClient ? { icon: fromClient.icon } : {}) };
  const known = fromClient ?? knownByName(o.name);
  return known ? { client_uri: known.uri, icon: known.icon } : null;
}

/** A site is configured: a known DECOY_AGENT_FOR, or any DECOY_AGENT_URI (even one that was refused). */
export function siteConfigured(env: Env): boolean {
  return Object.hasOwn(KNOWN_AGENTS, (env.DECOY_AGENT_FOR ?? '').trim().toLowerCase()) || !!env.DECOY_AGENT_URI?.trim();
}

/** The agent's picture is configured: a site (siteConfigured) or an icon (any DECOY_AGENT_ICON).
 *  Then the bridge works nothing out on its own. */
export function identityConfigured(env: Env): boolean {
  return siteConfigured(env) || !!env.DECOY_AGENT_ICON?.trim();
}

/**
 * What the bridge may add on its own to the configured identity: the detected site and its icon.
 * Null when a site is configured (a known DECOY_AGENT_FOR, or any DECOY_AGENT_URI, even one that was
 * refused), and when an icon is (any DECOY_AGENT_ICON): Decoy shows a site's favicon before the
 * picked icon, so a site added beside a configured icon would hide it. The configuration is never
 * replaced.
 */
export function detectedIdentity(env: Env, detected: DetectedAgent | null): DetectedAgent | null {
  if (!detected || identityConfigured(env)) return null;
  return { client_uri: detected.client_uri, ...(detected.icon ? { icon: detected.icon } : {}) };
}

/**
 * The identity a pairing sends: the configured one, with the detected site (and icon) added on a
 * first pairing. A pairing that may continue a connection (a Reconnect) sends only what is
 * configured: the owner approved that connection as it is.
 */
export function pairingIdentity(env: Env, detected: DetectedAgent | null, firstPairing: boolean): AgentIdentity {
  const id = agentIdentity(env);
  const add = firstPairing ? detectedIdentity(env, detected) : null;
  if (!add) return id;
  return { ...id, client_uri: add.client_uri, ...(add.icon ? { icon: add.icon } : {}) };
}

/** Who is pairing, in the body of POST /api/connect: the asks are added by pairingRequestBody (index.ts). */
export function pairingBase(o: {
  name: string; publicKeySpki: string; clientId?: string | null; identity: AgentIdentity;
  /** The client id was made for this pairing: a first pairing, never a Reconnect. */
  newClientId?: boolean;
}): Record<string, unknown> {
  return {
    name: o.name,
    platform: 'mcp',
    agent_public_key: o.publicKeySpki,
    ...(o.clientId && { client_id: o.clientId }),
    ...(o.identity.client_uri && { client_uri: o.identity.client_uri }),
    ...(o.identity.icon ? { icon: o.identity.icon } : o.clientId && !o.newClientId ? {} : { icon: DEFAULT_AGENT_ICON }),
  };
}

const IDENTITY_WARNINGS: Readonly<Record<string, string>> = {
  client_uri_ignored: '[Decoy] Decoy did not use the site sent with the pairing (client_uri_ignored), so the app shows the picked icon. The pairing continues.',
  icon_ignored: '[Decoy] Decoy did not use the icon sent with the pairing (icon_ignored). The pairing continues.',
};

/** Log lines for the server's warnings about `client_uri` / `icon`, by code only: the server's
 *  own text is never repeated. */
export function identityWarnings(body: unknown): string[] {
  const w = (body as { warnings?: unknown } | null | undefined)?.warnings;
  if (!Array.isArray(w)) return [];
  const lines: string[] = [];
  for (const item of w) {
    if (typeof item !== 'string') continue;
    const code = item.split(':', 1)[0].trim();
    if (Object.hasOwn(IDENTITY_WARNINGS, code)) lines.push(IDENTITY_WARNINGS[code]);
  }
  return lines;
}

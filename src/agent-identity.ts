/**
 * The agent's identity at pairing, so the Decoy app shows its icon instead of its letter.
 *
 * POST /api/connect takes `client_uri` (RFC 7591: the agent's https site; Decoy uses only its host
 * and shows that site's favicon) and `icon` (one Phosphor name from the server's list, shown when
 * there is no favicon). The app shows favicon, else the picked icon, else the letter.
 *
 * Known `DECOY_AGENT_FOR` slugs map to their site and a picked icon (KNOWN_AGENTS); any other slug
 * sends neither. DECOY_AGENT_URI (https only) and DECOY_AGENT_ICON (a listed name) override. An
 * override that is not valid is left out with a log line; the pairing goes ahead either way.
 */

/** The Phosphor names the server accepts for `icon`: the same list as the Decoy API's
 *  (a test checks they match). */
export const AGENT_ICON_NAMES = [
  'airplane-tilt', 'bank', 'barbell', 'bed', 'bell', 'book-open', 'books', 'brain', 'briefcase', 'bug',
  'calendar', 'calendar-check', 'camera', 'car', 'chart-bar', 'chart-line', 'chat-circle', 'chat-teardrop-text',
  'check-square', 'clock', 'cloud', 'code', 'coffee', 'compass', 'cpu', 'credit-card', 'crown', 'database',
  'envelope', 'envelope-simple', 'file-text', 'film-slate', 'first-aid', 'flask', 'folder', 'fork-knife',
  'game-controller', 'gear', 'gift', 'globe', 'graduation-cap', 'handshake', 'heart', 'heartbeat', 'house',
  'image', 'key', 'leaf', 'lightbulb', 'lightning', 'list-checks', 'lock-key', 'magnifying-glass',
  'map-trifold', 'megaphone', 'microphone', 'music-notes', 'newspaper', 'note-pencil', 'notebook', 'package',
  'palette', 'paw-print', 'pencil-simple', 'phone', 'puzzle-piece', 'receipt', 'robot', 'rocket-launch',
  'shield-check', 'shopping-bag', 'shopping-cart', 'smiley', 'sparkle', 'star', 'storefront', 'tag',
  'terminal-window', 'ticket', 'train', 'translate', 'tray', 'truck', 'user-circle', 'users', 'wallet',
] as const;
export type AgentIconName = (typeof AGENT_ICON_NAMES)[number];
const ICON_SET: ReadonlySet<string> = new Set(AGENT_ICON_NAMES);

/** Each known `?for=` slug: its site (whose favicon Decoy shows) and the icon shown without one. */
export const KNOWN_AGENTS: Readonly<Record<string, { uri: string; icon: AgentIconName }>> = Object.freeze({
  cursor: { uri: 'https://cursor.com', icon: 'code' },
  'claude-code': { uri: 'https://claude.ai', icon: 'terminal-window' },
  claude: { uri: 'https://claude.ai', icon: 'sparkle' },
  codex: { uri: 'https://openai.com', icon: 'terminal-window' },
  openai: { uri: 'https://openai.com', icon: 'sparkle' },
  gemini: { uri: 'https://gemini.google.com', icon: 'sparkle' },
  windsurf: { uri: 'https://windsurf.com', icon: 'code' },
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
      id.notes.push('[Decoy] DECOY_AGENT_ICON is not one of the icon names Decoy lists, so no icon is sent with the pairing.');
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

/** Who is pairing, in the body of POST /api/connect: the asks are added by pairingRequestBody (index.ts). */
export function pairingBase(o: {
  name: string; publicKeySpki: string; clientId?: string | null; identity: AgentIdentity;
}): Record<string, unknown> {
  return {
    name: o.name,
    platform: 'mcp',
    agent_public_key: o.publicKeySpki,
    ...(o.clientId && { client_id: o.clientId }),
    ...(o.identity.client_uri && { client_uri: o.identity.client_uri }),
    ...(o.identity.icon && { icon: o.identity.icon }),
  };
}

const IDENTITY_WARNINGS: Readonly<Record<string, string>> = {
  client_uri_ignored: '[Decoy] Decoy did not use the site sent with the pairing (client_uri_ignored), so the app shows the picked icon or the letter. The pairing continues.',
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

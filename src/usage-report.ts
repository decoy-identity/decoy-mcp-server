// The counts-only record of how a session used memory: POST /api/agent/memory-sessions.
//
// Decoy cannot see memories, so it cannot see whether agents use them. This record says how often:
// per day and host, whether the session read memory before other work, how many reads and saves,
// which reminders went out, and what host hooks did. Only small numbers and fixed words leave:
// never a query, a memory, an id, a title, a name, or the host's own name or version string (it is
// mapped to a fixed word here). DECOY_USAGE_REPORT=off (or false, 0, no) sends nothing.

export const USAGE_RECORD_FIELDS = ['day', 'host', 'kind', 'summary_sent', 'read_before_other', 'reads', 'saves', 'edits',
  'read_reminders', 'save_reminders', 'tool_calls', 'recalls_injected', 'save_checks'] as const;

export type UsageHost = 'claude-code' | 'claude-desktop' | 'claude-ai' | 'chatgpt' | 'codex' | 'cursor' | 'gemini-cli' | 'antigravity'
  | 'vscode' | 'windsurf' | 'goose' | 'muse' | 'grok' | 'instinct' | 'other';

/** A client's name as hostFamily reads it: lower case, spaces and underscores as hyphens. */
export const normalizedClientName = (clientName: string | null | undefined): string => (clientName ?? '').toLowerCase().replace(/[\s_]+/g, '-');

/** The host a client is, as one fixed word, from the name it gives in MCP initialize. */
export function hostFamily(clientName: string | null | undefined): UsageHost {
  const n = normalizedClientName(clientName);
  const rules: Array<[RegExp, UsageHost]> = [
    [/^claude-code|claude-code/, 'claude-code'],
    [/claude-ai|claude\.ai/, 'claude-ai'],
    [/claude/, 'claude-desktop'],
    [/codex/, 'codex'],
    [/openai|chatgpt/, 'chatgpt'],
    [/cursor/, 'cursor'],
    [/antigravity|^agy/, 'antigravity'],
    [/gemini/, 'gemini-cli'],
    [/visual-studio-code|vscode|copilot/, 'vscode'],
    [/windsurf|devin/, 'windsurf'],
    [/goose/, 'goose'],
    // Muse (Meta's agent): "muse" or "meta" as a whole word, never a name that only contains one.
    [/(^|[-./@])(muse|meta)($|[-./])/, 'muse'],
    [/grok|xai/, 'grok'],
    [/instinct/, 'instinct'],
  ];
  return rules.find(([r]) => r.test(n))?.[1] ?? 'other';
}

/**
 * The host a session is counted under. Claude Desktop names itself "claude-ai", the name claude.ai's
 * connectors use too; claude.ai on the web cannot reach a bridge on this computer, so outside listing
 * mode (the store-safe profile only the hosted connector runs) that name is Claude Desktop.
 */
export function usageHost(clientName: string | null | undefined, { listing }: { listing: boolean }): UsageHost {
  const host = hostFamily(clientName);
  return host === 'claude-ai' && !listing ? 'claude-desktop' : host;
}

export interface SessionCounts {
  host: UsageHost; at: Date; toolCalls: number; reads: number; saves: number;
  readBeforeOther: boolean; summarySent: boolean; readNudged: boolean; saveNudged: boolean;
}

export function sessionRecord(c: SessionCounts): Record<typeof USAGE_RECORD_FIELDS[number], string | number | boolean> {
  return {
    day: c.at.toISOString().slice(0, 10), host: c.host, kind: 'session',
    summary_sent: c.summarySent, read_before_other: c.readBeforeOther,
    reads: c.reads, saves: c.saves, edits: 0,
    read_reminders: c.readNudged ? 1 : 0, save_reminders: c.saveNudged ? 1 : 0,
    tool_calls: c.toolCalls, recalls_injected: 0, save_checks: 0,
  };
}

/** A hook run's record: a session-start brief (`context_run`), or what the hooks did (`hooks`). */
export function hookRecord(kind: 'context_run' | 'hooks', host: UsageHost, at: Date, counts: { recalls?: number; checks?: number } = {}): Record<string, string | number> {
  return { day: at.toISOString().slice(0, 10), host, kind, recalls_injected: counts.recalls ?? 0, save_checks: counts.checks ?? 0 };
}

/** Off when DECOY_USAGE_REPORT is off, false, 0 or no (any case, spaces around ignored). */
export const usageReportOn = (): boolean => !/^(off|false|0|no)$/i.test((process.env.DECOY_USAGE_REPORT ?? '').trim());

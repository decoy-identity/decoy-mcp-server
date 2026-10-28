// Use the bridge without a running server: the command line of `call` and `tools`, and how a
// result is printed for a shell.
//
//   decoy-mcp-server call <tool> [<json-arguments> | - | @file] [--json]
//   decoy-mcp-server tools [<tool>] [--json]
//
// `call` runs one tool call through this process's own server (the same tool handlers a connected
// MCP client reaches; no listener, no port) and prints what the client would receive:
//
//   default   each content block's text, in order; a line `---` between two blocks
//   --json    one line: { "isError": …, "content": [ … ], "structuredContent": … }
//
// Exit codes: 0 a tool result (an error result too: it is printed; arguments the tool's schema
// refuses come back that way); 2 a usage error (no tool, an unknown tool or option, arguments that
// are not a JSON object); 1 the command could not run (not connected, a setting the bridge refuses).
//
// Arguments are JSON on the command line, `-` for standard input, or `@file`. Anything typed on a
// command line stays in the shell's history: text with a secret in it goes through `-` or a file.
import fs from 'node:fs';

/** How long one request to Decoy may take in a `call`. A renewal has its own, shorter limit. */
export const CALL_REQUEST_TIMEOUT_MS = 30_000;
/** How long the one tool call may take in all (a request for access waits for the owner). */
export const CALL_TOOL_TIMEOUT_MS = 10 * 60_000;
/** How long the first result of a session waits for the summary of memories: there is no later
 *  result in this process to carry it. */
export const CALL_BRIEF_WAIT_MS = 4_000;

export const CALL_USAGE = 'Usage: decoy-mcp-server call <tool> [<json-arguments> | - | @file] [--json]\n' +
  '  <json-arguments>  the tool\'s arguments as one JSON object (default: {})\n' +
  '  -                 read the JSON from standard input\n' +
  '  @file             read the JSON from a file\n' +
  '  --json            print one JSON object { isError, content } instead of text\n' +
  'Run `decoy-mcp-server tools` to list the tools.';
export const TOOLS_USAGE = 'Usage: decoy-mcp-server tools [<tool>] [--json]';

/** A command line this command does not take. The message is printed, and the exit code is 2. */
export class UsageError extends Error {}

function split(argv: string[], usage: string, maxPositional: number): { positional: string[]; json: boolean } {
  const positional: string[] = [];
  let json = false;
  for (const a of argv) {
    if (a === '--json') json = true;
    else if (a.startsWith('--')) throw new UsageError(`Unknown option ${a.slice(0, 40)}.\n${usage}`);
    else positional.push(a);
  }
  if (positional.length > maxPositional) throw new UsageError(usage);
  return { positional, json };
}

/** The arguments after `call`. Reads standard input or the file when asked to. */
export function parseCallArgs(argv: string[], io: { stdin?: () => string; readFile?: (file: string) => string } = {}): { tool: string; args: Record<string, unknown>; json: boolean } {
  const { positional, json } = split(argv, CALL_USAGE, 2);
  const [tool, given] = positional;
  if (!tool) throw new UsageError(CALL_USAGE);
  let text = given ?? '{}';
  let what = 'The arguments are';
  if (given === '-') {
    what = 'Standard input is';
    try { text = (io.stdin ?? (() => fs.readFileSync(0, 'utf8')))(); } catch { throw new UsageError('Standard input could not be read.'); }
  } else if (given?.startsWith('@')) {
    what = 'The arguments file is';
    // The file's name is the caller's own; nothing of its contents is echoed.
    try { text = (io.readFile ?? ((f: string) => fs.readFileSync(f, 'utf8')))(given.slice(1)); } catch { throw new UsageError(`The arguments file could not be read: ${given.slice(1)}`); }
  }
  const EXAMPLE = 'Pass one JSON object, for example \'{"query":"kitchen"}\'.';
  let parsed: unknown;
  // What was passed is never echoed back: it may be the text of a memory.
  try { parsed = JSON.parse(text.trim() || '{}'); } catch { throw new UsageError(`${what} not valid JSON. ${EXAMPLE}`); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new UsageError(`The arguments must be a JSON object. ${EXAMPLE}`);
  return { tool, args: parsed as Record<string, unknown>, json };
}

/** The arguments after `tools`. */
export function parseToolsArgs(argv: string[]): { tool?: string; json: boolean } {
  const { positional, json } = split(argv, TOOLS_USAGE, 1);
  return { ...(positional[0] ? { tool: positional[0] } : {}), json };
}

export interface ToolResult { content?: unknown; isError?: boolean; structuredContent?: unknown }
type Block = { type?: unknown; text?: unknown };

/** A tool result as it is printed. Text: the blocks in order, `---` on a line of its own between
 *  two of them. JSON: one line holding exactly what the client received. */
export function renderResult(result: ToolResult, json: boolean): string {
  const content = Array.isArray(result.content) ? result.content as Block[] : [];
  if (json) {
    return JSON.stringify({ isError: result.isError === true, content, ...(result.structuredContent !== undefined ? { structuredContent: result.structuredContent } : {}) }) + '\n';
  }
  const texts = content.map((c) => (c && c.type === 'text' && typeof c.text === 'string' ? c.text.replace(/\n+$/, '') : `[${typeof c?.type === 'string' ? c.type.slice(0, 40) : 'unknown'} content: use --json]`));
  return texts.join('\n---\n') + '\n';
}

export interface ListedTool { name: string; description?: string; inputSchema?: { properties?: Record<string, { type?: unknown }>; required?: string[] } }
const HEAD_CHARS = 240;

/** The first sentence of a description, on one line, cut at HEAD_CHARS. */
function firstSentence(description: string): string {
  const line = description.split('\n')[0] ?? '';
  const end = /[.!?](?=\s|$)/.exec(line);
  const sentence = end ? line.slice(0, end.index + 1) : line;
  return sentence.length > HEAD_CHARS ? `${sentence.slice(0, HEAD_CHARS - 1)}…` : sentence;
}

/** Every tool on two lines: its name with the first sentence of its description, then its arguments. */
export function renderToolList(tools: ListedTool[]): string {
  return tools.map((t) => {
    const required = new Set(t.inputSchema?.required ?? []);
    const args = Object.entries(t.inputSchema?.properties ?? {}).map(([name, p]) => `${name} (${typeof p?.type === 'string' ? p.type : 'value'}${required.has(name) ? ', required' : ''})`);
    return `${t.name}: ${firstSentence(t.description ?? '')}\n  arguments: ${args.length ? args.join(', ') : 'none'}\n`;
  }).join('');
}

/** One tool whole: its name, its description, and its input schema. */
export function renderTool(t: ListedTool): string {
  return `${t.name}\n${t.description ?? ''}\nInput schema:\n${JSON.stringify(t.inputSchema ?? {}, null, 2)}\n`;
}

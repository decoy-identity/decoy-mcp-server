// Decoy as the first step of every task: what `decoy-mcp-server --context` prints, and the one
// line that tells an agent how to make that run happen at the start of its tasks.
//
// The output is plain text and short, in a fixed order: what this is, the summary of what is
// saved, the two habits, and what changed since the last run on this machine. The full memory
// rules follow only with `--context --full`.
//
// A session-start hook runs it, so it is quick and never fails: every way it can go wrong is one
// line that states a fact, printed within CONTEXT_DEADLINE_MS. It only reads: it never renews a
// token (the bridge does that), so a token Decoy refuses is the "could not be read" line.

import type { ContextSeen } from './context-seen.js';
import { PLAIN_VERSION, UPDATE_COMMAND } from './api-error.js';

/** The time budget of a whole `--context` run, counted from the start of its process: the run has
 *  printed by then, whatever Decoy did. A hook waits for the run as a whole, so the whole is what
 *  is bounded. A run makes several requests one after another, and a limit on each of them alone
 *  bounds no run. */
export const CONTEXT_DEADLINE_MS = 10_000;
/** How long one request to Decoy may take in a `--context` run: half the budget. It is not what
 *  bounds the run. It ends a request that will never be answered, so a Decoy that cannot be
 *  reached is said as "could not be read" halfway through the budget and not at its end. */
export const CONTEXT_REQUEST_TIMEOUT_MS = 5_000;
/** The end of the budget is kept for printing. Account names that have not arrived this long
 *  before it are left out, and the summary is printed without them. */
export const CONTEXT_NAMES_RESERVE_MS = 500;

export const CONTEXT_LEAD = 'Decoy holds what is known about this person. Reading this is the first step of every task, including tasks with no login.';
export const CONTEXT_HABITS = [
  'Before you start, and before asking the person: read what is saved (search_memories for the subject of the task, and list_topics).',
  'As you work: save lasting facts as they come up (add_memory), each linked to the account or topic it belongs to.',
] as const;
/** Said only by a connection that reads all memories: for any other, nothing it can read is all that is known. */
export const CONTEXT_NOTHING_SAVED = 'Nothing is saved about this person so far.';
export const CONTEXT_NOTHING_READABLE = 'Nothing this connection can read is saved so far.';
/** Addressed to the person, as a fact: the command is theirs to run, pinned to the version that prints this. */
export const contextNotPaired = (version: string) =>
  `Decoy is not connected on this machine, so nothing is known from it for this task. The person can connect it with \`npx -y decoy-mcp-server@${version}\`.`;
export const CONTEXT_NO_MEMORY_ACCESS = 'Decoy is connected, but this connection cannot read memories, so nothing is known from it for this task.';
/** Follows CONTEXT_NO_MEMORY_ACCESS on the first run that finds no access, and on no later one. */
export const CONTEXT_MAY_ASK = 'If the person wants this connection to read them, you may ask once: request_access({ permissions: ["memory.read"] }).';
/** A request that failed, and a token Decoy refuses (expired, replaced or revoked): both are this. */
export const CONTEXT_UNAVAILABLE = 'Decoy could not be read, so nothing is known from it for this task. Carry on with the task.';
export const CONTEXT_TIMED_OUT = 'Decoy did not answer in time, so nothing is known from it for this task. Carry on with the task.';
/** A setting the bridge refuses: the variable is named, its value never is. */
export const contextMisconfigured = (variable: string | null) =>
  `Decoy is not set up correctly on this machine${variable ? ` (environment variable ${variable})` : ''}, so nothing is known from it for this task.`;

/** How this bridge was started, as the command that starts it again when it is installed on this
 *  machine: the path of the command that was run, or `node` and the path of this bridge's file.
 *  null when npx started it (npm's own run of a package, or a file in npm's npx cache), and when
 *  the file is not a built one: then the npx command is the one to give. A path with a space in
 *  it is quoted; one that holds a quote, a backtick, a dollar sign or a line break is not given. */
export function launchCommand(o: { self: string; argv1?: string; entry: boolean; env: Record<string, string | undefined> }): string | null {
  if (o.env.npm_command === 'exec' || o.self.split(/[\\/]/).includes('_npx') || !o.self.endsWith('.js')) return null;
  const ran = o.entry && o.argv1?.split(/[\\/]/).pop() === 'decoy-mcp-server' ? o.argv1 : null;
  const path = ran ?? o.self;
  if (/["`$\r\n]/.test(path)) return null;
  const quoted = /^[\w@%+=:,.\/\\-]+$/.test(path) ? path : `"${path}"`;
  return ran ? quoted : `node ${quoted}`;
}
/** The command that is the first step: this bridge's own (launchCommand) when it is installed on
 *  the machine, else npx, pinned to the version that prints this. */
export const firstStepCommand = (version: string, local?: string | null) => (local ? `${local} --context` : `npx -y decoy-mcp-server@${version} --context`);
/** Said once per session while no `--context` run is recorded on this machine. */
export const firstStepLine = (version: string, local?: string | null) =>
  `Decoy first step: no run of it is recorded on this machine. At the start of every task, run \`${firstStepCommand(version, local)}\` and read its output; put that command in a session-start hook or in your standing notes.`;

/** A version's three numbers, and whether it is a prerelease (`-rc.1`); build metadata (`+x`) counts for nothing. */
const core = (v: string): { n: number[]; pre: boolean } | null => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})(-[^+]*)?(?:\+.*)?$/.exec(v);
  return m ? { n: [1, 2, 3].map(i => Number(m[i])), pre: !!m[4] } : null;
};
/** One line when Decoy says a newer bridge is published (GET /policies `bridge_update`), else null.
 *  The line is the bridge's own: only a well-formed released version newer than this one is taken
 *  from the answer, never its text or command. The line grants nothing: it says to update when the
 *  person's own setup text asks for the bridge to be kept current, and otherwise to tell the person. */
export function bridgeUpdateLine(answer: unknown, running: string): string | null {
  const u = answer && typeof answer === 'object' ? (answer as { bridge_update?: unknown }).bridge_update : null;
  const latest = u && typeof u === 'object' ? (u as { latest_version?: unknown }).latest_version : null;
  if (typeof latest !== 'string' || !PLAIN_VERSION.test(latest)) return null;
  const mine = core(running);
  const theirs = core(latest)!;
  if (!mine) return null;
  // A release is newer than its own prerelease (1.4.1 after 1.4.1-rc.1).
  const newer = theirs.n[0] - mine.n[0] || theirs.n[1] - mine.n[1] || theirs.n[2] - mine.n[2] || (mine.pre ? 1 : 0);
  if (newer <= 0) return null;
  const shown = /^[\w.+-]{1,40}$/.test(running) ? running : mine.n.join('.');
  // The version is Decoy's word, so a pin moves only once npm itself answers with that release.
  // The start command is not an update: it runs a bridge, so the update is a restart.
  return `decoy-mcp-server ${latest} is available (this bridge is ${shown}). If the person's setup text asks you to keep the bridge on its latest release, update it: ` +
    `a bridge started with \`${UPDATE_COMMAND}\` takes the new release when it restarts: restart it, and never run that command beside the running bridge (it starts a second one). ` +
    `An install with its own update: use that. A start command pinned to a version: change it to ${latest} only once \`npx -y decoy-mcp-server@${latest} --version\` answers ${latest}, then restart. ` +
    `The saved connection is kept. Otherwise, tell the person that ${latest} is out and give them that command.`;
}
/** The --context output with the update line after its first line. */
export const withUpdateLine = (text: string, line: string | null): string => {
  if (!line) return text;
  const i = text.indexOf('\n');
  return i < 0 ? `${text}\n${line}` : `${text.slice(0, i)}\n${line}${text.slice(i)}`;
};

const minute = (iso: string) => `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;

/** What changed since the last run, in one line; null when there is no earlier run to compare with.
 *  A memory counts as added or changed when the server dates it after the newest one the last run
 *  saw. When none does but the set differs (one was deleted, or the access now reaches other
 *  memories), that is said instead. A last run that could not read memories is said as that. The
 *  access is compared only like with like (a version with a version, a hash with a hash). */
export function sinceLastRun(prev: ContextSeen | null, now: ContextSeen, updatedAt: readonly string[]): string | null {
  if (!prev) return null;
  const since = prev.latest === null ? -Infinity : Date.parse(prev.latest);
  const changed = updatedAt.filter(t => Date.parse(t) > since).length;
  const memories = prev.count === null ? 'this connection can now read memories.'
    : changed > 0 ? `${changed} ${changed === 1 ? 'memory' : 'memories'} added or changed.`
    : prev.ids !== now.ids ? `the memories you can read changed (${prev.count} then, ${now.count} now).`
    : 'no memories added or changed.';
  const access = prev.access && now.access && prev.access !== now.access && prev.access[0] === now.access[0] ? ' Your access changed: call my_permissions.' : '';
  return `Since the last run on this machine (${minute(prev.at)}): ${memories}${access}`;
}

/** The whole output of a run that could read memories. `all`: the connection reads all memories. */
export function contextText(o: { brief: string; since: string | null; rules?: string; all?: boolean; waiting?: string | null }): string {
  // Memories that are waiting on the owner's Decoy app are saved: with none to show, the run says
  // that they are waiting, never that nothing is saved.
  const nothing = o.waiting ? [] : [o.all ? CONTEXT_NOTHING_SAVED : CONTEXT_NOTHING_READABLE];
  const short = [CONTEXT_LEAD, ...(o.brief.trim() ? [o.brief.trim()] : nothing), ...(o.waiting ? [o.waiting] : []), ...CONTEXT_HABITS, ...(o.since ? [o.since] : [])].join('\n');
  return o.rules ? `${short}\n\n${o.rules}` : short;
}

/** The output of a run on a connection that cannot read memories: the fact, and the call the
 *  agent may make, only on the run that could record having said it. */
export function noMemoryAccessText(ask: boolean): string {
  return ask ? `${CONTEXT_NO_MEMORY_ACCESS} ${CONTEXT_MAY_ASK}` : CONTEXT_NO_MEMORY_ACCESS;
}

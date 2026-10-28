// Reads that are waiting on the owner's Decoy app.
//
// A connection opens what the owner's app has sealed or wrapped to its key. When the app has not
// done that for a record, Decoy answers the read with a state instead of the data. This module
// turns each such answer into ONE shape, so every read says the same thing the same way:
//
//   { kind, state, count?, ids?, retry_after_seconds?, waiting_on?, recovery?, recovery_description? }
//
// and one line of text (waitingLine). The states, the recovery codes and the recovery sentences
// are Decoy's own; a code or a sentence this build does not know is left out, never relayed. The
// only other words are the fixed ones below. A record that is waiting is saved: it is reported
// here, never as missing and never dropped.

export type WaitingState = 'preparing' | 'failed' | 'unavailable' | 'unknown';
export type WaitingKind = 'memories' | 'account_fields' | 'mail' | 'account_secrets' | 'personal_info';

export interface Waiting {
  kind: WaitingKind;
  /** preparing: read again after retry_after_seconds. failed, unavailable: do not retry.
   *  unknown: Decoy listed the record and gave no state for it. */
  state: WaitingState;
  /** How many records; left out when Decoy says some are waiting and not how many. */
  count?: number;
  /** True when Decoy cut its list of ids, so `count` is a lower bound. */
  at_least?: true;
  /** The ids Decoy named (the ones this connection made, or asked for): UUIDs only. */
  ids?: string[];
  retry_after_seconds?: number;
  /** What a `preparing` read waits on, when Decoy names it. */
  waiting_on?: string;
  recovery?: string;
  recovery_description?: string;
}

/** Decoy's recovery codes for a read that is waiting. `stopped_asking`: Decoy asks the owner's
 *  phone for the copy on a schedule, and that schedule has ended. */
export const RECOVERY_CODES = ['owner_open_app', 'owner_keep_app_open', 'carry_on', 'not_shareable', 'stopped_asking', 'none'] as const;
/** What Decoy says a `preparing` read waits on. */
export const WAITING_ON = ['owner_phone'] as const;
/** Recovery codes that ask nothing of the owner: their line does not name the owner's app as awaited. */
const QUIET_RECOVERIES: readonly string[] = ['carry_on', 'stopped_asking'];

const OWED_WORDS = ['memories', 'account fields', 'earlier mail', 'the name of this address'];
/** Decoy's recovery sentences, word for word. One that is not here is not shown. */
export const RECOVERY_SENTENCES: ReadonlySet<string> = new Set([
  'The owner must open Decoy on their phone. If it still does not clear, they need to update the Decoy app. Stop retrying until then.',
  ...OWED_WORDS.map((what) => `The owner needs to open the Decoy app; this connection is waiting for it to share ${what}. Stop retrying until then.`),
  ...OWED_WORDS.map((what) => `The owner's Decoy app was opened and it has not shared ${what} with this connection yet. The owner should keep Decoy open for a minute. If that does not clear it, the last thing to try is updating the Decoy app. Stop retrying until the owner has done that.`),
  'These items are not available to this connection yet. Carry on with what you can read.',
  'The name of this address is not available to this connection yet. Carry on with what you can read.',
  'The owner\'s Decoy app could not share these items with this connection. Retrying will not help.',
  'Not shared with this connection yet. Decoy has stopped asking the owner\'s device for it on its own. It becomes readable if the device shares it, and reading again later may ask the device once more.',
]);

const KIND_WORDS: Record<WaitingKind, string> = {
  memories: 'memories', account_fields: 'account fields', mail: 'messages', account_secrets: 'account secrets', personal_info: 'personal info entries',
};
/** The bridge's own sentence for each state. */
const STATE_SENTENCE: Record<WaitingState, string> = {
  preparing: 'They are saved, and this connection cannot open them until the owner\'s Decoy app shares them. Do not report them as missing. Read again after the retry time.',
  failed: 'They are saved, and this connection cannot open them until the owner\'s Decoy app shares them. Do not report them as missing, and do not retry.',
  unavailable: 'They are saved, and this connection cannot open them. Do not report them as missing, and do not retry.',
  unknown: 'They are saved, and this connection cannot open them. Do not report them as missing.',
};

/** The bridge's own sentence for `stopped_asking`: what the agent does, with nothing for the owner to do. */
const STOPPED_ASKING_SENTENCE = 'They are saved, and this connection cannot open them. Do not report them as missing, do not retry now, and do not ask the owner to do anything. ' +
  'Carry on with what you can read; a read on a later day may ask the owner\'s phone once more.';

/** How a line starts. */
export const WAITING_LEAD = 'Waiting on the owner\'s Decoy app:';
export const QUIET_LEAD = 'Not available to this connection:';

/** The longest retry time taken as one (a day). Decoy's retry time is reported as it gave it; a
 *  value past this, or one that is not a positive number, is not a time and is left out. How long
 *  a tool call itself waits is bounded separately (MAX_ADDED_WAIT_MS). */
export const MAX_RETRY_SECONDS = 24 * 60 * 60;
/** The most waiting one tool call adds, over all its reads. A read is never made sooner than
 *  Decoy says: when the retry time is longer than what is left, the call reports what is waiting. */
export const MAX_ADDED_WAIT_MS = 15_000;
/** How many ids of one answer are taken, and how many of them a result shows; `count` says the rest. */
export const MAX_IDS_READ = 1000;
export const MAX_IDS_SHOWN = 20;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** The ids in an answer: a record's id is a UUID, and anything else is dropped. */
const ids = (v: unknown): string[] => {
  const out: string[] = [];
  if (Array.isArray(v)) for (const x of v) { if (typeof x === 'string' && UUID.test(x)) { out.push(x); if (out.length >= MAX_IDS_READ) break; } }
  return out;
};
/** Entries as a result shows them: at most MAX_IDS_SHOWN ids each. */
export const shownWaiting = (list: Waiting[]): Waiting[] =>
  list.map((w) => (w.ids && w.ids.length > MAX_IDS_SHOWN ? { ...w, ids: w.ids.slice(0, MAX_IDS_SHOWN) } : w));
const count = (v: unknown): number => (typeof v === 'number' && Number.isInteger(v) && v > 0 ? v : 0);
const retry = (v: unknown): number | undefined =>
  (typeof v === 'number' && Number.isFinite(v) && v > 0 && v <= MAX_RETRY_SECONDS ? Math.ceil(v) : undefined);
const waitingOn = (v: unknown): Pick<Waiting, 'waiting_on'> => ((WAITING_ON as readonly unknown[]).includes(v) ? { waiting_on: v as string } : {});
const recovery = (code: unknown, sentence: unknown): Pick<Waiting, 'recovery' | 'recovery_description'> => ({
  ...((RECOVERY_CODES as readonly unknown[]).includes(code) ? { recovery: code as string } : {}),
  ...(typeof sentence === 'string' && RECOVERY_SENTENCES.has(sentence) ? { recovery_description: sentence } : {}),
});

/**
 * What a LIST answer says is waiting (GET /context/memories, /accounts/:id/fields,
 * /sealed-secrets): `preparing` / `failed` / `unavailable` are the ids this connection may be
 * told, `*_others` a count of the rest, `preparing_unknown` that some are waiting and not how
 * many. Nothing when the answer names none of them.
 */
export function waitingFromList(kind: WaitingKind, body: unknown): Waiting[] {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  const out: Waiting[] = [];
  const cut = b.preparing_capped === true ? { at_least: true as const } : {};
  const entry = (state: WaitingState, named: string[], others: number, rest: Partial<Waiting>, some = false) => {
    const n = named.length + others;
    if (n === 0 && !some) return;
    out.push({ kind, state, ...(n > 0 ? { count: n } : {}), ...(n > 0 ? cut : {}), ...(named.length ? { ids: named } : {}), ...rest });
  };
  const wait = retry(b.retry_after_seconds);
  entry('preparing', ids(b.preparing), count(b.preparing_others), { ...(wait !== undefined ? { retry_after_seconds: wait } : {}), ...waitingOn(b.waiting_on) }, b.preparing_unknown === true);
  entry('failed', ids(b.failed), count(b.failed_others), recovery(b.recovery, b.recovery_description));
  entry('unavailable', ids(b.unavailable), count(b.unavailable_others), recovery(b.unavailable_recovery, b.unavailable_description));
  return out;
}

/**
 * What an answer about ONE read says (POST /unlock): `available: false`, with `state`,
 * `retry_after_seconds`, `recovery` and `recovery_description` when Decoy sends them. An answer
 * with no `state` is `preparing`; one with a state this build does not know is `unknown`. Null
 * when the answer is not a waiting one.
 */
export function waitingFromAnswer(kind: WaitingKind, body: unknown, named: string[] = []): Waiting | null {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  if (b.available !== false) return null;
  // No state is `preparing` (Decoy's answer for a copy it is asking for). A state this build
  // does not know is reported as unknown, never read as one it does.
  const state: WaitingState = b.state === undefined || b.state === null || b.state === 'preparing' ? 'preparing'
    : b.state === 'failed' || b.state === 'unavailable' ? b.state : 'unknown';
  const wait = state === 'preparing' ? retry(b.retry_after_seconds) : undefined;
  const listed = ids(named);
  return {
    kind, state, count: Math.max(listed.length, 1), ...(listed.length ? { ids: listed } : {}),
    ...(wait !== undefined ? { retry_after_seconds: wait } : {}),
    ...(state === 'preparing' ? waitingOn(b.waiting_on) : recovery(b.recovery, b.recovery_description)),
  };
}

/** Entries of the same kind, state and recovery, added up. */
export function mergeWaiting(list: Waiting[]): Waiting[] {
  const by = new Map<string, Waiting>();
  for (const w of list) {
    const key = [w.kind, w.state, w.recovery ?? '', w.recovery_description ?? '', w.waiting_on ?? ''].join('\n');
    const had = by.get(key);
    if (!had) { by.set(key, { ...w, ...(w.ids ? { ids: [...w.ids] } : {}) }); continue; }
    if (w.count !== undefined || had.count !== undefined) had.count = (had.count ?? 0) + (w.count ?? 0);
    if (w.at_least) had.at_least = true;
    if (w.ids?.length) had.ids = [...(had.ids ?? []), ...w.ids];
    const waits = [had.retry_after_seconds, w.retry_after_seconds].filter((n): n is number => n !== undefined);
    if (waits.length) had.retry_after_seconds = Math.max(...waits);
  }
  return [...by.values()];
}

/** One entry as one line: the same words in a tool result, an error and a `--context` run.
 *  Decoy's `carry_on` and `stopped_asking` ask nothing of anyone, so those lines do not start by
 *  naming the owner's app. */
export function waitingLine(w: Waiting): string {
  const n = w.count === undefined ? '' : ` (${w.at_least ? 'at least ' : ''}${w.count})`;
  const quiet = !!w.recovery && QUIET_RECOVERIES.includes(w.recovery);
  return [
    `${quiet ? QUIET_LEAD : WAITING_LEAD} ${KIND_WORDS[w.kind]}${n}.`,
    `state: ${w.state}.`,
    ...(w.waiting_on ? [`waiting_on: ${w.waiting_on}.`] : []),
    ...(w.retry_after_seconds !== undefined ? [`retry_after_seconds: ${w.retry_after_seconds}.`] : []),
    ...(w.recovery ? [`recovery: ${w.recovery}.`] : []),
    ...(w.recovery_description ? [w.recovery_description] : []),
    w.recovery === 'stopped_asking' ? STOPPED_ASKING_SENTENCE : STATE_SENTENCE[quiet ? 'unavailable' : w.state],
  ].join(' ');
}

// ── The name of an address ──
//
// An address's name is read from a copy sealed to this connection's key. When this connection may
// read the name and holds no copy, Decoy's read carries `metadata_seal: null` with
// `metadata_seal_state` (and, for `waiting`, `metadata_seal_code`). The states below are Decoy's;
// anything else is not passed on.

export type NameState = 'preparing' | 'waiting_for_owner_device' | 'not_shared_asking_stopped' | 'failed';
export interface NameWaiting {
  state: NameState;
  /** Decoy's retry time, as it gave it. Never with `not_shared_asking_stopped` or `failed`. */
  retry_after_seconds?: number;
  /** What the agent does. */
  next: string;
}
const NAME_NOT_SHARED = 'The name of this address is not shared with this connection yet, so service_name is null here: that does not mean the address has no name.';
const NAME_CARRY_ON = 'Carry on with its decoy_email and agent_label';
/** The bridge's instruction for each state, up to when to read again. */
export const NAME_NEXT: Record<NameState, string> = {
  preparing: `${NAME_NOT_SHARED} The owner's Decoy app has been asked to share it.`,
  waiting_for_owner_device: `${NAME_NOT_SHARED} Decoy is asking the owner's phone to share it, so do not ask the owner to do anything. ${NAME_CARRY_ON}.`,
  not_shared_asking_stopped: `${NAME_NOT_SHARED} Decoy has stopped asking the owner's phone for it on its own, so do not retry now and do not ask the owner to do anything. ` +
    `${NAME_CARRY_ON}; if the name is needed, tell the user that this connection cannot read it. A read on a later day may ask the phone once more.`,
  failed: `${NAME_NOT_SHARED} Decoy reports that sharing it with this connection has failed, and gives no time to read again, so do not retry now. ` +
    `${NAME_CARRY_ON}; if the name is needed, tell the user that this connection cannot read it.`,
};
/** When to read again: said only for a state that is still being asked for, and by the retry
 *  time only when Decoy gave one. */
const NAME_READ_AGAIN = { timed: 'Read it again after retry_after_seconds.', untimed: 'Decoy gave no retry time: read it again later, not at once.' };
/** The instruction for a state, with or without a retry time. */
export const nameNext = (state: NameState, timed: boolean): string =>
  (state === 'preparing' || state === 'waiting_for_owner_device' ? `${NAME_NEXT[state]} ${timed ? NAME_READ_AGAIN.timed : NAME_READ_AGAIN.untimed}` : NAME_NEXT[state]);
/** The longest retry time for a name that is passed on (a day). */
const MAX_NAME_RETRY_SECONDS = 24 * 60 * 60;

/** What a read of an address (or of its account) says about a name this connection holds no copy
 *  of. Null when the row carries a copy, no state, or a state that is not one of Decoy's. */
export function nameWaiting(row: unknown): NameWaiting | null {
  const r = (row && typeof row === 'object' ? row : {}) as Record<string, unknown>;
  if (typeof r.metadata_seal === 'string' && r.metadata_seal) return null;
  const state: NameState | null = r.metadata_seal_state === 'preparing' ? 'preparing'
    : r.metadata_seal_state === 'failed' ? 'failed'
    : r.metadata_seal_state === 'waiting' && (r.metadata_seal_code === 'waiting_for_owner_device' || r.metadata_seal_code === 'not_shared_asking_stopped') ? r.metadata_seal_code
    : null;
  if (!state) return null;
  const s = r.retry_after_seconds;
  const asking = state === 'preparing' || state === 'waiting_for_owner_device';
  const wait = asking && typeof s === 'number' && Number.isFinite(s) && s > 0 && s <= MAX_NAME_RETRY_SECONDS ? Math.ceil(s) : undefined;
  return { state, ...(wait !== undefined ? { retry_after_seconds: wait } : {}), next: nameNext(state, wait !== undefined) };
}

/** Every entry, one line each; null when nothing is waiting. */
export function waitingText(list: Waiting[]): string | null {
  return list.length ? mergeWaiting(list).map(waitingLine).join('\n') : null;
}

/** A read that has nothing to return because what it asked for is waiting. The message is the line. */
export class WaitingError extends Error {
  constructor(public readonly waiting: Waiting) {
    super(waitingLine(waiting));
    this.name = 'WaitingError';
  }
}

/** The seconds to wait before one more read, when anything is `preparing` with a retry time. */
export function retrySeconds(list: Waiting[]): number | null {
  const waits = list.filter((w) => w.state === 'preparing' && w.retry_after_seconds !== undefined).map((w) => w.retry_after_seconds!);
  return waits.length ? Math.max(...waits) : null;
}

/**
 * Read, and while the answer has something `preparing` with a retry time, wait that long and read
 * again: at most `tries` reads in all, and at most once per `gapMs` for the same `key` (a second
 * call inside that time reports what is waiting at once). Then the last answer stands.
 * `sleep` may refuse a wait by answering false without waiting (the tool call has no time left
 * for it): the last answer stands then too.
 */
export async function readWithRetry<T>(
  read: () => Promise<T>, waitingOf: (r: T) => Waiting[],
  o: { sleep: (ms: number) => Promise<unknown>; now: () => number; tries: number; gapMs: number; waited: Map<string, number>; key: string },
): Promise<T> {
  let r = await read();
  for (let n = 1; n < o.tries; n++) {
    const wait = retrySeconds(waitingOf(r));
    if (wait === null) return r;
    const last = o.waited.get(o.key);
    if (n === 1 && last !== undefined && o.now() - last < o.gapMs) return r;
    const at = o.now();
    if ((await o.sleep(wait * 1000)) === false) return r;
    o.waited.set(o.key, at);
    r = await read();
  }
  return r;
}

/** Wait `ms` (with the given sleep), or less when `signal` aborts first. Leaves no listener behind. */
export async function sleepUnlessAborted(sleep: (ms: number) => Promise<void>, ms: number, signal?: AbortSignal): Promise<void> {
  if (!signal) return sleep(ms);
  if (signal.aborted) return;
  let onAbort: () => void = () => {};
  try {
    await Promise.race([sleep(ms), new Promise<void>((r) => { onAbort = r; signal.addEventListener('abort', onAbort, { once: true }); })]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

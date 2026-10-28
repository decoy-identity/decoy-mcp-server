// Credential files (agent token, agent private key) are readable by this OS user only: the
// directory is 0700 and the file 0600. A write goes to a fresh temp file (created exclusively,
// owner-only, flushed to disk) that is renamed into place, so a crash never leaves half a token
// and a planted symlink is replaced rather than followed. A read re-tightens files older versions
// left open.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

/** Write `data` to a new owner-only temp file beside `file`, flush it, and rename it into place.
 *  `beforeRename` runs on the temp file first; if it throws, nothing is renamed and the temp file is removed. */
function replaceAtomically(file: string, data: string, beforeRename?: (tmp: string) => void): void {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString('hex')}.tmp`);
  let fd: number | null = null;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);            // on disk before it takes the name: a crash never leaves a short file
    fs.closeSync(fd); fd = null;
    beforeRename?.(tmp);
    fs.renameSync(tmp, file);
  } catch (err) {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  // Best effort: make the rename itself durable. Not every platform lets a directory be synced.
  try { const d = fs.openSync(dir, 'r'); try { fs.fsyncSync(d); } finally { fs.closeSync(d); } } catch { /* not supported here */ }
}

/** Directories already looked at by this process. */
const checkedDirs = new Set<string>();
/**
 * Make the bridge's own directory owner-only: once per process, and never through a link. If
 * ~/.decoy is a symbolic link its target is left as it is (its owner must keep it private).
 */
function tightenDirOnce(dir: string): void {
  if (checkedDirs.has(dir)) return;
  try {
    if (!fs.lstatSync(dir).isSymbolicLink()) fs.chmodSync(dir, 0o700);
    checkedDirs.add(dir);
  } catch { /* not there yet, or not ours to change: looked at again next time */ }
}

export function writeSecretFile(file: string, data: string, beforeRename?: (tmp: string) => void): void {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  tightenDirOnce(dir);
  replaceAtomically(file, data, beforeRename);
}

/**
 * A file in ~/.decoy: its contents (null if it doesn't exist), after making the file owner-only
 * (and, once per process, its directory). Opened and checked like a file in a caller-chosen directory (readThroughDescriptor):
 * a link at the path is refused, never followed, and nothing is re-permissioned by path.
 */
export function readSecretFile(file: string): string | null {
  tightenDirOnce(path.dirname(file));
  return readThroughDescriptor(file, {});
}

/** Why a file at a caller-chosen path was not read or written. The message names no contents. */
export class SecretFileError extends Error {}

export interface ReadInOptions {
  /** The uid the file and its directory must belong to (default: this process's). */
  expectUid?: number;
  /** The platform (default: process.platform). On Windows there are no uids or mode bits to check. */
  platform?: NodeJS.Platform;
  /** How the open file is made owner-only, given its DESCRIPTOR (default: fchmod 0600). */
  tighten?: (fd: number) => void;
  /** The directory's owner and mode (default: stat). Tests stand in a mounted volume with it. */
  dirStat?: (dir: string) => { uid: number; mode: number } | null;
}

/** The DIRECTORY a credentials file is in can't be used (the file itself was not judged). */
export class SecretDirError extends SecretFileError {}

/**
 * The directory a credentials file is in (POSIX only). Accepted: one owned by this user or by
 * root, unless anyone at all can write to it and it has no sticky bit. That covers the usual
 * mounted volumes: a root-owned mount, and a group-writable one (Kubernetes fsGroup, mode 2775).
 * In a group-writable directory another member of the group could put a file at the path, so the
 * FILE must still be this user's own and owner-only — which every read checks on the open
 * descriptor — and what a planted file could say is limited by its binding to the key and tokens.
 * Refused: a directory owned by another ordinary user, and a world-writable one without the
 * sticky bit (anyone could replace the file).
 */
function checkSecretDir(dir: string, opts: ReadInOptions): void {
  if ((opts.platform ?? process.platform) === 'win32') return;
  let st: { uid: number; mode: number } | null;
  if (opts.dirStat) st = opts.dirStat(dir);
  else { try { st = fs.statSync(dir); } catch { st = null; } }
  if (!st) return;   // no directory yet: nothing to check
  const uid = opts.expectUid ?? process.getuid?.();
  if (uid !== undefined && st.uid !== uid && st.uid !== 0) throw new SecretDirError(`the directory is owned by another user (${dir})`);
  if ((st.mode & 0o002) !== 0 && (st.mode & 0o1000) === 0) throw new SecretDirError(`the directory is writable by anyone and has no sticky bit (${dir})`);
}

/**
 * The same atomic, owner-only write for a file in a directory the CALLER chose (a mounted secret
 * volume, a state directory): the file is 0600 and replaced by rename, but the directory is
 * left as it is — only created (0700) when it doesn't exist. It may hold other things; see
 * checkSecretDir for which directories are refused.
 */
export function writeSecretFileIn(file: string, data: string, opts: ReadInOptions = {}): void {
  const dir = path.dirname(file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  else checkSecretDir(dir, opts);
  replaceAtomically(file, data);
}

/**
 * Read a file in a caller-chosen directory (null if nothing is there).
 *
 * Nothing is done to the PATH but open it, without following a link at it and without blocking;
 * every check and the tightening then go through the open descriptor, so a file swapped in after
 * a check is never the one that gets examined, re-permissioned or read. Refused: a symbolic link,
 * anything that is not a regular file, a file another user owns, a file still readable by group
 * or others after being made owner-only, and a directory checkSecretDir refuses. On Windows the
 * owner, mode and directory checks do not apply and are skipped.
 */
export function readSecretFileIn(file: string, opts: ReadInOptions = {}): string | null {
  checkSecretDir(path.dirname(file), opts);
  return readThroughDescriptor(file, opts);
}
function readThroughDescriptor(file: string, opts: ReadInOptions): string | null {
  const posix = (opts.platform ?? process.platform) !== 'win32';
  // Where O_NOFOLLOW doesn't exist (Windows) this is the only link check there is.
  try { if (fs.lstatSync(file).isSymbolicLink()) throw new SecretFileError('it is a symbolic link'); }
  catch (e) { if (e instanceof SecretFileError) throw e; if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null; }
  let fd: number;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return null;
    if (code === 'ELOOP' || code === 'EMLINK') throw new SecretFileError('it is a symbolic link');
    throw new SecretFileError('it could not be opened');
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new SecretFileError('it is not a regular file');
    if (posix) {
      const uid = opts.expectUid ?? process.getuid?.();
      if (uid !== undefined && st.uid !== uid) throw new SecretFileError('it is owned by another user');
      try { (opts.tighten ?? ((d) => fs.fchmodSync(d, 0o600)))(fd); } catch { /* judged by what the mode is now */ }
      if ((fs.fstatSync(fd).mode & 0o077) !== 0) throw new SecretFileError('it is readable or writable by other users and could not be made owner-only');
    }
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}

/** A temp file younger than this may be another bridge's write in progress. */
export const LEFTOVER_TEMP_AGE_MS = 60_000;

/** Remove temp files an interrupted write of `file` left behind (they may hold tokens): regular
 *  files only, never through a link, and only when old enough that no write can still be using them. */
export function removeLeftoverTemps(file: string, olderThanMs = LEFTOVER_TEMP_AGE_MS): string[] {
  const dir = path.dirname(file);
  const removed: string[] = [];
  let names: string[];
  try { names = fs.readdirSync(dir); } catch { return removed; }
  const prefix = `.${path.basename(file)}.`;
  for (const name of names) {
    if (!name.startsWith(prefix) || !/^[0-9a-f]{12}\.tmp$/.test(name.slice(prefix.length))) continue;
    const full = path.join(dir, name);
    try {
      const st = fs.lstatSync(full);
      if (!st.isFile() || Date.now() - st.mtimeMs < olderThanMs) continue;
      fs.rmSync(full, { force: true });
      removed.push(full);
    } catch { /* gone, or not ours */ }
  }
  return removed;
}

/** A lock older than this was left by a process that died. A renewal must finish well inside it. */
export const LOCK_STALE_MS = 60_000;

/** The lock path can't be used as a lock. The message says what to remove. */
export class LockError extends Error {}

/**
 * A lock file beside `file`, held while a token is renewed or a pairing is committed, so two
 * bridges sharing one connection don't both spend the same refresh token or write over each other.
 *
 * The lock holds its taker's id. It is taken by exclusive create and then read back; it is
 * released only if it still holds that id (a lock taken over as stale is the new holder's). A
 * lock older than `staleMs` is claimed by renaming it away, which only one waiter can do. The
 * deadline is checked on every pass, so no state of the path can make this wait forever; a lock
 * path that is not a regular file is an error. { held: false } means the lock was not free in
 * time — the caller then re-reads the file instead of writing.
 */
type LockOptions = { waitMs?: number; staleMs?: number; pollMs?: number };
/** How long a caller waits for a lock another holder keeps, unless it says otherwise. */
export const LOCK_WAIT_MS = 15_000;

/** One attempt. 'taken' = this caller now holds it; 'busy' = wait and try again; 'never' = it can't be locked here. */
function tryTakeLock(lock: string, me: string, staleMs: number): 'taken' | 'busy' | 'never' {
  let st: fs.Stats | null = null;
  try { st = fs.lstatSync(lock); } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') return 'never';
  }
  if (st) {
    if (!st.isFile()) throw new LockError(`The lock path is not a regular file, so nothing can be written safely. Remove it: ${lock}`);
    if (Date.now() - st.mtimeMs <= staleMs) return 'busy';
    // Stale. Claim it by renaming it away: of several waiters, only one rename succeeds.
    const claim = `${lock}.${randomBytes(6).toString('hex')}.stale`;
    try {
      fs.renameSync(lock, claim);
      const claimed = fs.lstatSync(claim);
      if (claimed.ino !== st.ino || Date.now() - claimed.mtimeMs <= staleMs) {
        // Not the stale one seen a moment ago: a live holder's lock. Put it back and wait.
        try { fs.linkSync(claim, lock); } catch { /* another lock is already in place */ }
        fs.rmSync(claim, { force: true });
        return 'busy';
      }
      fs.rmSync(claim, { force: true });
    } catch { /* another waiter claimed it first */ }
  }
  try {
    const fd = fs.openSync(lock, 'wx', 0o600);
    try { fs.writeFileSync(fd, me); } finally { fs.closeSync(fd); }
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' && !fs.existsSync(path.dirname(lock))) {
      try { fs.mkdirSync(path.dirname(lock), { recursive: true, mode: 0o700 }); return 'busy'; } catch { return 'never'; }
    }
    return code === 'EEXIST' ? 'busy' : 'never';   // 'never': it can't be locked here at all, so don't write blind
  }
  // Taken. Read it back: it must be ours.
  try { return fs.readFileSync(lock, 'utf8') === me ? 'taken' : 'busy'; } catch { return 'busy'; }
}
function releaseLock(lock: string, me: string): void {
  try { if (fs.readFileSync(lock, 'utf8') === me) fs.rmSync(lock, { force: true }); } catch { /* already released or taken over */ }
}
const lockId = () => `${process.pid}:${randomBytes(8).toString('hex')}`;

/** Not held: 'held' = another holder kept it for the whole wait; 'unusable' = the lock file could not be created here. */
export type NotHeld = { held: false; why: 'held' | 'unusable' };
export async function withFileLock<T>(file: string, fn: () => Promise<T>, opts: LockOptions = {}): Promise<{ held: true; value: T } | NotHeld> {
  const lock = `${file}.lock`, me = lockId();
  const deadline = Date.now() + (opts.waitMs ?? LOCK_WAIT_MS);
  for (let first = true; ; first = false) {
    if (!first && Date.now() >= deadline) return { held: false, why: 'held' };
    const got = tryTakeLock(lock, me, opts.staleMs ?? LOCK_STALE_MS);
    if (got === 'taken') break;
    if (got === 'never') return { held: false, why: 'unusable' };
    await new Promise<void>((r) => setTimeout(r, opts.pollMs ?? 100));
  }
  try { return { held: true, value: await fn() }; } finally { releaseLock(lock, me); }
}

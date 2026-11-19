// Only programs of the account that started the bridge may drive it over HTTP.
//
// The bridge holds the owner's connection and decrypts on this computer, so whatever reaches its
// port acts as the owner. Binding loopback keeps other computers out (local-guard.ts), and the
// Host/Origin check keeps web pages out, but loopback is shared by every account on the computer:
// a CI runner's user, or another person signed in, could otherwise drive the bridge.
//
// So for each new connection the bridge looks up who holds its other end, and serves it only when
// that is a program of its own account. MCP clients need no new setting: the check is on the
// connection, not on anything the client sends.
//
//   macOS   lsof, limited to this account's own processes and the bridge's port. A process of
//           another account is not listed, so it is never mistaken for one of ours.
//   Linux   /proc/net/tcp and /proc/net/tcp6, which carry the uid that owns each socket.
//   others  no way to tell (Windows; WSL, where programs on Windows arrive through a relay):
//           allowed, and the bridge says so when it starts.
//
// One lookup answers every connection waiting for it, and only one runs at a time: a burst of
// connections is answered by a few lookups, never turned away for being many, and never becomes a
// burst of the owner's processes. A lookup that cannot run (lsof missing or failing, /proc
// unreadable, a timeout) refuses the connections it was for.
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { endianness, release as osRelease } from 'node:os';
import { isIPv4, isIPv6, type Socket } from 'node:net';
import type { RequestHandler } from 'express';

/** The two ends of a connection as the bridge's socket sees them. */
export interface ConnectionEnds { remoteAddress: string; remotePort: number; localAddress: string; localPort: number }

/**
 * owner      a program of the account the bridge runs as holds the other end
 * other      it is held by another account's program, or by nothing any more
 * failed     the lookup could not run (refused like `other`, logged apart)
 * unchecked  this system has no way to tell (allowed)
 */
export type Holder = 'owner' | 'other' | 'failed' | 'unchecked';

export interface LookupOptions {
  /** The owner's uid. Default: the account this process runs as. */
  uid?: number;
  platform?: NodeJS.Platform;
  /** The kernel release (os.release()): WSL is told apart by it. */
  release?: string;
  /** macOS: where lsof is (launchd jobs often have no /usr/sbin on PATH). */
  lsof?: string;
  /** Linux: the socket tables to read. */
  procNet?: string[];
  timeoutMs?: number;
}

export const LSOF = '/usr/sbin/lsof';
export const PROC_NET_TCP = ['/proc/net/tcp', '/proc/net/tcp6'];
const LOOKUP_TIMEOUT_MS = 5_000;

/** True where the bridge can tell which account a connection comes from. */
export function canCheckConnectionAccount(platform: NodeJS.Platform, release: string = osRelease()): boolean {
  if (platform === 'darwin') return true;
  return platform === 'linux' && !/microsoft|wsl/i.test(release);
}

/** What a 403 says. Shipped text. */
export const OTHER_ACCOUNT_MESSAGE = 'The Decoy MCP bridge answers only programs running as the account that started it.';
export const UNCHECKED_ACCOUNT_MESSAGE = 'The Decoy MCP bridge could not check which account on this computer this connection comes from, so it refused it.';

// ── Addresses ─────────────────────────────────────────────────────────────────

/** An address as 16 bytes (IPv4 as ::ffff:a.b.c.d), or null. */
export function addressBytes(address: string): Buffer | null {
  const a = address.replace(/%.*$/, '');
  if (isIPv4(a)) return Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...a.split('.').map(Number)]);
  if (!isIPv6(a)) return null;
  let text = a;
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (tail) {
    const [p, q, r, s] = tail[1].split('.').map(Number);
    text = text.slice(0, -tail[1].length) + `${((p << 8) | q).toString(16)}:${((r << 8) | s).toString(16)}`;
  }
  const [head, rest] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = rest !== undefined && rest ? rest.split(':') : [];
  const groups = rest === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  if (groups.length !== 8) return null;
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

interface Endpoint { bytes: Buffer; port: number }
const endKey = (e: Endpoint) => `${e.bytes.toString('hex')}:${e.port}`;

/** Who holds each client end: `client>bridge` → the uids of the processes (or sockets) holding it. */
export type HolderTable = Map<string, number[]>;

/** The table key of a connection's client end. */
export function connectionKey(ends: ConnectionEnds): string | null {
  const client = addressBytes(ends.remoteAddress), bridge = addressBytes(ends.localAddress);
  if (!client || !bridge) return null;
  return `${endKey({ bytes: client, port: ends.remotePort })}>${endKey({ bytes: bridge, port: ends.localPort })}`;
}

function add(table: HolderTable, key: string, uid: number) {
  const uids = table.get(key);
  if (uids) uids.push(uid); else table.set(key, [uid]);
}

// ── lsof (macOS) ──────────────────────────────────────────────────────────────

function lsofEndpoint(text: string): Endpoint | null {
  const i = text.lastIndexOf(':');
  if (i < 0) return null;
  const bytes = addressBytes(text.slice(0, i).replace(/^\[|\]$/g, ''));
  const port = Number(text.slice(i + 1));
  return bytes && Number.isInteger(port) ? { bytes, port } : null;
}

/**
 * Every connection end in `lsof -F pun` output, by the processes holding it. A name is
 * `<this end>-><other end>`; the bridge's own ends (`<bridge>-><client>`) are keyed the other way
 * round, so they are never taken for the client's.
 */
export function lsofTable(output: string): HolderTable {
  const table: HolderTable = new Map();
  let uid: number | null = null;
  let counted = new Set<string>();
  for (const line of output.split('\n')) {
    const tag = line[0], value = line.slice(1).split(' ')[0];
    if (tag === 'p') { uid = null; counted = new Set(); }
    else if (tag === 'u') uid = Number.isInteger(Number(value)) && value !== '' ? Number(value) : null;
    else if (tag === 'n' && uid !== null && value.includes('->')) {
      const [here, there] = value.split('->');
      const a = lsofEndpoint(here), b = lsofEndpoint(there);
      if (!a || !b) continue;
      const key = `${endKey(a)}>${endKey(b)}`;
      if (!counted.has(key)) { add(table, key, uid); counted.add(key); }
    }
  }
  return table;
}

/** The uids of the processes holding the client end of this connection, from `lsof -F pun` output. */
export function lsofHolderUids(output: string, ends: ConnectionEnds): number[] {
  const key = connectionKey(ends);
  return key ? lsofTable(output).get(key) ?? [] : [];
}

/**
 * One lsof run. Its deadline is a timer of its own: at the deadline the lookup is `failed` and lsof
 * is killed (SIGKILL), without waiting for it to exit, so a stuck lsof never holds the connections
 * after it. `-b` keeps lsof off the calls that can block (stat, lstat, readlink).
 */
function lsofSnapshot(port: number, uid: number, opts: LookupOptions): Promise<HolderTable | 'failed'> {
  const args = ['-nP', '-w', '-b', '-a', `-u${uid}`, `-iTCP:${port}`, '-F', 'pun'];
  const ms = opts.timeoutMs ?? LOOKUP_TIMEOUT_MS;
  return new Promise((resolve) => {
    let settled = false;
    const done = (answer: HolderTable | 'failed') => { if (settled) return; settled = true; clearTimeout(timer); resolve(answer); };
    const child = execFile(opts.lsof ?? LSOF, args, { timeout: ms, killSignal: 'SIGKILL', windowsHide: true, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (!err) { done(lsofTable(String(stdout))); return; }
      // lsof exits 1 with nothing on standard error when nothing matched. Exit 1 with an error
      // message is a lookup that failed, not an answer.
      const nothingFound = (err as { code?: unknown }).code === 1 && !err.killed && !String(stderr).trim();
      done(nothingFound ? lsofTable(String(stdout)) : 'failed');
    });
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } done('failed'); }, ms);
  });
}

/** `failed` when the answer has not come by the deadline. */
function byDeadline<T>(answer: Promise<T>, ms: number): Promise<T | 'failed'> {
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<'failed'>((resolve) => { timer = setTimeout(() => resolve('failed'), ms); });
  return Promise.race([answer, late]).finally(() => clearTimeout(timer));
}

// ── /proc/net/tcp (Linux) ─────────────────────────────────────────────────────

/** A /proc/net/tcp{,6} address (`HEX:PORT`). Each 32-bit word is in host order. */
function procAddress(field: string, littleEndian: boolean): Endpoint | null {
  const [hex, portHex] = field.split(':');
  if (!hex || !portHex || (hex.length !== 8 && hex.length !== 32)) return null;
  const words: number[] = [];
  for (let i = 0; i < hex.length; i += 8) {
    const word = [...Buffer.from(hex.slice(i, i + 8), 'hex')];
    words.push(...(littleEndian ? word.reverse() : word));
  }
  const bytes = hex.length === 8 ? Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...words]) : Buffer.from(words);
  return { bytes, port: parseInt(portHex, 16) };
}

/**
 * Every connection end in the text of /proc/net/tcp and tcp6, by the uid owning its socket. A row
 * with inode 0 has no socket behind it (a closed end in TIME_WAIT, listed as uid 0): it is no one's.
 */
export function procNetTcpTable(text: string, littleEndian = endianness() === 'LE'): HolderTable {
  const table: HolderTable = new Map();
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10 || !/^\d+:$/.test(f[0]) || f[9] === '0') continue;
    const local = procAddress(f[1], littleEndian), remote = procAddress(f[2], littleEndian);
    const uid = Number(f[7]);
    if (!local || !remote || !Number.isInteger(uid)) continue;
    add(table, `${endKey(local)}>${endKey(remote)}`, uid);
  }
  return table;
}

/** The uids owning the client end of this connection, from the text of /proc/net/tcp and tcp6. */
export function procNetTcpHolderUids(text: string, ends: ConnectionEnds, littleEndian = endianness() === 'LE'): number[] {
  const key = connectionKey(ends);
  return key ? procNetTcpTable(text, littleEndian).get(key) ?? [] : [];
}

async function procSnapshot(opts: LookupOptions): Promise<HolderTable | 'failed'> {
  const tables = await Promise.all((opts.procNet ?? PROC_NET_TCP).map((file) => readFile(file, 'utf8').catch(() => null)));
  if (tables.every((t) => t === null)) return 'failed';
  return procNetTcpTable(tables.filter((t): t is string => t !== null).join('\n'));
}

// ── The verdict ───────────────────────────────────────────────────────────────

/** The owner's only when something holds the client end and every holder is the owner's account. */
function verdict(table: HolderTable | 'failed' | undefined, ends: ConnectionEnds, uid: number): Holder {
  if (!table || table === 'failed') return 'failed';
  const key = connectionKey(ends);
  const uids = key ? table.get(key) ?? [] : [];
  return uids.length > 0 && uids.every((u) => u === uid) ? 'owner' : 'other';
}

const validEnds = (e: ConnectionEnds) => !!(e.remoteAddress && e.remotePort && e.localAddress && e.localPort);

/**
 * A lookup shared by every connection waiting for it. A connection that asks while a lookup runs
 * waits for the next one (the running one may have started before it was accepted).
 */
export function sharedLookup(opts: LookupOptions & { count?: () => void } = {}): (ends: ConnectionEnds) => Promise<Holder> {
  const platform = opts.platform ?? process.platform;
  const checkable = canCheckConnectionAccount(platform, opts.release ?? osRelease());
  let waiting: Array<{ ends: ConnectionEnds; resolve: (h: Holder) => void }> = [];
  let busy = false;
  const run = async () => {
    busy = true;
    try {
      while (waiting.length) {
        const batch = waiting;
        waiting = [];
        opts.count?.();
        const uid = opts.uid ?? process.getuid?.();
        if (uid === undefined) { for (const w of batch) w.resolve('failed'); continue; }
        const snapshot = (port: number) => (platform === 'darwin'
          ? lsofSnapshot(port, uid, opts)
          : byDeadline(procSnapshot(opts), opts.timeoutMs ?? LOOKUP_TIMEOUT_MS)).catch((): 'failed' => 'failed');
        const ports = [...new Set(batch.map((w) => w.ends.localPort))];
        const tables = new Map(await Promise.all(ports.map(async (p) => [p, await snapshot(p)] as const)));
        for (const w of batch) w.resolve(verdict(tables.get(w.ends.localPort), w.ends, uid));
      }
    } finally { busy = false; }
  };
  return (ends) => {
    if (!checkable) return Promise.resolve('unchecked');
    if (!validEnds(ends)) return Promise.resolve('failed');
    return new Promise<Holder>((resolve) => {
      waiting.push({ ends, resolve });
      if (!busy) void run();
    });
  };
}

/** Who holds the other end of this connection (one lookup of its own). */
export function connectionHolder(ends: ConnectionEnds, opts: LookupOptions = {}): Promise<Holder> {
  return sharedLookup(opts)(ends);
}

const endsOf = (s: Socket): ConnectionEnds => ({
  remoteAddress: s.remoteAddress ?? '', remotePort: s.remotePort ?? 0, localAddress: s.localAddress ?? '', localPort: s.localPort ?? 0,
});

export interface OwnerOnlyOptions extends LookupOptions {
  /** Told about each refused request: `other` or `failed`. */
  onRefused?: (why: 'other' | 'failed') => void;
  /** Told about each lookup run (tests count them). */
  count?: () => void;
}

/**
 * Express middleware: a request is handled only when its connection comes from a program of the
 * owner's account. Each connection is looked up once; a kept-alive connection's later requests
 * reuse the answer. A refused request gets 403 and its connection is closed.
 */
export function ownerOnly(opts: OwnerOnlyOptions = {}): RequestHandler {
  const lookup = sharedLookup(opts);
  const verdicts = new WeakMap<Socket, Promise<Holder>>();
  return (req, res, next) => {
    const socket = req.socket;
    let answer = verdicts.get(socket);
    if (!answer) {
      // Read the ends now, while the connection is open: a closed socket has none.
      answer = lookup(endsOf(socket)).catch((): Holder => 'failed');
      verdicts.set(socket, answer);
    }
    void answer.then((holder) => {
      if (holder === 'owner' || holder === 'unchecked') { next(); return; }
      opts.onRefused?.(holder);
      res.setHeader('Connection', 'close');
      res.status(403).json({ error: 'forbidden', message: holder === 'failed' ? UNCHECKED_ACCOUNT_MESSAGE : OTHER_ACCOUNT_MESSAGE });
    });
  };
}

/**
 * The log line for refusals: at most one a minute for each kind, so a refused owner's client
 * (`failed`) is never hidden behind another account's (`other`). The next line says how many were
 * left out since the last one.
 */
export function refusalLog(write: (line: string) => void, everyMs = 60_000, now: () => number = Date.now): (why: 'other' | 'failed') => void {
  const last = { other: { at: -Infinity, skipped: 0 }, failed: { at: -Infinity, skipped: 0 } };
  return (why) => {
    const s = last[why], t = now();
    if (t - s.at < everyMs) { s.skipped++; return; }
    const more = s.skipped ? ` (${s.skipped} more since the last line)` : '';
    s.at = t;
    s.skipped = 0;
    write(why === 'failed'
      ? `[Decoy] Refused a connection: could not check which account on this computer it comes from.${more}`
      : `[Decoy] Refused a connection from a program of another account on this computer.${more}`);
  };
}

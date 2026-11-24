// Secret references, command arguments, output masking and AWS signing for `run`.
// No connection material, disk writes or tool-result logging belongs here.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants } from 'node:os';
import { StringDecoder } from 'node:string_decoder';
import { Transform } from 'node:stream';
import { UsageError } from './call-mode.js';
import { makeScrubber, secretForms } from './scrub.js';

export const RUN_USAGE = 'Usage: decoy-mcp-server run [--env NAME=<ref>]... [--env-file <file>] [--aws <host|account-id>] -- <command> [args...]';
export const HIDDEN = '[hidden by Decoy]';
export const RUN_SCRUB_OPTIONS = { minLength: 4, hex: true, replacement: HIDDEN, jwtPieces: false };
export interface SecretRef { host?: string; id?: string; field: 'password' | 'username' | 'totp' | 'note'; label?: string }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function parseSecretRef(ref: string): SecretRef {
  const match = /^decoy:\/\/(.+)$/i.exec(ref);
  if (!match) throw new UsageError('Invalid secret reference. Use decoy://<host>/<field> or decoy://id/<uuid>/field/<label>.');
  const parts = match[1].split('/');
  if (parts[0].toLowerCase() === 'account') parts.shift();
  let target: { host: string } | { id: string };
  if (parts[0]?.toLowerCase() === 'id') {
    parts.shift(); const id = parts.shift();
    if (!id || !UUID.test(id)) throw new UsageError('The secret reference needs an account UUID.');
    target = { id };
  } else {
    const host = parts.shift();
    if (!host || !/^[\p{L}\p{N}._:-]+$/u.test(host)) throw new UsageError('The secret reference needs a host.');
    target = { host };
  }
  if (parts[0] === 'field' && parts.length === 2) {
    let label: string;
    try { label = decodeURIComponent(parts[1]); } catch { throw new UsageError('The field label has an invalid percent escape.'); }
    if (!label.trim() || label.length > 200) throw new UsageError('The field label must be 1 to 200 characters.');
    return { ...target, field: 'password', label };
  }
  const field = (parts[0] ?? 'password').toLowerCase();
  if (parts.length > 1 || !['password', 'username', 'totp', 'note'].includes(field)) throw new UsageError('A secret reference names password, username, totp, note, or field/<label>.');
  return { ...target, field: field as SecretRef['field'] };
}

export interface RunArgs { env: Record<string, string>; aws?: string; command: string; args: string[] }
export function parseRunArgs(argv: string[]): RunArgs {
  const at = argv.indexOf('--');
  if (at < 0 || !argv[at + 1]) throw new UsageError(RUN_USAGE);
  const command = argv[at + 1];
  if (['env', 'printenv', 'set', 'export', 'declare'].includes(path.basename(command).toLowerCase())) throw new UsageError('Environment dumpers cannot be run with Decoy.');
  const env: Record<string, string> = Object.create(null), files: string[] = [];
  let aws: string | undefined;
  const assignment = (line: string, referenceOnly: boolean) => {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(line);
    if (!m || (referenceOnly && !/^decoy:\/\//i.test(m[2]))) throw new UsageError('Use NAME=decoy://<host>/<field> with --env, or NAME=value in an env file.');
    if (/^decoy:\/\//i.test(m[2])) parseSecretRef(m[2]);
    env[m[1]] = m[2];
  };
  for (let i = 0; i < at; i++) {
    const option = argv[i], value = argv[++i];
    if (i >= at || !value) throw new UsageError(RUN_USAGE);
    if (option === '--env') assignment(value, true);
    else if (option === '--env-file') files.push(value);
    else if (option === '--aws' && !aws) aws = value;
    else throw new UsageError(RUN_USAGE);
  }
  // Explicit --env wins over a file. Literal file values are never echoed in an error.
  const explicit = { ...env };
  for (const file of files) {
    let text: string;
    try { text = fs.readFileSync(file, 'utf8'); } catch { throw new UsageError('The env file could not be read.'); }
    for (const line of text.split(/\r?\n/)) {
      const content = line.split('#', 1)[0];
      if (content.trim()) assignment(content, false);
    }
  }
  Object.assign(env, explicit);
  if (!aws && !Object.values(env).some(v => /^decoy:\/\//i.test(v))) throw new UsageError(RUN_USAGE);
  return { env, aws, command, args: argv.slice(at + 2) };
}

/** UTF-8 decoding and overlap retention are separate from the scrubber's matching rules. */
export function streamingMasker(values: string[]): Transform {
  const secrets = values.filter(s => s.length >= 4);
  const scrub = makeScrubber(() => secrets, RUN_SCRUB_OPTIONS);
  // Long values match at every 16-character piece. Retain 15 characters for those;
  // only shorter values need a whole encoded form held back. A private key must not
  // buffer kilobytes of unrelated progress until the command exits.
  const hold = Math.max(16, ...secrets.filter(s => s.length < 16).flatMap(s => secretForms(s, 4, true).map(f => f.length))) - 1;
  const decoder = new StringDecoder('utf8');
  let pending = '';
  return new Transform({
    transform(chunk, _encoding, done) {
      pending += decoder.write(chunk);
      let cut = Math.max(0, pending.length - hold);
      // A match crossing the safe boundary stays whole until the next write.
      scrub(pending, (start, end) => { if (start < cut && end > cut) cut = start; });
      if (cut > 0 && /[\uD800-\uDBFF]/.test(pending[cut - 1])) cut--;
      if (cut) this.push(scrub(pending.slice(0, cut)));
      pending = pending.slice(cut); done();
    },
    flush(done) { this.push(scrub(pending + decoder.end())); pending = ''; done(); },
  });
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
const hmac = (key: string | Buffer, text: string) => createHmac('sha256', key).update(text).digest();
const awsEncode = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
export function signAwsRequest(o: { method: string; url: URL; body: string; accessKeyId: string; secretAccessKey: string; region: string; service: string; date: Date; headers?: Record<string, string> }): Record<string, string> {
  const date = o.date.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const headers: Record<string, string> = {};
  for (const [k,v] of Object.entries(o.headers ?? {})) headers[k.toLowerCase()] = v.trim().replace(/\s+/g, ' ');
  headers.host = o.url.host; headers['x-amz-date'] = date;
  const names = Object.keys(headers).sort(), signed = names.join(';');
  const query = [...o.url.searchParams].map(([k,v])=>[awsEncode(k),awsEncode(v)]).sort(([ak,av],[bk,bv])=>ak < bk ? -1 : ak > bk ? 1 : av < bv ? -1 : av > bv ? 1 : 0).map(p=>p.join('=')).join('&');
  const uri = o.url.pathname.split('/').map(s=>awsEncode(decodeURIComponent(s))).join('/');
  const canonical = [o.method, uri, query, names.map(k=>`${k}:${headers[k]}\n`).join(''), signed, sha256(o.body)].join('\n');
  const scope = `${date.slice(0,8)}/${o.region}/${o.service}/aws4_request`;
  const key = hmac(hmac(hmac(hmac('AWS4'+o.secretAccessKey,date.slice(0,8)),o.region),o.service),'aws4_request');
  const signature = createHmac('sha256', key).update(`AWS4-HMAC-SHA256\n${date}\n${scope}\n${sha256(canonical)}`).digest('hex');
  return { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${o.accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${signature}` };
}

export function stsEndpoint(override?: string): URL {
  if (!override) return new URL('https://sts.amazonaws.com/');
  let url: URL;
  try { url = new URL(override); } catch { throw new Error('DECOY_TEST_STS_URL must use a loopback host.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !(url.hostname === 'localhost' || url.hostname === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(url.hostname)) || url.username || url.password) throw new Error('DECOY_TEST_STS_URL must use a loopback host.');
  return url;
}
function xmlValue(xml: string, tag: string): string | undefined {
  const text = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(xml)?.[1]?.trim();
  return text?.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (all, e: string) => {
    if (e.startsWith('#')) { const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2),16) : Number(e.slice(1)); return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : all; }
    return ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" } as Record<string,string>)[e] ?? all;
  });
}
export async function temporaryAwsCredentials(accessKeyId: string, secretAccessKey: string, remember: (s: string) => void): Promise<Record<string,string>> {
  const url = stsEndpoint(process.env.DECOY_TEST_STS_URL);
  const body = 'Action=GetSessionToken&Version=2011-06-15&DurationSeconds=3600';
  const headers = signAwsRequest({ method: 'POST', url, body, accessKeyId, secretAccessKey, region: 'us-east-1', service: 'sts', date: new Date(), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  const res = await fetch(url, { method: 'POST', body, headers, redirect: 'error', signal: AbortSignal.timeout(30_000) });
  const xml = await res.text();
  const id = xmlValue(xml, 'AccessKeyId'), secret = xmlValue(xml, 'SecretAccessKey'), token = xmlValue(xml, 'SessionToken');
  for (const v of [id,secret,token]) if (v) remember(v);
  if (!res.ok) throw new Error(`AWS STS ${xmlValue(xml,'Code') ?? `HTTP ${res.status}`}: ${xmlValue(xml,'Message') ?? 'The request failed.'}`);
  if (!id || !secret || !token) throw new Error('AWS STS did not return temporary credentials.');
  return { AWS_ACCESS_KEY_ID: id, AWS_SECRET_ACCESS_KEY: secret, AWS_SESSION_TOKEN: token, AWS_SHARED_CREDENTIALS_FILE: '/dev/null' };
}

// Internal coordination only: this marker contains a PID, never a secret or credential.
const RUN_SUPERVISOR_PID = '_DECOY_RUN_SUPERVISOR_PID';

// Own the command outside its process group, with a private liveness pipe to this bridge.
// An exit callback alone cannot clean up after SIGKILL. This small Node process receives
// no connection secrets, creates the command itself (no spawn/registration race), and kills
// its group on parent disconnect. IPC carries only PIDs, signal names and spawn failure.
const RUN_GUARDIAN = String.raw`
const {spawn}=require('node:child_process');
const {constants}=require('node:os');
const outer=process.argv[1]==='outer';
let child, ending=false;
const kill=(sig)=>{
  if(!child || !child.pid)return;
  try { if(outer && process.platform!=='win32')process.kill(-child.pid,sig); else child.kill(sig); } catch {}
};
const end=(code)=>{
  if(ending)return; ending=true;
  if(outer)kill('SIGKILL');
  process.exit(code);
};
process.on('disconnect',()=>{
  if(!outer && !ending && child && child.pid) { try { process.kill(Number(process.env._DECOY_RUN_SUPERVISOR_PID),'SIGTERM'); } catch {} }
  kill('SIGKILL'); end(1);
});
process.on('message',m=>{if(m && ['SIGINT','SIGTERM','SIGHUP','SIGKILL'].includes(m.signal))kill(m.signal)});
for(const sig of ['SIGINT','SIGTERM','SIGHUP'])process.on(sig,()=>kill(sig));
process.on('uncaughtException',()=>{kill('SIGKILL');end(1)});
process.on('exit',()=>{if(outer)kill('SIGKILL')});
try {
  child=spawn(process.argv[2],process.argv.slice(3),{env:process.env,shell:false,
    detached:outer && process.platform!=='win32',stdio:'inherit'});
  child.once('error',()=>{if(process.connected)process.send({spawnFailed:true},()=>end(1));else end(1)});
  child.once('spawn',()=>{if(process.connected)process.send({pid:child.pid})});
  child.once('exit',(code,signal)=>end(code ?? (signal ? 128+constants.signals[signal] : 1)));
} catch { if(process.connected)process.send({spawnFailed:true},()=>end(1));else end(1); }
`;

/** Only argv and environment variable names cross the spawn call; values stay in its env. */
export async function spawnMasked(asked: RunArgs, env: NodeJS.ProcessEnv, values: string[]): Promise<number> {
  // Node's argument validation can include escaped environment values in its exception.
  // Reject NUL first, and prepare both maskers before anything can inherit the environment.
  if (Object.values(env).some(value => value?.includes('\0'))) {
    console.error('[Decoy] An environment value contains NUL; the command was not started.');
    return 1;
  }
  let stdout: Transform, stderr: Transform;
  try { stdout = streamingMasker(values); stderr = streamingMasker(values); }
  catch { console.error('[Decoy] Output masking could not be prepared; the command was not started.'); return 1; }
  const inherited = Number(process.env[RUN_SUPERVISOR_PID]);
  let supervisor: number | undefined;
  if (process.platform !== 'win32' && Number.isSafeInteger(inherited) && inherited > 1 && inherited !== process.pid) {
    try { process.kill(inherited, 0); supervisor = inherited; } catch { /* stale marker: supervise a new group */ }
  }
  let child: ReturnType<typeof spawn>;
  try {
    // Only the outer run creates a group. Every nested command stays in it, so killing
    // an inner wrapper first can never strand its command outside the outer kill target.
    child = spawn(process.execPath, ['--input-type=commonjs', '-e', RUN_GUARDIAN, supervisor === undefined ? 'outer' : 'inner', asked.command, ...asked.args], {
      env: { ...env, [RUN_SUPERVISOR_PID]: String(supervisor ?? process.pid) },
      // The outer guardian also survives a signal to the bridge's entire group.
      shell: false, detached: supervisor === undefined, stdio: ['inherit', 'pipe', 'pipe', 'ipc'],
    });
  } catch {
    stdout.destroy(); stderr.destroy();
    console.error('[Decoy] The command could not be started.');
    return 1;
  }
  return new Promise<number>((resolve) => {
    let commandPid: number | undefined;
    let failed = false, closed = false, done = false, stopping = false, escalated = false, flushing = false;
    let code: number | null = null, signal: NodeJS.Signals | null = null, ended = 0;
    let killTimer: NodeJS.Timeout | undefined, reapTimer: NodeJS.Timeout | undefined;
    const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'] as const;
    const destinations = [process.stdout, process.stderr];
    const result = () => failed ? 1 : code ?? (signal ? 128 + constants.signals[signal] : 1);
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(killTimer); clearTimeout(reapTimer);
      signalGroup('SIGKILL');
      process.removeListener('exit', exiting);
      signals.forEach((sig, i) => process.removeListener(sig, handlers[i]));
      child.stdout?.unpipe(stdout); child.stderr?.unpipe(stderr);
      stdout.unpipe(process.stdout); stderr.unpipe(process.stderr);
      child.stdout?.destroy(); child.stderr?.destroy(); stdout.destroy(); stderr.destroy();
      for (const destination of destinations) {
        destination.removeListener('error', outputFailed);
        destination.removeListener('close', outputFailed);
      }
      resolve(result());
    };
    const signalGroup = (sig: NodeJS.Signals) => {
      try {
        if (commandPid) process.kill(process.platform === 'win32' || supervisor !== undefined ? commandPid : -commandPid, sig);
        else if (child.connected) child.send({ signal: sig }, () => {});
      } catch { /* already gone; never print a value-bearing process error */ }
    };
    const exiting = () => {
      signalGroup('SIGKILL');
      // Also covers exit before the guardian has reported its command's PID.
      if (child.connected) child.disconnect();
    };
    process.once('exit', exiting);
    child.on('message', message => {
      const info = message as { pid?: unknown; spawnFailed?: unknown };
      if (typeof info.pid === 'number' && Number.isSafeInteger(info.pid) && info.pid > 1) commandPid = info.pid;
      if (info.spawnFailed === true) {
        failed = true; console.error('[Decoy] The command could not be started.'); finish();
      }
    });
    const stop = (sig: NodeJS.Signals) => {
      if (done || stopping) return;
      stopping = true;
      // An inner cancellation also stops the whole supervised tree. Mark stopping first:
      // the outer group signal comes back here, and must not create a forwarding loop.
      if (supervisor !== undefined) {
        try { process.kill(supervisor, sig); } catch { /* supervisor already gone */ }
      }
      signalGroup(sig);
      // Even after the direct child exits, descendants can retain both pipes or ignore sig.
      killTimer = setTimeout(() => {
        escalated = true;
        signalGroup('SIGKILL');
        reapTimer = setTimeout(finish, 1_000); // bound cleanup even if pipes never close
        maybeFinish();
      }, 750);
    };
    const outputFailed = () => {
      if (done) return;
      if (!failed) console.error('[Decoy] Command output closed; the command was stopped.');
      failed = true;
      stop('SIGTERM');
    };
    const handlers = signals.map(sig => {
      const forward = () => stop(sig);
      process.on(sig, forward); return forward;
    });
    const maybeFinish = () => {
      if (done || !closed) return;
      if (stopping) { if (escalated) finish(); return; }
      if (ended !== 2 || flushing) return;
      flushing = true;
      // Normal completion still drains both masks and destinations before finish() can exit.
      Promise.all(destinations.map(destination => new Promise<void>(r => {
        try { destination.write('', error => { if (error) outputFailed(); r(); }); }
        catch { outputFailed(); r(); }
      }))).then(() => { if (!stopping) finish(); });
    };
    for (const destination of destinations) {
      destination.on('error', outputFailed);
      destination.on('close', outputFailed);
    }
    for (const stream of [stdout, stderr]) {
      stream.on('error', outputFailed);
      stream.once('end', () => { ended++; maybeFinish(); });
    }
    child.stdout?.on('error', outputFailed); child.stderr?.on('error', outputFailed);
    child.once('error', () => {
      // No command was created: let the caller handle the failure without cancelling
      // its surrounding shell or notifying the outer run supervisor.
      failed = true; console.error('[Decoy] The command could not be started.'); finish();
    });
    child.once('exit', (exitCode, exitSignal) => { code = exitCode; signal = exitSignal; });
    child.once('close', () => { closed = true; maybeFinish(); });
    try {
      if (destinations.some(destination => destination.destroyed || destination.writableEnded || !destination.writable)) outputFailed();
      else {
        child.stdout!.pipe(stdout).pipe(process.stdout, { end: false });
        child.stderr!.pipe(stderr).pipe(process.stderr, { end: false });
      }
    } catch { outputFailed(); }
  });
}

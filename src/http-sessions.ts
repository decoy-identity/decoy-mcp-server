// Live MCP HTTP sessions. Each session removes itself by ITS OWN id when its transport closes and
// releases what it owns (its MCP server, and with it any memory engine) exactly once. A client that
// re-initializes while presenting a live session id gets that session closed first, so nothing is
// orphaned. `attach` runs BEFORE the MCP server connects, so the SDK chains its own close cleanup
// onto this handler instead of being overwritten by it.

export interface SessionTransport {
  onclose?: () => void;
  close(): Promise<void>;
}

/** What a POST /mcp does: reuse a live session, create one (initialize), replace a live one
 *  (initialize presenting its id), or reject (anything else — no server is built for it). */
export function sessionAction(hasLiveSession: boolean, isInitialize: boolean): 'reuse' | 'create' | 'replace' | 'reject' {
  if (isInitialize) return hasLiveSession ? 'replace' : 'create';
  return hasLiveSession ? 'reuse' : 'reject';
}

/** A DELETE /mcp the SDK refused (4xx/5xx) leaves the session open. */
export function closeAfterDelete(status: number): boolean {
  return status < 400;
}

export class SessionRegistry<T extends SessionTransport> {
  private sessions = new Map<string, T>();
  // Last use per session: an idle one (a client that reconnected without DELETE) is closed by
  // reapIdle, releasing the decrypted secrets, vault key and memory engine it holds.
  private lastSeen = new Map<string, number>();

  constructor(private now: () => number = Date.now) {}

  get(id: string | undefined): T | undefined {
    const t = id ? this.sessions.get(id) : undefined;
    if (t && id) this.lastSeen.set(id, this.now());
    return t;
  }

  /** Close every session unused for longer than idleMs (their close handlers release them). */
  async reapIdle(idleMs: number): Promise<void> {
    const cutoff = this.now() - idleMs;
    const stale = [...this.sessions].filter(([id]) => (this.lastSeen.get(id) ?? 0) < cutoff).map(([, t]) => t);
    await Promise.all(stale.map((t) => t.close().catch(() => {})));
  }

  get size(): number {
    return this.sessions.size;
  }

  /** Install the close handler (call before connecting the MCP server to this transport). */
  attach(transport: T, release: () => Promise<void>): void {
    let done = false;
    transport.onclose = () => {
      if (done) return;
      done = true;
      for (const [id, t] of this.sessions) if (t === transport) { this.sessions.delete(id); this.lastSeen.delete(id); }
      void release().catch((err) => console.error('[Decoy] Releasing a closed session failed:', (err as Error)?.message ?? err));
    };
  }

  /** Record a session once its id is known. */
  register(id: string, transport: T): void {
    this.sessions.set(id, transport);
    this.lastSeen.set(id, this.now());
  }

  /** attach + register, for a transport whose id is already known. */
  track(id: string, transport: T, release: () => Promise<void>): void {
    this.attach(transport, release);
    this.register(id, transport);
  }

  async closeIfOpen(id: string | undefined): Promise<void> {
    const t = this.get(id);
    if (t) await t.close();
  }
}

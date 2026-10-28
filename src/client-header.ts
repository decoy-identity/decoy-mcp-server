// Which client is calling. Every request the bridge sends to Decoy carries one header that names
// this package and its version, and says when the request comes from a `--context` run or from a
// one-shot `call`:
//
//   X-Decoy-Client: decoy-mcp-server/1.2.3
//   X-Decoy-Client: decoy-mcp-server/1.2.3; mode=context
//   X-Decoy-Client: decoy-mcp-server/1.2.3; mode=call
//
// That is all it says. Nothing about the machine, the user, the host application or the session
// is ever put in it, and no other identifying header is added. It goes to the API host this bridge
// is configured for and to no other: a request to another host (revoking a saved token at the
// host that issued it) carries no such header, and a redirect is never followed, so an answer
// from the API host cannot send the request (with this header) on to another one. Nothing the
// bridge calls answers with a redirect; one that arrives is the answer, and fails the call.

export const CLIENT_HEADER = 'X-Decoy-Client';
export const CLIENT_NAME = 'decoy-mcp-server';

export function clientHeaderValue(version: string, mode?: 'context' | 'call'): string {
  return `${CLIENT_NAME}/${version}${mode ? `; mode=${mode}` : ''}`;
}

/** The same request with the client header set (a header of that name already there is replaced). */
export function withClient(init: RequestInit | undefined, value: string): RequestInit {
  const headers = new Headers(init?.headers);
  headers.set(CLIENT_HEADER, value);
  return { ...init, headers };
}

/** The host a request goes to ("api.example:8443"), or null when the address cannot be read. */
function requestHost(url: Parameters<typeof fetch>[0]): string | null {
  try { return new URL(typeof url === 'string' ? url : url instanceof URL ? url.href : url.url).host; } catch { return null; }
}

/** What is sent for one request: the client header when it goes to the configured API host, and
 *  none for any other host; with `timeoutMs`, a time limit on a request that brings none of its own.
 *  A request to the API host never follows a redirect: 'manual' (the redirect is the answer)
 *  unless the request itself refuses one with 'error'. */
export function decoyRequest(url: Parameters<typeof fetch>[0], init: RequestInit | undefined, o: { apiHost: string; client: string; timeoutMs?: number }): RequestInit | undefined {
  const named = requestHost(url) === o.apiHost ? { ...withClient(init, o.client), redirect: init?.redirect === 'error' ? 'error' as const : 'manual' as const } : init;
  return o.timeoutMs !== undefined && !named?.signal ? { ...named, signal: AbortSignal.timeout(o.timeoutMs) } : named;
}

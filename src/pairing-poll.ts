/**
 * The pairing poll. The pairing code is public (the connect URL and QR); the token is collected
 * by presenting the session's secret device_code, which only this process received when it
 * created the session. It goes in a header so it never lands in a URL, log or history, and the
 * poll never follows a redirect, so the header can't travel to another origin.
 */
export function pairingPollRequest(connectUrl: string, code: string, deviceCode: string): [string, RequestInit] {
  return [`${connectUrl}?code=${encodeURIComponent(code)}`, { headers: { 'X-Device-Code': deviceCode }, redirect: 'error' }];
}

export interface PairingSession { code: string; deviceCode: string; expiresAt: Date }

/** The create response, or an error before any polling if it can't be completed. */
export function parseCreateResponse(body: unknown): PairingSession {
  const b = (body ?? {}) as Record<string, unknown>;
  if (typeof b.code !== 'string' || !b.code) throw new Error('The pairing service returned no pairing code.');
  if (typeof b.device_code !== 'string' || !b.device_code) {
    throw new Error('The pairing service returned no device_code, so this bridge could never collect its token. ' +
      'Check DECOY_AGENT_API_URL points at a current Decoy API.');
  }
  return { code: b.code, deviceCode: b.device_code, expiresAt: new Date(String(b.expires_at)) };
}

const FALLBACK_WINDOW_MS = 10 * 60_000;

/** Poll until approved, denied or past the deadline. Every tick checks the deadline first. */
export async function pollForPairing(o: {
  connectUrl: string; code: string; deviceCode: string; expiresAt: Date; intervalMs?: number;
  fetch?: typeof fetch; now?: () => number; sleep?: (ms: number) => Promise<void>;
}): Promise<{ accessToken: string; refreshToken?: string }> {
  const doFetch = o.fetch ?? fetch;
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const interval = o.intervalMs ?? 2000;
  const deadline = Number.isFinite(o.expiresAt.getTime()) ? o.expiresAt.getTime() : now() + FALLBACK_WINDOW_MS;
  const expired = () => new Error('Pairing code expired. Restart the server to try again.');
  for (;;) {
    if (now() > deadline) throw expired();
    try {
      const res = await doFetch(...pairingPollRequest(o.connectUrl, o.code, o.deviceCode));
      if (res.status === 404 || res.status === 410) throw expired();
      if (res.ok) {
        const { status, access_token, refresh_token } = await res.json() as { status?: string; access_token?: string; refresh_token?: string };
        if (status === 'approved' && access_token) return { accessToken: access_token, refreshToken: refresh_token };
        if (status === 'approved') {
          throw new Error('Pairing was approved but the token could not be collected. Check DECOY_AGENT_API_URL and any proxy ' +
            'between this machine and Decoy, then revoke the stray connection in the Decoy app (Connections) and pair again.');
        }
        if (status === 'denied') throw new Error('Pairing was denied in the Decoy app.');
        if (status === 'expired') throw expired();
      }
    } catch (err) {
      if (err instanceof Error && /^Pairing (code expired|was approved|was denied)/.test(err.message)) throw err;
      // transient (network, a non-JSON gateway page): retry until the deadline
    }
    await sleep(interval);
  }
}

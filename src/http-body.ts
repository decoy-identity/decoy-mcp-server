// Request bodies for the local MCP endpoint. Email tools take attachments up to ~4 MB of base64,
// so the limit sits above that; any body error answers JSON, never Express's HTML page (which
// prints a stack trace with local paths when NODE_ENV isn't set).
import express, { type ErrorRequestHandler } from 'express';

export const jsonBody = () => express.json({ limit: '6mb' });

export const jsonErrors: ErrorRequestHandler = (err, _req, res, next) => {
  if (res.headersSent) return next(err);
  const status = typeof err?.status === 'number' && err.status >= 400 && err.status < 600 ? err.status : 500;
  const message = status === 413 ? 'Request too large.' : status === 400 ? 'Malformed JSON request.' : 'Internal error.';
  res.status(status).json({ jsonrpc: '2.0', error: { code: -32700, message }, id: null });
};

/** Express 4 doesn't catch a rejected async handler (the process would crash): send it to jsonErrors. */
export const asyncRoute = (fn: (req: express.Request, res: express.Response) => Promise<unknown>): express.RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next); };

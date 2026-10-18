// Timeout-oracle HTTP request smuggling (desync) detection over a raw socket. Deliberately SAFE:
// every probe either completes a well-formed request or just hangs — it never leaves a partial body
// or stray prefix bytes queued, so it cannot poison the next requester on a pooled connection.
//
// Oracle matrix (control = plain request that must respond):
//   P2 "CL overstates" — `Content-Length: 6` + `Transfer-Encoding: chunked` + only 5 body bytes
//      (`0\r\n\r\n`). A front-CL waits for byte 6 (timeout); front-TE forwards it complete but a
//      back-CL waits for byte 6 (timeout). Both-TE parses the `0` chunk and responds.
//   P3 "CL understates" — `Content-Length: 4` + `Transfer-Encoding: chunked` + only 4 body bytes
//      (`0\r\n\r`, the 5th is NEVER sent). Both-CL: front reads exactly 4, back reads 4 → response.
//      Front-TE hangs itself mid-chunk (timeout); front-CL+back-TE forwards `0\r\n\r` and the back
//      waits for the missing `\n` (timeout).
//   Both probes timeout → disagreement somewhere = SUSPECTED-DESYNC (we cannot tell CL.TE from
//   TE.CL without queue poisoning, which we deliberately do not attempt — stays suspected).
//   Exactly one timeout → both ends agree (consistent CL.CL or TE.TE) → not vulnerable here.
//   A dual-header reject (400) on the P1 consistency probe → hardened/WAF.

import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";

export interface RawProbeRequest {
  /** Absolute http(s) URL — only the origin+path are used; the raw request head is caller-built. */
  url: string;
  /** Complete request head + body bytes to write verbatim after connect. */
  raw: string;
  timeoutMs: number;
  /** When set, keep reading after the response head until this many body bytes arrive, the socket
   *  closes, or a short drain window (600ms) passes — needed when the reflection lives in the body. */
  bodyCapBytes?: number;
}

export interface RawProbeResult {
  /** Parsed HTTP status (0 = no response / transport failure). */
  status: number;
  /** True when the socket produced no complete response head within the window. */
  timedOut: boolean;
  responseHead: string;
  /** Response body bytes received (empty unless bodyCapBytes was set). */
  body: string;
  error?: string;
}

/** Send one raw HTTP/1.1 request and wait for a response head. Never throws. */
export async function rawHttpProbe(req: RawProbeRequest): Promise<RawProbeResult> {
  let u: URL;
  try {
    u = new URL(req.url);
  } catch {
    return { status: 0, timedOut: false, responseHead: "", body: "", error: `bad url: ${req.url}` };
  }
  const secure = u.protocol === "https:";
  const host = u.hostname;
  const port = Number(u.port) || (secure ? 443 : 80);
  return await new Promise<RawProbeResult>((resolve) => {
    const done = (r: RawProbeResult, sock?: { destroy(): void }) => {
      try {
        sock?.destroy();
      } catch {
        /* ignore */
      }
      resolve(r);
    };
    const sock = secure ? tlsConnect({ host, port, servername: host, rejectUnauthorized: true }) : netConnect({ host, port });
    let buf = Buffer.alloc(0);
    let headStatus = 0;
    const finish = (timedOut: boolean, err?: string) => {
      const headEnd = buf.indexOf("\r\n\r\n");
      clearTimeout(timer);
      clearTimeout(drainTimer);
      done(
        {
          status: headStatus,
          timedOut,
          responseHead: headEnd >= 0 ? buf.subarray(0, headEnd + 4).toString("latin1") : buf.toString("latin1").slice(0, 400),
          body: headEnd >= 0 ? buf.subarray(headEnd + 4).toString("latin1") : "",
          ...(err ? { error: err } : {}),
        },
        sock,
      );
    };
    let drainTimer: NodeJS.Timeout | undefined;
    const timer = setTimeout(() => finish(true, "no complete response within window"), req.timeoutMs);
    sock.on("error", (e) => finish(false, String(e).slice(0, 200)));
    sock.on("connect", () => sock.write(req.raw, "latin1"));
    sock.on("close", () => finish(headStatus === 0 && buf.indexOf("\r\n\r\n") < 0));
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const headEnd = buf.indexOf("\r\n\r\n");
      if (headEnd < 0) return;
      const statusLine = buf.subarray(0, buf.indexOf("\r\n")).toString("latin1");
      headStatus = Number(statusLine.match(/HTTP\/1\.1 (\d+)/)?.[1] ?? 0);
      const cap = req.bodyCapBytes ?? 0;
      if (cap <= 0 || buf.length - (headEnd + 4) >= cap) return finish(false);
      // Keep draining briefly for the body — resolve early if the socket idles.
      clearTimeout(drainTimer);
      drainTimer = setTimeout(() => finish(false), 600);
    });
  });
}

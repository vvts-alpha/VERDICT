import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";

export const LOCAL_TOKEN_HEADER = "x-verdict-token";

/** Validate before routing so malformed encodings cannot escape a synchronous or WebSocket callback. */
export function validateRequestPath(req: IncomingMessage): boolean {
  const path = (req.url ?? "/").split("?")[0]!;
  if (!path.startsWith("/") || path.startsWith("//")) return false;
  try {
    for (const part of path.split("/")) {
      const decoded = decodeURIComponent(part);
      if (decoded === "." || decoded === ".." || /[\\/\x00-\x1f\x7f]/.test(decoded)) return false;
    }
    // Assessment/run IDs are filesystem components, not arbitrary paths (also on Windows).
    const id = /^\/api\/(?:assessments|run)\/([^/]+)/.exec(path)?.[1];
    return !id || /^[a-z0-9_-]+$/i.test(decodeURIComponent(id));
  } catch {
    return false;
  }
}

/** Browser requests must originate in the UI. Missing Origin remains valid for CLI clients. */
export function isTrustedRequest(req: IncomingMessage, boundHost: string): boolean {
  try {
    const authority = req.headers.host;
    if (!authority || !/^[a-z0-9.:[\]-]+$/i.test(authority)) return false;
    const base = new URL(`http://${authority}`);
    // Prevent DNS rebinding to the loopback listener. Wildcard binds retain CLI LAN hosting support.
    if (boundHost !== "0.0.0.0" && boundHost !== "::" && base.hostname !== boundHost &&
        !(boundHost === "127.0.0.1" && base.hostname === "localhost")) return false;
    if (Number(base.port || 80) !== req.socket.localPort) return false;
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== base.origin) return false;
    const site = req.headers["sec-fetch-site"];
    // Same-site includes other localhost ports and other tenants: only same-origin is privileged.
    if (site && site !== "same-origin" && site !== "none") return false;
    if (site === "none" && req.method !== "GET" && req.method !== "HEAD") return false;
    return true;
  } catch {
    return false;
  }
}

export function hasLocalToken(req: IncomingMessage, expected?: string): boolean {
  if (expected === undefined) return true;
  const supplied = req.headers[LOCAL_TOKEN_HEADER];
  if (typeof supplied !== "string" || !expected) return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

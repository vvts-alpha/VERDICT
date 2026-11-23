import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { networkInterfaces } from "node:os";

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

/** Canonical host spelling (URL-normalized: lowercased, IPv6 compressed, brackets and zone id dropped). */
const bareHost = (h: string): string => {
  const raw = h.trim().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  try {
    return new URL(`http://${raw.includes(":") ? `[${raw}]` : raw}`).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return raw.toLowerCase();
  }
};

/** Host names that address this listener. Wildcard binds accept localhost and the machine's own interface
 *  addresses, never arbitrary names — a DNS-rebinding page always sends its own name as Host. */
export function isAllowedHostName(hostname: string, boundHost: string, allowedHosts: readonly string[] = []): boolean {
  const host = bareHost(hostname);
  const bound = bareHost(boundHost);
  if (allowedHosts.some((h) => bareHost(h) === host)) return true;
  if (host === bound) return true;
  const loopbackName = host === "localhost";
  if (bound === "0.0.0.0" || bound === "::") {
    if (loopbackName) return true;
    return Object.values(networkInterfaces()).some((list) => (list ?? []).some((i) => bareHost(i.address) === host));
  }
  return loopbackName && (bound === "127.0.0.1" || bound === "::1" || bound === "localhost");
}

/** Browser requests must originate in the UI. Missing Origin remains valid for CLI clients. */
export function isTrustedRequest(req: IncomingMessage, boundHost: string, allowedHosts: readonly string[] = []): boolean {
  try {
    const authority = req.headers.host;
    if (!authority || !/^[a-z0-9.:[\]-]+$/i.test(authority)) return false;
    const base = new URL(`http://${authority}`);
    // Prevent DNS rebinding: the Host name must be one this listener is actually addressed by.
    if (!isAllowedHostName(base.hostname, boundHost, allowedHosts)) return false;
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

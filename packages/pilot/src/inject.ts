// FAM-1 — the injection-location factory. A pure helper that places an attack payload into a chosen LOCATION of a
// request (query param / request header / cookie / path segment / JSON body field), so any probe oracle
// (timing / boolean / marker / OOB) can be aimed at ANY location — not just the query-or-{{TOKEN}}-body the probes
// historically hardcoded. This closes a whole class of coverage holes (header/cookie/path blind-timing SQLi/CMDi,
// JSON-body-field injection through the probe oracles) with one shared, unit-tested surface. See the coverage audit.
//
// placePayload is PURE and does NOT enforce scope — the caller must still isInScope-gate the returned url (this keeps
// the scope-gate invariant explicit at every probe call site, exactly as before).

import type { HttpRequest, MultipartSpec } from "@veritas/scanner";

export type InjectionLocation =
  | { kind: "query"; name: string }
  | { kind: "header"; name: string }
  | { kind: "cookie"; name: string }
  | { kind: "path"; index?: number }
  | { kind: "json"; pointer: string };

/**
 * Parse the model-facing string form of a location:
 *   "query:q" | "header:X-Forwarded-For" | "cookie:sid" | "path" | "path:2" | "path:-1" | "json:/user/id" | "json:user.id"
 * Returns null on a malformed spec (caller should reject).
 */
export function parseLocation(spec: string): InjectionLocation | null {
  const i = spec.indexOf(":");
  const kind = (i < 0 ? spec : spec.slice(0, i)).trim().toLowerCase();
  const arg = i < 0 ? "" : spec.slice(i + 1).trim();
  switch (kind) {
    case "query":
      return arg ? { kind: "query", name: arg } : null;
    case "header":
      return arg ? { kind: "header", name: arg } : null;
    case "cookie":
      return arg ? { kind: "cookie", name: arg } : null;
    case "path": {
      if (!arg) return { kind: "path" };
      if (!/^-?\d+$/.test(arg)) return null; // reject "2abc" / "0x10" / "1e3" — parseInt would silently keep a prefix and mis-aim the probe
      return { kind: "path", index: Number.parseInt(arg, 10) };
    }
    case "json":
      return arg ? { kind: "json", pointer: arg } : null;
    default:
      return null;
  }
}

/** Case-insensitive header set — overwrites any existing header of the same name (keeps the caller's casing). */
function setHeaderCI(headers: Record<string, string>, name: string, value: string): void {
  const lc = name.toLowerCase();
  for (const k of Object.keys(headers)) if (k.toLowerCase() === lc) delete headers[k];
  headers[name] = value;
}
function getHeaderCI(headers: Record<string, string>, name: string): string | undefined {
  const lc = name.toLowerCase();
  for (const k of Object.keys(headers)) if (k.toLowerCase() === lc) return headers[k];
  return undefined;
}

/** Set cookie NAME=value in the Cookie header, preserving the other cookies already present. */
function setCookie(headers: Record<string, string>, name: string, value: string): void {
  const existing = getHeaderCI(headers, "cookie") ?? "";
  const kept = existing
    .split(/;\s*/)
    .filter((p) => p !== "" && p.split("=")[0]?.trim() !== name);
  kept.push(`${name}=${value}`);
  setHeaderCI(headers, "Cookie", kept.join("; "));
}

/**
 * Set a value at a JSON path in `obj`, creating intermediate objects. Accepts an RFC6901-ish pointer ("/a/b", with
 * ~1→/ and ~0→~) or a dotted path ("a.b") or a bare key ("a"). Returns false if the path is empty or a non-object
 * blocks it (so the caller declines rather than silently mis-injecting).
 */
function setJsonField(obj: Record<string, unknown>, pointer: string, value: string): boolean {
  const keys = pointer.startsWith("/")
    ? pointer.slice(1).split("/").map((k) => k.replace(/~1/g, "/").replace(/~0/g, "~"))
    : pointer.split(".");
  if (keys.length === 0 || keys.some((k) => k === "")) return false;
  // Reject prototype-chain keys: a "json:/__proto__/x" path would otherwise walk INTO Object.prototype and pollute it
  // process-wide (the model would naturally emit exactly this against a prototype-pollution target). Keep the factory PURE.
  if (keys.some((k) => k === "__proto__" || k === "prototype" || k === "constructor")) return false;
  let cur: Record<string, unknown> = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const k = keys[i]!;
    if (!Object.hasOwn(cur, k) || cur[k] === null) cur[k] = {}; // own-property only — never follow the prototype chain
    const next = cur[k];
    if (typeof next !== "object" || Array.isArray(next)) return false;
    cur = next as Record<string, unknown>;
  }
  cur[keys[keys.length - 1]!] = value;
  return true;
}

/**
 * Place `payload` into `base` at `loc`, returning a NEW request (base is untouched). Returns null when the location
 * can't be built: an unparseable url, a JSON body that won't parse (or isn't an object), or a path with no segment to
 * hit. The caller MUST still scope-gate the returned url.
 *
 * `contentType` only matters for the `json` location (defaults to application/json there); it is ignored for
 * query/header/cookie/path, which never touch the body.
 */
export function placePayload(base: HttpRequest, loc: InjectionLocation, payload: string, contentType?: string): HttpRequest | null {
  const headers: Record<string, string> = { ...(base.headers ?? {}) };
  switch (loc.kind) {
    case "query": {
      try {
        const u = new URL(base.url);
        u.searchParams.set(loc.name, payload);
        return { ...base, url: u.toString(), headers };
      } catch {
        return null;
      }
    }
    case "header": {
      setHeaderCI(headers, loc.name, payload);
      return { ...base, headers };
    }
    case "cookie": {
      setCookie(headers, loc.name, payload);
      return { ...base, headers };
    }
    case "path": {
      let u: URL;
      try {
        u = new URL(base.url);
      } catch {
        return null;
      }
      const segs = u.pathname.split("/");
      const filled: number[] = [];
      segs.forEach((seg, i) => {
        if (seg !== "") filled.push(i);
      });
      if (filled.length === 0) return null; // no path segment to inject into
      const raw = loc.index;
      const pick = raw == null ? filled.length - 1 : raw < 0 ? filled.length + raw : raw;
      const target = filled[pick];
      if (target == null) return null; // index out of range
      segs[target] = encodeURIComponent(payload);
      u.pathname = segs.join("/");
      return { ...base, url: u.toString(), headers };
    }
    case "json": {
      let obj: Record<string, unknown> = {};
      if (base.body != null && base.body !== "") {
        try {
          const parsed = JSON.parse(base.body);
          if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
          obj = parsed as Record<string, unknown>;
        } catch {
          return null;
        }
      }
      if (!setJsonField(obj, loc.pointer, payload)) return null;
      setHeaderCI(headers, "content-type", contentType ?? "application/json");
      return { ...base, headers, body: JSON.stringify(obj) };
    }
  }
}

/**
 * Build a multipart spec from probe_oob's file specs, substituting the callback host into each file's TEXT `content`
 * via `sub` (e.g. an XXE SVG or an FFmpeg/HLS playlist carrying http://{{OOB}}/). Base64 file bytes are passed through
 * UNCHANGED — a pre-encoded binary blob cannot carry a post-hoc {{OOB}} substitution (a known limitation; craft the
 * host into the text `content` path when you need it substituted).
 */
export function oobFilesToMultipart(
  files: Array<{ name: string; filename: string; contentType?: string; content?: string; base64?: string }>,
  sub: (v: string) => string,
): MultipartSpec {
  return {
    files: files.map((f) => ({
      name: f.name,
      filename: f.filename,
      ...(f.contentType ? { contentType: f.contentType } : {}),
      base64: f.base64 ?? Buffer.from(sub(f.content ?? ""), "utf8").toString("base64"),
    })),
  };
}

/**
 * Does any file part carry a {{OOB}} placeholder that WILL actually be substituted+sent? Only a text-`content` part
 * (no `base64`) is substitutable — a part that also sets `base64` sends the raw bytes and DISCARDS the substituted
 * content, so a marker there would pass the gate but never reach the wire. Gate and sender must agree, so require
 * base64 to be absent (matches oobFilesToMultipart's `base64 ?? sub(content)`).
 */
export function filesHaveOobPlaceholder(files: Array<{ content?: string; base64?: string }> | undefined, marker: string): boolean {
  return (files ?? []).some((f) => f.base64 == null && (f.content ?? "").includes(marker));
}

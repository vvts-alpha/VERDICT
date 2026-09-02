// Decode an ENCODED parameter VALUE to reveal a nested sink — a base64/percent-wrapped return-URL (the SSO_ORIG_URI
// miss: the agent saw the value every line and never decoded it) — so a redirect/SSRF probe can inject into the DECODED
// url and RE-ENCODE the payload in the SAME wrapper. Plaintext-only injection can't reach a sink hidden behind base64.

export interface UrlWrapper {
  inner: string; // the decoded URL
  kind: "base64" | "base64url" | "percent";
  rewrap: (payload: string) => string; // re-encode a new payload the same way the original value was encoded
}

const looksLikeUrl = (s: string): boolean => /^https?:\/\//i.test(s.trim()) || /^\/\/[^/]/.test(s.trim());

function tryPercent(value: string): UrlWrapper | null {
  if (!value.includes("%")) return null;
  try {
    const decoded = decodeURIComponent(value);
    if (decoded === value || !looksLikeUrl(decoded)) return null;
    return { inner: decoded, kind: "percent", rewrap: (p) => encodeURIComponent(p) };
  } catch {
    return null;
  }
}

function tryBase64(value: string): UrlWrapper | null {
  if (!/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(value)) return null;
  const urlSafe = /[-_]/.test(value);
  try {
    const decoded = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    if (!looksLikeUrl(decoded)) return null;
    // Round-trip guard: re-encoding the decoded value must reproduce the original — rejects random strings that merely
    // happen to base64-decode into something URL-ish.
    const std = Buffer.from(decoded, "utf8").toString("base64");
    const safe = std.replace(/\+/g, "-").replace(/\//g, "_");
    const strip = (x: string): string => x.replace(/=+$/, "");
    if (strip(value) !== strip(std) && strip(value) !== strip(safe)) return null;
    return {
      inner: decoded,
      kind: urlSafe ? "base64url" : "base64",
      rewrap: (p) => {
        const b = Buffer.from(p, "utf8").toString("base64");
        return urlSafe ? b.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : b;
      },
    };
  } catch {
    return null;
  }
}

/** Return the decoded inner URL + a same-encoding rewrap fn if `value` wraps a URL (percent- or base64-encoded); else null. */
export function detectUrlWrapper(value: string): UrlWrapper | null {
  if (!value) return null;
  return tryPercent(value) ?? tryBase64(value);
}

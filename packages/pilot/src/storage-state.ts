// Playwright storageState helpers (cookies + origin localStorage). Used by loadCookieFile so a captured
// SPA session (Bearer in localStorage) authenticates the HTTP path without waiting on a live page evaluate.

export interface StorageOrigin {
  origin: string;
  localStorage: Array<{ name: string; value: string }>;
}

const BEARER_KEYS = ["token", "access_token", "accessToken", "authToken", "auth_token", "jwt", "id_token", "idToken", "bearer"];

function looksLikeJwt(raw: string): boolean {
  const tok = raw.replace(/^Bearer\s+/i, "").trim();
  if (tok.length < 20) return false;
  if (tok.startsWith("{") || tok.startsWith("[")) return false;
  const dots = tok.split(".");
  return dots.length >= 2 && dots.length <= 3 && /^[A-Za-z0-9_-]+$/.test(dots[0] ?? "") && (dots[0]?.length ?? 0) > 4 && (dots[1]?.length ?? 0) > 4;
}

function tokenFromValue(raw: string): string | null {
  const trimmed = raw.trim();
  if (looksLikeJwt(trimmed)) return trimmed.replace(/^Bearer\s+/i, "").trim();
  if (!trimmed.startsWith("{")) return null;
  try {
    const o = JSON.parse(trimmed) as Record<string, unknown>;
    for (const k of BEARER_KEYS) {
      const v = o[k];
      if (typeof v === "string" && looksLikeJwt(v)) return v.replace(/^Bearer\s+/i, "").trim();
    }
  } catch {
    /* not json */
  }
  return null;
}

/** Pull a Bearer JWT out of storageState origins (Juice Shop `localStorage.token` and cousins). */
export function bearerFromOrigins(origins: ReadonlyArray<StorageOrigin>): string {
  for (const origin of origins) {
    for (const item of origin.localStorage) {
      if (BEARER_KEYS.includes(item.name)) {
        const tok = tokenFromValue(item.value);
        if (tok) return tok;
      }
    }
    for (const item of origin.localStorage) {
      const tok = tokenFromValue(item.value);
      if (tok) return tok;
    }
  }
  return "";
}

export function normalizeOrigins(raw: unknown): StorageOrigin[] {
  if (!Array.isArray(raw)) return [];
  const out: StorageOrigin[] = [];
  for (const o of raw) {
    if (!o || typeof o !== "object") continue;
    const rec = o as { origin?: unknown; localStorage?: unknown };
    if (typeof rec.origin !== "string" || !rec.origin) continue;
    const ls = Array.isArray(rec.localStorage) ? rec.localStorage : [];
    const localStorage = ls
      .map((item) => {
        if (!item || typeof item !== "object") return null;
        const it = item as { name?: unknown; value?: unknown };
        if (typeof it.name !== "string" || !it.name) return null;
        return { name: it.name, value: String(it.value ?? "") };
      })
      .filter((x): x is { name: string; value: string } => x !== null);
    out.push({ origin: rec.origin, localStorage });
  }
  return out;
}

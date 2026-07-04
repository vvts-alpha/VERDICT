// DESIGN §6.4 — URL normalization (path templating). Scope checks live in core.

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LONGHEX_RE = /^[0-9a-f]{16,}$/i; // mongo ObjectId / long hex
const NUM_RE = /^\d+$/;
const SLUGNUM_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*-\d+$/i; // foo-bar-123
const PREFIXNUM_RE = /^[a-z]{1,3}\d{2,}$/i; // p101, ord12, u99 (short prefix + 2+ digits)

export type SegmentKind = "static" | "id";

/** Whether a path segment is a "value (id)" or "static". Numbers/UUID/long hex/trailing-number slug/prefix+number count as id. */
export function classifyPathSegment(seg: string): SegmentKind {
  if (seg === "") return "static";
  if (NUM_RE.test(seg)) return "id";
  if (UUID_RE.test(seg)) return "id";
  if (LONGHEX_RE.test(seg)) return "id";
  if (SLUGNUM_RE.test(seg)) return "id";
  if (PREFIXNUM_RE.test(seg)) return "id";
  return "static";
}

export interface PathParam {
  name: string;
  example: string;
}

/** `/orders/123` → `{ template: "/orders/{id}", params:[{name:"id",example:"123"}] }`. Multiple: id, id2... */
export function normalizePath(pathname: string): { template: string; params: PathParam[] } {
  const segs = pathname.split("/");
  const params: PathParam[] = [];
  let idN = 0;
  const out = segs.map((seg) => {
    if (classifyPathSegment(seg) === "id") {
      idN += 1;
      const name = idN === 1 ? "id" : `id${idN}`;
      params.push({ name, example: seg });
      return `{${name}}`;
    }
    return seg;
  });
  let template = out.join("/");
  if (template.length > 1 && template.endsWith("/")) template = template.slice(0, -1);
  return { template: template === "" ? "/" : template, params };
}

export interface QueryParam {
  name: string;
  example: string;
}

export function extractQueryParams(search: string): QueryParam[] {
  const out: QueryParam[] = [];
  for (const [name, value] of new URLSearchParams(search)) out.push({ name, example: value });
  return out;
}

/** Resolve href to an absolute URL against base. Non-http(s) and unparseable → null. Fragment stripped. */
export function resolveLink(base: string, href: string): string | null {
  try {
    const u = new URL(href, base);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    u.hash = "";
    return u.toString();
  } catch {
    return null;
  }
}

// Scope checks live in core (shared by crawler / scanner). Re-exported for backwards compatibility.
export { hostMatches, isInScope } from "@veritas/core";

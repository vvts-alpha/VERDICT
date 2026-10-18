// Minimal GraphQL document parsing for inventory/probing. NOT a spec-complete parser — it understands the
// executable-document grammar well enough to (a) identify an operation (type/name/identity), (b) list root
// selection fields and declared variables, and (c) canonicalize a document to a STRUCTURE-ONLY signature so
// different variable/literal VALUES of the same operation share one identity (no per-value proliferation).
//
// Secrets policy: variable VALUES never enter the identity/signature; credential-looking variable names get
// their observed example value masked ("<redacted>") before the value is stored anywhere.

import type { GraphQLOperation } from "@veritas/core";

// ── tokens ────────────────────────────────────────────────────────────────
type Tok =
  | { t: "name"; v: string; s: number; e: number }
  | { t: "str"; v: string; s: number; e: number } // string/block-string literal (value kept only to be masked)
  | { t: "num"; v: string; s: number; e: number } // int/float literal
  | { t: "punct"; v: string; s: number; e: number }; // { } ( ) [ ] : = @ ! $ ... & |

const PUNCT = new Set(["{", "}", "(", ")", "[", "]", ":", "=", "@", "!", "$", "&", "|", ",", "..."]);

function lex(src: string): Tok[] | null {
  const toks: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c) || c === "," || c === "﻿") { i += 1; continue; }
    if (c === "#") { while (i < src.length && src[i] !== "\n") i += 1; continue; }
    if (src.startsWith('"""', i)) {
      const end = src.indexOf('"""', i + 3);
      if (end < 0) return null;
      toks.push({ t: "str", v: src.slice(i + 3, end), s: i, e: end + 3 });
      i = end + 3;
      continue;
    }
    if (src.startsWith("...", i)) { toks.push({ t: "punct", v: "...", s: i, e: i + 3 }); i += 3; continue; }
    if (c === '"') {
      let j = i + 1;
      let out = "";
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\") { out += src[j] + (src[j + 1] ?? ""); j += 2; continue; }
        out += src[j]; j += 1;
      }
      if (j >= src.length) return null;
      toks.push({ t: "str", v: out, s: i, e: j + 1 });
      i = j + 1;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < src.length && /[_0-9A-Za-z]/.test(src[j]!)) j += 1;
      toks.push({ t: "name", v: src.slice(i, j), s: i, e: j });
      i = j;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      const m = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(src.slice(i));
      if (!m) return null;
      toks.push({ t: "num", v: m[0], s: i, e: i + m[0].length });
      i += m[0].length;
      continue;
    }
    if (PUNCT.has(c)) { toks.push({ t: "punct", v: c, s: i, e: i + 1 }); i += 1; continue; }
    return null; // unknown char → not parseable by this subset
  }
  return toks.length ? toks : null;
}

// ── parser (recursive descent over the executable grammar) ────────────────
export interface ParsedOperation {
  operationType: "query" | "mutation" | "subscription";
  operationName: string | null;
  /** Variable names declared in the operation header ($x: T). */
  variableNames: string[];
  /** Root selection field names (aliases resolved to the real field name), fragment spreads expanded. */
  rootFields: string[];
  /** Root-level RESPONSE keys (alias when present, else the field name) — these are the keys that appear in
   *  the response `data` object, so response-side checks (baseline field presence) must use them. */
  responseKeys: string[];
  /** Structure-only signature: names/nesting/arg names/var refs, all literal values masked to "?". */
  canonical: string;
}

class P {
  private i = 0;
  constructor(private readonly toks: Tok[]) {}
  peek(): Tok | undefined { return this.toks[this.i]; }
  next(): Tok | undefined { return this.toks[this.i++]; }
  is(v: string): boolean { const t = this.toks[this.i]; return t?.t === "punct" && t.v === v; }
  eat(v: string): boolean { if (this.is(v)) { this.i += 1; return true; } return false; }
  name(): string | null { const t = this.toks[this.i]; return t?.t === "name" ? (this.i++, t.v) : null; }
  idx(): number { return this.i; }
  fail(): never { throw new Error("parse"); }
}

/** value := scalar | $var | enum | [value..] | {name: value..} — returns the canonical token ("?" masks literals). */
function value(p: P, depth: number): string {
  if (depth > 24) p.fail();
  const t = p.next();
  if (!t) p.fail();
  if (t.t === "punct" && t.v === "$") { const n = p.name() ?? p.fail(); return `$${n}`; }
  if (t.t === "punct" && t.v === "[") {
    const inner: string[] = [];
    while (!p.eat("]")) inner.push(value(p, depth + 1));
    return `[${inner.join(",")}]`; // order kept: list position is meaningful
  }
  if (t.t === "punct" && t.v === "{") {
    const inner: string[] = [];
    while (!p.eat("}")) {
      const k = p.name() ?? p.fail();
      if (!p.eat(":")) p.fail();
      inner.push(`${k}:${value(p, depth + 1)}`);
    }
    return `{${inner.sort().join(",")}}`; // input objects: key order is irrelevant → sort for stability
  }
  if (t.t === "str" || t.t === "num") return "?"; // literal scalar → masked (identity must not depend on the value)
  if (t.t === "name") {
    if (t.v === "true" || t.v === "false" || t.v === "null") return "?";
    return `e:${t.v}`; // enum-ish literal — structural (not a user secret in practice), kept distinct from "?"
  }
  p.fail();
}

/** type := Name | [type] | type! — consumed and ignored (types don't distinguish operations for identity). */
function gqlType(p: P): void {
  if (p.eat("[")) { gqlType(p); if (!p.eat("]")) p.fail(); }
  else if (!p.name()) p.fail();
  p.eat("!");
}

/** directives := (@name(args?))* — args carry no identity (directives like @include(if:$x) keep the var ref). */
function directives(p: P, out: string[]): void {
  while (p.eat("@")) {
    const n = p.name() ?? p.fail();
    out.push(`@${n}`);
    if (p.eat("(")) while (!p.eat(")")) { p.name() ?? p.fail(); if (!p.eat(":")) p.fail(); value(p, 0); }
  }
}

/** Per-level selection metadata collected while parsing a selection set. */
interface LevelInfo {
  /** Real field names at this level (alias resolved away), incl. via inline fragments. */
  fields: string[];
  /** Response keys at this level — the alias when present (data.current), else the field name. */
  keys: string[];
  /** Named fragment spreads at this level — resolved against the document's fragment map by the caller. */
  spreads: string[];
}

/** selectionSet := { selection+ } → canonical child list. Order is NOT semantic for query selections → items
 *  are sorted; but a MUTATION's ROOT selection set executes serially per spec — `ordered` keeps source order
 *  there so `mutation{ setFlag clearFlag }` and its reverse are NOT the same operation.
 *  `lv` collects THIS level's fields/response-keys/spreads (incl. through inline fragments), so callers get
 *  the operation's root-level selections. Named spreads are recorded for post-parse expansion. */
function selectionSet(p: P, depth: number, lv: LevelInfo, ordered = false): string {
  if (depth > 32 || !p.eat("{")) p.fail();
  const items: string[] = [];
  while (!p.eat("}")) {
    if (p.eat("...")) {
      const dirs: string[] = [];
      const fragName = p.name();
      if (fragName === "on" || fragName === null) {
        const tname = fragName === "on" ? p.name() ?? p.fail() : "";
        directives(p, dirs);
        const inner: LevelInfo = { fields: [], keys: [], spreads: [] };
        // An inline fragment is transparent to execution — inside a mutation's ordered root its contents are
        // still serially-executed root fields, so `ordered` propagates; a real field's child set is never serial.
        const canon = selectionSet(p, depth + 1, inner, ordered);
        items.push(`...on ${tname}${dirs.join("")}${canon}`);
        // inline-fragment selections belong to THIS level
        lv.fields.push(...inner.fields);
        lv.keys.push(...inner.keys);
        lv.spreads.push(...inner.spreads);
      } else {
        directives(p, dirs);
        items.push(`...${fragName}${dirs.join("")}`);
        lv.spreads.push(fragName);
      }
      continue;
    }
    const first = p.name() ?? p.fail();
    let fname = first;
    if (p.eat(":")) fname = p.name() ?? p.fail(); // alias: real field name after ':', but the RESPONSE key is the alias (= first)
    const args: string[] = [];
    if (p.eat("(")) {
      while (!p.eat(")")) {
        const a = p.name() ?? p.fail();
        if (!p.eat(":")) p.fail();
        args.push(`${a}:${value(p, 0)}`);
      }
    }
    const dirs: string[] = [];
    directives(p, dirs);
    const child = p.is("{") ? selectionSet(p, depth + 1, { fields: [], keys: [], spreads: [] }) : "";
    // Alias is part of identity: `first:user` and `second:user` return DIFFERENT response shapes (data.first vs
    // data.second) — they're different operations. `user:user` ≡ `user` (same key, same shape → one identity).
    items.push(`${first === fname ? fname : `${first}:${fname}`}${args.length ? `(${args.sort().join(",")})` : ""}${dirs.join("")}${child}`);
    lv.fields.push(fname);
    lv.keys.push(first); // response key: alias-or-name = the token before any ':'
  }
  return `{${(ordered ? items : items.sort()).join(",")}}`;
}

/** operation | fragment definition → canonical string + this definition's LEVEL-0 selection info
 *  (fields/response-keys/spread names — spreads are expanded into the caller's root lists post-parse). */
function definition(p: P): { canonical: string; op: ParsedOperation | null; fragName?: string; level: LevelInfo } {
  const head = p.peek();
  if (!head) p.fail();
  if (head.t === "punct" && head.v === "{") {
    // anonymous shorthand: `{ ... }` = a query (order-insensitive)
    const lv: LevelInfo = { fields: [], keys: [], spreads: [] };
    const sel = selectionSet(p, 0, lv, false);
    return { canonical: `q:${sel}`, op: { operationType: "query", operationName: null, variableNames: [], rootFields: [...new Set(lv.fields)], responseKeys: [...new Set(lv.keys)], canonical: `q:${sel}` }, level: lv };
  }
  const kw = p.name() ?? p.fail();
  if (kw === "fragment") {
    const fname = p.name() ?? p.fail();
    if (!p.name()) p.fail(); // 'on'
    const tname = p.name() ?? p.fail();
    const dirs: string[] = [];
    directives(p, dirs);
    const lv: LevelInfo = { fields: [], keys: [], spreads: [] };
    // A fragment ON the Mutation type is only ever spread into mutation roots — its top-level fields execute
    // serially there, so their order is part of identity (`fragment F on Mutation {a b}` ≠ `{b a}`).
    const sel = selectionSet(p, 1, lv, tname === "Mutation");
    return { canonical: `frag:${fname}:${tname}:${sel}`, op: null, fragName: fname, level: lv };
  }
  if (kw === "query" || kw === "mutation" || kw === "subscription") {
    const opName = p.peek()?.t === "name" ? p.name()! : null;
    const vars: string[] = [];
    const varCanon: string[] = [];
    if (p.eat("(")) {
      while (!p.eat(")")) {
        if (!p.eat("$")) p.fail();
        const vn = p.name() ?? p.fail();
        vars.push(vn);
        if (!p.eat(":")) p.fail();
        gqlType(p);
        if (p.eat("=")) value(p, 0); // default value — masked like any literal
        varCanon.push(`$${vn}`);
      }
    }
    const dirs: string[] = [];
    directives(p, dirs);
    const lv: LevelInfo = { fields: [], keys: [], spreads: [] };
    // Root mutation selections run IN ORDER — preserve it in the canonical signature.
    const sel = selectionSet(p, 0, lv, kw === "mutation");
    const canonical = `${kw[0]}:${opName ?? ""}(${varCanon.sort().join(",")})${dirs.join("")}${sel}`;
    return {
      canonical,
      op: { operationType: kw, operationName: opName, variableNames: vars, rootFields: [...new Set(lv.fields)], responseKeys: [...new Set(lv.keys)], canonical },
      level: lv,
    };
  }
  // SDL / schema / type definitions are not valid inside an executable request document — a client POSTing one
  // is not something we can replay, so treat the document as unparseable rather than guess.
  p.fail();
}

export interface ParsedGraphqlDocument {
  operations: ParsedOperation[];
  /** Whole-document structure signature (all definitions, canonicalized). */
  canonical: string;
  /** Named fragment definitions present in the document (name → structure-canonical body). */
  fragments: Map<string, string>;
}

/** Parse a GraphQL document. Returns null for non-parseable input (caller treats it as "not graphql"). */
export function parseGraphqlDocument(doc: string): ParsedGraphqlDocument | null {
  const toks = lex(doc);
  if (!toks) return null;
  const p = new P(toks);
  const ops: ParsedOperation[] = [];
  const canonParts: string[] = [];
  const fragments = new Map<string, string>();
  const fragLevels = new Map<string, LevelInfo>();
  const opLevels = new Map<ParsedOperation, LevelInfo>();
  try {
    while (p.peek()) {
      const d = definition(p);
      if (d.op) {
        ops.push(d.op);
        opLevels.set(d.op, d.level);
      }
      if (d.fragName) {
        fragments.set(d.fragName, d.canonical);
        fragLevels.set(d.fragName, d.level);
      }
      if (d.canonical) canonParts.push(d.canonical);
    }
  } catch {
    return null;
  }
  if (ops.length === 0) return null;
  // Expand named fragment spreads into each op's root fields / response keys — `{ ...F }` at the root means
  // the response carries F's selections, so the op's root surface is the transitive closure of its spreads.
  for (const op of ops) {
    const lv = opLevels.get(op);
    if (!lv || lv.spreads.length === 0) continue;
    const fields = new Set(op.rootFields);
    const keys = new Set(op.responseKeys);
    const queue = [...lv.spreads];
    const seen = new Set<string>();
    while (queue.length) {
      const n = queue.pop()!;
      if (seen.has(n)) continue;
      seen.add(n);
      const f = fragLevels.get(n);
      if (!f) continue;
      for (const x of f.fields) fields.add(x);
      for (const x of f.keys) keys.add(x);
      queue.push(...f.spreads);
    }
    op.rootFields = [...fields];
    op.responseKeys = [...keys];
  }
  return { operations: ops, canonical: canonParts.join("|"), fragments };
}

/** FNV-1a 32-bit — stable non-crypto hash for document identity. */
function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(36);
}

/** Variable name → JSON kind (never the value). */
export function variablesShape(vars: Record<string, unknown> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(vars ?? {})) {
    out[k] = v === null ? "null" : Array.isArray(v) ? "array" : typeof v === "object" ? "object" : typeof v;
  }
  return out;
}

const CREDENTIAL_VAR = /pass(word|wd)?|secret|token|credential|api[_-]?key|otp|cvv|card|session|auth/i;

/** Recursive mask: a credential-looking key redacts its whole subtree; inside plain objects/arrays each
 *  element is re-checked by its own key (arrays carry the enclosing key's sensitivity). Non-secret leaves
 *  (e.g. observed ids) are kept verbatim — they feed IDOR replays. */
function maskValue(v: unknown, sensitive: boolean): unknown {
  if (sensitive) return "<redacted>";
  if (Array.isArray(v)) return v.map((x) => maskValue(x, false));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = maskValue(x, CREDENTIAL_VAR.test(k));
    return out;
  }
  return v;
}

/** Mask values of credential-looking variables — recursively through nested objects and arrays.
 *  `sensitiveVars` = variables whose NAME is innocent but which were referenced from a sensitive position in
 *  the document (`login(password: $p)`) — the usage makes the value a credential, so it masks too. */
export function maskVariables(vars: Record<string, unknown> | undefined, sensitiveVars?: ReadonlySet<string>): Record<string, unknown> | undefined {
  if (!vars) return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(vars)) out[k] = maskValue(v, CREDENTIAL_VAR.test(k) || sensitiveVars?.has(k) === true);
  return out;
}

export interface GraphqlRequestParts {
  query: string;
  operationName: string | null;
  variables?: Record<string, unknown>;
}

/** Detect a GraphQL request body: JSON object with a string `query` field (optionally operationName/variables). */
export function parseGraphqlRequestBody(body: string | null | undefined): GraphqlRequestParts | null {
  if (!body) return null;
  const t = body.trim();
  if (!t.startsWith("{")) return null;
  let o: unknown;
  try {
    o = JSON.parse(t);
  } catch {
    return null;
  }
  if (!o || typeof o !== "object" || Array.isArray(o)) return null;
  const rec = o as Record<string, unknown>;
  if (typeof rec["query"] !== "string" || rec["query"].trim() === "") return null;
  const vars = rec["variables"];
  return {
    query: rec["query"],
    operationName: typeof rec["operationName"] === "string" ? rec["operationName"] : null,
    ...(vars && typeof vars === "object" && !Array.isArray(vars) ? { variables: vars as Record<string, unknown> } : {}),
  };
}

/**
 * The operation the server would actually execute: the one named by `operationName`, or the sole operation
 * in the document. Returns null when the document can't decide — an unknown operationName or several
 * operations without a selector must NOT silently pick the first (the server rejects those requests too).
 */
export function selectOperation(parts: GraphqlRequestParts, parsed: ParsedGraphqlDocument): ParsedOperation | null {
  if (parts.operationName != null) {
    return parsed.operations.find((o) => o.operationName === parts.operationName) ?? null;
  }
  return parsed.operations.length === 1 ? (parsed.operations[0] ?? null) : null;
}

/** Selected op's canonical PLUS the canonicals of the fragments it (transitively) spreads — two ops that
 *  differ only inside a referenced fragment are different operations. */
function operationCanonical(op: ParsedOperation, parsed: ParsedGraphqlDocument): string {
  const used: string[] = [];
  const seen = new Set<string>();
  const scan = (canon: string) => {
    for (const m of canon.matchAll(/\.\.\.([_A-Za-z][_0-9A-Za-z]*)/g)) {
      const n = m[1]!;
      if (n === "on" || seen.has(n)) continue; // "on" is inline-fragment syntax, not a spread name
      const frag = parsed.fragments.get(n);
      if (!frag) continue;
      seen.add(n);
      used.push(frag);
      scan(frag);
    }
  };
  scan(op.canonical);
  return used.length ? `${op.canonical}|${used.sort().join("|")}` : op.canonical;
}

/**
 * The identity used to tell operations apart on one endpoint:
 *   named op    → `name:<opName>:<hash>` — the NAME alone is not enough (two requests named Same with
 *                 different selections are different operations), so the selected op's canonical structure
 *                 (including used fragments) is folded in. Literal/variable VALUES stay out of the hash.
 *   anonymous   → `doc:<hash>` of the same per-operation canonical.
 * Returns null when the executed operation cannot be determined (unknown operationName / ambiguous doc).
 */
export function graphqlOperationKey(parts: GraphqlRequestParts, parsed: ParsedGraphqlDocument): string | null {
  const op = selectOperation(parts, parsed);
  if (!op) return null;
  const h = fnv1a(operationCanonical(op, parsed));
  return op.operationName ? `name:${op.operationName}:${h}` : `doc:${h}`;
}

/**
 * Re-lex `src` and rewrite the parts that can carry secrets so the PERSISTED document is display/export safe:
 *   - the value subtree of any argument or input-object field whose name looks credential-like → `null`
 *   - a variable DEFAULT of a credential-looking variable → the whole `= <value>` clause is dropped (writing
 *     `null` there would be INVALID for a non-null type like `String!`; benign defaults stay verbatim so the
 *     stored document still replays a baseline)
 * Also returns the names of variables REFERENCED from sensitive positions (`login(password: $p)` — the
 * literal isn't inline, so the variable's observed value in `variables` must be masked instead).
 * Non-secret literals (ids etc.) are preserved. Selection names/aliases/structure are untouched, so the
 * sanitized document parses to the same canonical identity.
 */
function sanitizeDocumentFull(src: string): { document: string; sensitiveVars: Set<string> } {
  const toks = lex(src);
  if (!toks) return { document: src, sensitiveVars: new Set() };
  const p = new P(toks);
  const sensitiveVars = new Set<string>();
  const edits: Array<{ s: number; e: number; r: string }> = []; // token ranges → replacement text
  // Variable defaults are DECIDED LAST: `mutation Login($p:String! = "x") { login(password:$p) }` makes $p
  // sensitive by USE, not by name — and the use site is only discovered after the header parses. So a default
  // clause's range is recorded now and dropped after the walk iff its var is credential-named OR used in a
  // sensitive position.
  const pendingDefaults: Array<{ vn: string; s: number; e: number }> = [];

  const markValue = (depth: number, sensitive: boolean): void => {
    if (depth > 24) p.fail();
    const t = p.next() ?? p.fail();
    if (t.t === "punct" && t.v === "$") {
      const vn = p.name() ?? p.fail();
      if (sensitive) sensitiveVars.add(vn); // the secret value lives in `variables` — mask it there
      return;
    }
    if (t.t === "punct" && t.v === "[") {
      while (!p.eat("]")) markValue(depth + 1, sensitive);
      return;
    }
    if (t.t === "punct" && t.v === "{") {
      while (!p.eat("}")) {
        const k = p.name() ?? p.fail();
        if (!p.eat(":")) p.fail();
        markValue(depth + 1, sensitive || CREDENTIAL_VAR.test(k));
      }
      return;
    }
    if (t.t === "str" || t.t === "num") { if (sensitive) edits.push({ s: t.s, e: t.e, r: "null" }); return; }
    if (t.t === "name") return; // enum/true/false/null — structural, not secret-bearing
    p.fail();
  };
  const markArgList = (): void => {
    if (!p.eat("(")) return;
    while (!p.eat(")")) {
      const a = p.name() ?? p.fail();
      if (!p.eat(":")) p.fail();
      markValue(0, CREDENTIAL_VAR.test(a));
    }
  };
  const markDirectives = (): void => {
    while (p.eat("@")) {
      p.name() ?? p.fail();
      markArgList();
    }
  };
  const markSelSet = (depth: number): void => {
    if (depth > 32 || !p.eat("{")) p.fail();
    while (!p.eat("}")) {
      if (p.eat("...")) {
        const fragName = p.name();
        if (fragName === "on" || fragName === null) {
          if (fragName === "on") p.name() ?? p.fail();
          markDirectives();
          markSelSet(depth + 1);
        } else {
          markDirectives();
        }
        continue;
      }
      p.name() ?? p.fail();
      if (p.eat(":")) p.name() ?? p.fail(); // alias
      markArgList();
      markDirectives();
      if (p.is("{")) markSelSet(depth + 1);
    }
  };
  try {
    while (p.peek()) {
      const head = p.peek()!;
      if (head.t === "punct" && head.v === "{") { markSelSet(0); continue; }
      const kw = p.name() ?? p.fail();
      if (kw === "fragment") {
        p.name() ?? p.fail();
        p.name() ?? p.fail(); // 'on'
        p.name() ?? p.fail(); // type name
        markDirectives();
        markSelSet(1);
        continue;
      }
      if (kw === "query" || kw === "mutation" || kw === "subscription") {
        if (p.peek()?.t === "name") p.name();
        if (p.eat("(")) {
          while (!p.eat(")")) {
            if (!p.eat("$")) p.fail();
            const vn = p.name() ?? p.fail();
            if (!p.eat(":")) p.fail();
            gqlType(p);
            if (p.eat("=")) {
              const eqTok = toks[p.idx() - 1]!;
              markValue(0, false); // consume the value; nested credential fields inside a kept default still mask
              pendingDefaults.push({ vn, s: eqTok.s, e: toks[p.idx() - 1]!.e });
            }
          }
        }
        markDirectives();
        markSelSet(0);
        continue;
      }
      p.fail();
    }
  } catch {
    // Shouldn't happen (callers sanitize only already-parsed docs) — if it does, mask every literal token.
    for (const t of toks) if (t.t === "str" || t.t === "num") edits.push({ s: t.s, e: t.e, r: "null" });
  }
  // Defaults of credential-named OR sensitively-USED variables are dropped whole (`= <value>` gone — `null`
  // would be invalid on a `T!` type and must never be replayed as a real default anyway). When the clause is
  // dropped, any nested literal edits INSIDE its range must go too — applying both edits corrupts the doc.
  for (const d of pendingDefaults) {
    if (CREDENTIAL_VAR.test(d.vn) || sensitiveVars.has(d.vn)) {
      for (let i = edits.length - 1; i >= 0; i--) {
        if (edits[i]!.s >= d.s && edits[i]!.e <= d.e) edits.splice(i, 1);
      }
      edits.push({ s: d.s, e: d.e, r: "" });
    }
  }
  let out = src;
  for (const ed of edits.sort((a, b) => b.s - a.s)) out = out.slice(0, ed.s) + ed.r + out.slice(ed.e);
  // Defensive: the sanitized document MUST re-parse — a corrupted rewrite would otherwise persist an
  // unreplayable/unreadable document. The fallback must NOT be raw `src` (that would persist the very
  // secrets we're stripping): bluntly drop EVERY default clause and null EVERY string literal outside
  // them — loses benign defaults but is guaranteed secret-free; last resort is a minimal valid doc.
  if (!parseGraphqlDocument(out)) {
    const blunt: { s: number; e: number; r: string }[] = pendingDefaults.map((d) => ({ s: d.s, e: d.e, r: "" }));
    for (const t of toks)
      if (t.t === "str" && !blunt.some((b) => t.s >= b.s && t.e <= b.e)) blunt.push({ s: t.s, e: t.e, r: "null" });
    let out2 = src;
    for (const ed of blunt.sort((a, b) => b.s - a.s)) out2 = out2.slice(0, ed.s) + ed.r + out2.slice(ed.e);
    return { document: parseGraphqlDocument(out2) ? out2 : "{ __typename }", sensitiveVars };
  }
  return { document: out, sensitiveVars };
}

/** Sanitize a document for persistence/display (secret-bearing inline literals → `null`, credential-named
 *  variable defaults dropped). */
export function sanitizeGraphqlDocument(src: string): string {
  return sanitizeDocumentFull(src).document;
}

/** Full ApiCall.graphql payload for one observed exchange. Returns null when the request isn't a GraphQL op
 *  OR when the executed operation is ambiguous (multi-op doc without operationName / unknown operationName) —
 *  an undecidable request must not be pinned to a wrong operation. */
export function describeGraphqlOperation(body: string | null | undefined): GraphQLOperation | null {
  const parts = parseGraphqlRequestBody(body);
  if (!parts) return null;
  const parsed = parseGraphqlDocument(parts.query);
  if (!parsed) return null;
  const op = selectOperation(parts, parsed);
  if (!op) return null;
  const operationKey = graphqlOperationKey(parts, parsed);
  if (!operationKey) return null;
  const { document, sensitiveVars } = sanitizeDocumentFull(parts.query);
  return {
    operationType: op.operationType,
    operationName: parts.operationName ?? op.operationName,
    operationKey,
    rootFields: op.rootFields,
    responseKeys: op.responseKeys,
    variablesShape: variablesShape(parts.variables),
    // persisted/display material is sanitized — secrets never enter inventory, exports or the UI.
    document,
    ...(parts.variables ? { variablesExample: maskVariables(parts.variables, sensitiveVars) } : {}),
  };
}

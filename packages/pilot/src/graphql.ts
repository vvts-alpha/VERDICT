// GraphQL response semantics for probing. A GraphQL endpoint answers HTTP 200 for almost EVERYTHING — syntax errors,
// validation failures, authz denials, partial resolver failures — so "status 200" proves nothing. These helpers
// classify the ENVELOPE ({data, errors, extensions}) so probes can distinguish "the resolver ran and returned data"
// from "the request never executed" from "it was denied", and a baseline is only 'established' when real data came back.
//
// Evidence discipline note: classification is honest ABOUT evidence — an "errors" or auth-denied baseline means the
// check is UNVERIFIED (never silently counted as clean), and a positive result is only a candidate; record_finding
// still applies the control-fails + ≥2-stable-replays rule on the recorded evidence.

export interface GraphqlError {
  message: string;
  /** extensions.code / classification — UNAUTHENTICATED, FORBIDDEN, BAD_USER_INPUT, GRAPHQL_VALIDATION_FAILED, ... */
  code?: string;
  /** Field path the error belongs to (present on field-level authz denials & resolver errors). */
  path?: Array<string | number>;
}

export type GraphqlResponseKind =
  | "ok" // data present, no errors — resolver ran clean
  | "partial" // data AND errors — partial authz failure / partial resolver crash (a real, meaningful state)
  | "errors" // errors only (data absent or null) — request-level failure: syntax/validation/auth/denied
  | "empty" // data object exists but every top-level key is null/missing — target data absent (object doesn't exist / no rows)
  | "not-graphql"; // body isn't a GraphQL envelope (not JSON, or no data/errors keys) — wrong endpoint/shape

export interface GraphqlResponse {
  kind: GraphqlResponseKind;
  /** parsed envelope (null when not-graphql / unparseable) */
  data: Record<string, unknown> | null;
  errors: GraphqlError[];
  /** true when errors indicate authentication or authorization denial (UNAUTHENTICATED / FORBIDDEN / authz message). */
  authzDenied: boolean;
  /** true when errors indicate the request never reached resolvers (parse / validation / variable-type errors). */
  requestRejected: boolean;
}

const AUTHZ_CODES = /^(UNAUTHENTICATED|UNAUTHORIZED|FORBIDDEN|AUTH_NOT_AUTHORIZED|NOT_AUTHORIZED|ACCESS_DENIED|PERMISSION_DENIED)$/i;
const AUTHZ_MSG = /not authorized|unauthori[sz]ed|forbidden|permission denied|access denied|requires? (auth|login)|must be logged|not authenticated|insufficient (privilege|permission)|denied/i;
const REJECT_CODES = /^(GRAPHQL_PARSE_FAILED|GRAPHQL_VALIDATION_FAILED|BAD_USER_INPUT|BAD_REQUEST|INTERNAL_(?=.))/i;
const REJECT_MSG = /cannot query field|did you mean|syntax error|expected type|variable .*(not|un)defined|of required type|was not provided|unknown argument|must not be null|not defined by the schema/i;
/** Explicit NON-authz error codes — an INTERNAL_SERVER_ERROR whose message happens to contain "Access denied
 *  for user 'app'@'db'" is a resolver/DB failure, not enforcement. A declared code beats message wording. */
const NON_AUTHZ_CODES = /^(INTERNAL|INTERNAL_SERVER_ERROR|GRAPHQL_PARSE_FAILED|GRAPHQL_VALIDATION_FAILED|BAD_USER_INPUT|BAD_REQUEST|DATABASE|DB_|TIMEOUT|SERVICE_UNAVAILABLE|RATE_LIMITED|ECONN|RESOLVER)/i;

/** Is this error a genuine authorization signal? A declared non-authz CODE (INTERNAL_SERVER_ERROR, validation,
 *  DB/timeout…) overrides any auth-looking message wording — only coded authz errors or uncoded authz-worded
 *  messages count. */
export function graphqlErrorIsAuthz(e: GraphqlError): boolean {
  if (e.code && AUTHZ_CODES.test(e.code)) return true;
  if (e.code && NON_AUTHZ_CODES.test(e.code)) return false;
  return AUTHZ_MSG.test(e.message);
}

/** Parse + classify a GraphQL HTTP response body. `status` participates: 401/403 = denied even if the body is terse. */
export function parseGraphqlResponse(status: number, body: string): GraphqlResponse {
  let j: unknown;
  try {
    j = JSON.parse(body);
  } catch {
    return { kind: "not-graphql", data: null, errors: [], authzDenied: status === 401 || status === 403, requestRejected: false };
  }
  if (!j || typeof j !== "object" || Array.isArray(j))
    return { kind: "not-graphql", data: null, errors: [], authzDenied: status === 401 || status === 403, requestRejected: false };
  const rec = j as Record<string, unknown>;
  if (!("data" in rec) && !("errors" in rec))
    return { kind: "not-graphql", data: null, errors: [], authzDenied: status === 401 || status === 403, requestRejected: false };

  const errors: GraphqlError[] = [];
  if (Array.isArray(rec.errors)) {
    for (const e of rec.errors) {
      if (!e || typeof e !== "object") continue;
      const eo = e as Record<string, unknown>;
      const ext = eo.extensions && typeof eo.extensions === "object" ? (eo.extensions as Record<string, unknown>) : undefined;
      errors.push({
        message: typeof eo.message === "string" ? eo.message : "",
        ...(typeof ext?.code === "string" ? { code: ext.code } : {}),
        ...(Array.isArray(eo.path) ? { path: eo.path as Array<string | number> } : {}),
      });
    }
  }
  const authzDenied =
    status === 401 ||
    status === 403 ||
    errors.some(graphqlErrorIsAuthz);
  const requestRejected =
    errors.length > 0 &&
    errors.every((e) => (e.code && REJECT_CODES.test(e.code)) || REJECT_MSG.test(e.message));

  const data = rec.data && typeof rec.data === "object" && !Array.isArray(rec.data) ? (rec.data as Record<string, unknown>) : null;
  if (errors.length > 0) {
    const partial = data !== null && Object.values(data).some((v) => v !== null && v !== undefined);
    return {
      kind: partial ? "partial" : "errors",
      data: partial ? data : null,
      errors,
      authzDenied,
      requestRejected,
    };
  }
  if (!data) {
    // data: null with no errors — resolver-level null; for baseline purposes this is "no data".
    return { kind: "empty", data: null, errors: [], authzDenied, requestRejected };
  }
  const populated = Object.values(data).some((v) => v !== null && v !== undefined);
  return { kind: populated ? "ok" : "empty", data, errors: [], authzDenied, requestRejected };
}

export type BaselineVerdict =
  | { established: true; data: Record<string, unknown>; returnedFields: string[]; partial: boolean }
  | { established: false; reason: string; classifiedAs: GraphqlResponseKind };

/** Decide whether a baseline request actually EXECUTED and returned real data — the precondition every authz/IDOR/
 *  injection check on a GraphQL operation depends on. NOT established on: parse/validation failure, auth denial,
 *  empty data (target object missing), or a non-GraphQL response. Callers must treat !established as UNVERIFIED. */
export function baselineVerdict(res: GraphqlResponse, expectedFields?: ReadonlyArray<string>): BaselineVerdict {
  switch (res.kind) {
    case "not-graphql":
      return { established: false, classifiedAs: res.kind, reason: "response is not a GraphQL envelope (no data/errors) — wrong endpoint or request shape" };
    case "errors":
      if (res.authzDenied) return { established: false, classifiedAs: res.kind, reason: `authz denied under the baseline session (${res.errors[0]?.message ?? "denied"}) — the baseline ROLE lacks access; baseline unverifiable` };
      if (res.requestRejected) return { established: false, classifiedAs: res.kind, reason: `request rejected before execution (${res.errors[0]?.message ?? "validation"}) — fix the document/variables; this is UNVERIFIED, not clean` };
      return { established: false, classifiedAs: res.kind, reason: `resolver returned errors only (${res.errors[0]?.message ?? "error"})` };
    case "empty":
      return { established: false, classifiedAs: res.kind, reason: "executed but returned no data — the target object/rows are absent; pick real variables/ids first" };
    case "ok":
    case "partial": {
      const data = res.data!;
      const returned = Object.keys(data).filter((k) => data[k] !== null && data[k] !== undefined);
      if (expectedFields && expectedFields.length > 0) {
        const missing = expectedFields.filter((f) => !returned.includes(f));
        if (missing.length === expectedFields.length)
          return { established: false, classifiedAs: res.kind, reason: `none of the operation's root fields (${expectedFields.join(",")}) returned data — wrong variables or a stub endpoint` };
      }
      return { established: true, data, returnedFields: returned, partial: res.kind === "partial" };
    }
  }
}

/** Build a GraphQL POST body for one operation. `variables` is JSON-encoded verbatim (typed values preserved). */
export function graphqlRequestBody(op: { document: string; operationName?: string | null }, variables?: Record<string, unknown>): string {
  const o: Record<string, unknown> = { query: op.document };
  if (op.operationName) o.operationName = op.operationName;
  if (variables && Object.keys(variables).length > 0) o.variables = variables;
  return JSON.stringify(o);
}

/** Field-level diff between two role responses over the SAME operation. Reports, per root field, who saw data —
 *  for field-level authz (a field resolving for admin but denied/null for user) and operation-level authz
 *  (the whole op denied). Public-readable fields in both are NOT flagged — presence in both is just "public". */
export function fieldDiff(
  baseline: GraphqlResponse,
  other: GraphqlResponse,
): {
  baselineFields: string[];
  otherFields: string[];
  /** Root fields that resolved for baseline but are absent/null for the other role (restricted for them). */
  deniedForOther: string[];
  /** Root fields resolving for the OTHER role but not baseline (the other role sees MORE — suspicious direction). */
  extraForOther: string[];
  /** Fields the other role got a field-level AUTHORIZATION error on — the full error path joined
   *  ("user.salary"), since a nested field denial's path[0] is the root field that still RESOLVED. Only
   *  authz-classified errors — a resolver crash or DB timeout at a path is NOT enforcement. */
  errorFieldsForOther: string[];
  /** Fields the other role got a NON-authz error on (INTERNAL_SERVER_ERROR, timeout, resolver exceptions) —
   *  the field failed to resolve; that is an outage/inconclusive signal, never enforcement. */
  failedFieldsForOther: string[];
} {
  const names = (d: Record<string, unknown> | null): string[] => (d ? Object.keys(d).filter((k) => d[k] !== null && d[k] !== undefined) : []);
  const b = names(baseline.data);
  const o = names(other.data);
  const authzErrs = new Set<string>();
  const failedErrs = new Set<string>();
  const failedRoots = new Set<string>(); // root field of each NON-authz error path — an absent root failed, not denied
  for (const e of other.errors) {
    const segs = e.path?.filter((x) => typeof x === "string");
    if (!segs || segs.length === 0) continue;
    if (graphqlErrorIsAuthz(e)) authzErrs.add(segs.join("."));
    else {
      failedErrs.add(segs.join("."));
      failedRoots.add(segs[0]!);
    }
  }
  return {
    baselineFields: b,
    otherFields: o,
    // A root field absent for the other role counts as DENIED only when its absence is unexplained or
    // authz-explained — a non-authz error at that path (INTERNAL/timeout/resolver) makes it a FAILED read,
    // which must never surface as "restriction working".
    deniedForOther: b.filter((f) => !o.includes(f) && !failedRoots.has(f)),
    extraForOther: o.filter((f) => !b.includes(f)),
    errorFieldsForOther: [...authzErrs],
    failedFieldsForOther: [...failedErrs],
  };
}

/** Vocabulary that marks a mutation as potentially destructive — enforced in CODE (a tool description is not a
 *  control). An observed operation named this way is never replayed by a probe; test-only mutations must use
 *  non-destructive names on test resources. */
export const DESTRUCTIVE_OP_NAME = /delete|remove|destroy|purge|drop|transfer|wire|pay(ment|out)?|charge|checkout|refund|withdraw|deposit|ban|deactivat|disable|reset|revok|terminat|erase|wipe|truncate|unlink|cancel|archive|suspend|shutdown|kill|demote|promote|grant|escalat/i;

/** true when a mutation's name/root fields read as destructive — probes must refuse to execute it. */
export function mutationLooksDestructive(op: { operationName?: string | null; rootFields: string[] }): string | null {
  const hit = [op.operationName ?? "", ...op.rootFields].find((n) => n && DESTRUCTIVE_OP_NAME.test(n));
  return hit ?? null;
}

/** Leaves in a variables object that still hold the inventory mask placeholder — a redacted value must never
 *  be replayed as if it were real baseline material. */
export function redactedVariablePaths(vars: Record<string, unknown> | undefined, prefix = "variables"): string[] {
  const out: string[] = [];
  const walk = (node: unknown, path: string[], depth: number): void => {
    if (depth > 8 || !node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        if (node[i] === "<redacted>") out.push([...path, String(i)].join("."));
        else walk(node[i], [...path, String(i)], depth + 1);
      }
      return;
    }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (v === "<redacted>") out.push([...path, k].join("."));
      else if (v && typeof v === "object") walk(v, [...path, k], depth + 1);
    }
  };
  walk(vars, [prefix], 0);
  return out;
}

const ID_LEAF = /(^|[_.\-])(ids?|.*[_\-]?ids?|uuid|guid|uid)s?$|^(owner|user|account|order|tenant|org|file|doc|document|message|post|comment|item|product|event|cart|basket|invoice|payment|address|profile|object|record|resource|target|entity)[_.\-]?ids?$/i;

/** Walk an observed variables object for ID-BEARING leaf paths ("input.ownerId" — relative to `variables`).
 *  Leaf predicate: id-ish name AND scalar value. Max depth 6, first 16 hits — bounded so a giant input object
 *  doesn't explode the sweep. */
export function graphqlIdLeafPaths(vars: Record<string, unknown> | undefined, prefix = "variables"): Array<{ pointer: string; name: string; example: string }> {
  const out: Array<{ pointer: string; name: string; example: string }> = [];
  const walk = (node: unknown, path: string[], depth: number): void => {
    if (depth > 6 || out.length >= 16 || !node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (let i = 0; i < Math.min(node.length, 3); i++) walk(node[i], [...path, String(i)], depth + 1);
      return;
    }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if ((typeof v === "string" || typeof v === "number") && ID_LEAF.test(k)) {
        out.push({ pointer: [...path, k].join("."), name: k, example: String(v) });
      } else if (v && typeof v === "object") {
        walk(v, [...path, k], depth + 1);
      }
    }
  };
  walk(vars, [prefix], 0);
  return out;
}

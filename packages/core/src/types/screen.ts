// DESIGN §6.6 — screen_inventory.json schema (the sole contract Phase1 writes and Phase2/WebUI read)

export type AuthState = "unauth" | "post-login";

export type ScreenType =
  | "listing"
  | "detail"
  | "form"
  | "auth"
  | "dashboard"
  | "search"
  | "upload"
  | "payment"
  | "admin"
  | "other";

export type ParamLoc = "path" | "query" | "body" | "header";

/** JSON shape inferred from req/res (recursive) */
export type JsonShape =
  | { type: "object"; fields: Record<string, JsonShape> }
  | { type: "array"; items: JsonShape }
  | { type: "string" | "number" | "boolean" | "null" | "unknown" };

/** One observed GraphQL operation on an endpoint. A single POST /graphql carries many logical operations —
 *  each becomes its own ApiCall (urlTemplate + graphql.operationKey) so probes/diagnosis address them individually. */
export interface GraphQLOperation {
  /** query / mutation / subscription — mutations are write-class, others read. */
  operationType: "query" | "mutation" | "subscription";
  /** The operationName the client sent, or null for anonymous docs. */
  operationName: string | null;
  /** Identity of THIS operation within the endpoint: `name:<operationName>:<hash>` when named, else `doc:<hash>`
   *  — the hash is of the SELECTED operation's structure-canonicalized form (literal/variable VALUES stripped,
   *  transitively-used fragment bodies included). Same op with different variable values shares one key; two ops
   *  sharing a name but differing in selection get different keys. */
  operationKey: string;
  /** Root selection field names — real field names (aliases resolved away), fragment spreads expanded. */
  rootFields: string[];
  /** Root-level RESPONSE keys: the alias when one was used (`{ current: user }` → data.current), else the field
   *  name — i.e. the keys actually present in the response `data`. Fragment spreads expanded. Older persisted
   *  inventory may lack it; fall back to rootFields. */
  responseKeys?: string[];
  /** Variable name → observed JSON kind ("string"|"number"|"boolean"|"object"|"array"|"null"). Never values. */
  variablesShape: Record<string, string>;
  /** The operation document text — SANITIZED for persistence/display: inline literals bound to credential-like
   *  argument/input-field names are `null`ed and credential-named variable defaults are dropped. Replays needing
   *  the original literal must be passed it explicitly — never replay a masked placeholder as a real value. */
  document: string;
  /** Observed example variable VALUES — replay material for baseline establishment, same precedent as
   *  Param.example. Credential-looking names AND variables referenced from sensitive argument positions are
   *  masked (`"<redacted>"`), recursively through objects/arrays; never part of the identity/dedup key. */
  variablesExample?: Record<string, unknown>;
}

export interface ApiCall {
  /** GET/POST/... */
  method: string;
  /** Normalized, e.g. /api/orders/{id} */
  urlTemplate: string;
  /** Auth header presence-detected only. The value is never stored (DESIGN §6.2) */
  auth: "none" | "bearer" | "cookie";
  reqSchema: JsonShape | null;
  resSchema: JsonShape | null;
  /** Present iff this call is a specific observed GraphQL operation (the endpoint path alone is not the identity). */
  graphql?: GraphQLOperation;
}

export type GuessedType =
  | "object_ref"
  | "id"
  | "enum"
  | "free_text"
  | "file"
  | "price"
  | "qty"
  | "unknown";

export interface Param {
  name: string;
  in: ParamLoc;
  example: string;
  guessedType: GuessedType;
}

export interface Screen {
  /** s-0007 format */
  screenId: string;
  /** Normalized route */
  urlTemplate: string;
  observedUrls: string[];
  authState: AuthState;
  screenType: ScreenType;
  /** LLM-assigned meaning (M1 is a rule-based placeholder) */
  description: string;
  params: Param[];
  apis: ApiCall[];
  /** Relative path to artifacts/<screen_id>.png etc. */
  screenshot: string;
  /** Part of the dedup key (DESIGN §6.4) */
  domSkeletonHash: string;
  /** Attack hints, e.g. ["idor-candidate","pii"] */
  labels: string[];
}

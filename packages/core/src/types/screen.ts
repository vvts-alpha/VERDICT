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

export interface ApiCall {
  /** GET/POST/... */
  method: string;
  /** Normalized, e.g. /api/orders/{id} */
  urlTemplate: string;
  /** Auth header presence-detected only. The value is never stored (DESIGN §6.2) */
  auth: "none" | "bearer" | "cookie";
  reqSchema: JsonShape | null;
  resSchema: JsonShape | null;
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

// Full-asset LLM review ledger — one record per fetched HTML/JS asset.
// `complete` is TRUE only when every chunk of the body was actually sent to the model;
// a truncated fetch, a model error, or a budget stop keeps it false — "not reviewed" is never
// laundered into "nothing found".

export type AssetKind = "html" | "js";

export interface AssetObservation {
  /** observation class — e.g. secret | credential | endpoint | debug | comment | logic */
  type: string;
  detail: string;
  /** verbatim snippet the model cited (already truncated by the prompt). */
  evidence?: string;
  /** where in the asset (offset hint / function name). */
  location?: string;
  /** the concrete next request/check the model suggested. */
  investigation?: string;
  /** follow-up status: executed-in-stage → verified/refuted; never reached → pending. */
  status?: "pending" | "verified" | "refuted";
}

export interface AssetReview {
  url: string;
  kind: AssetKind;
  bytes: number;
  /** true when the fetched body was complete (not truncated at the fetch bound). */
  fetchedComplete: boolean;
  chunksTotal: number;
  /** chunks actually sent to the model and answered (== chunksTotal only on full coverage). */
  chunksAnalyzed: number;
  /** complete = fetchedComplete && chunksAnalyzed === chunksTotal. */
  complete: boolean;
  observations: AssetObservation[];
  analyzedAt: string;
}

/** A state-changing action the assessment performed against the target.
 *  Recorded mechanically at the tool layer (never model-reported) so operators can answer
 *  "what did VERDICT change?" — e.g. which account's password now holds which value. */
export type MutationAction =
  | "password-change"
  | "password-reset"
  | "register"
  | "update"
  | "delete"
  | "write";

export interface Mutation {
  /** Screen being diagnosed when the write happened (null outside diagnosis). */
  screenId: string | null;
  /** Session role label ("alice") or null when unidentified. */
  role: string | null;
  /** Session identity (cookie/token fingerprint) when the role is unknown. */
  sessionRef?: string;
  action: MutationAction;
  /** Entity the write acted on — email / username / id when derivable. */
  subject?: string;
  /** Field name -> value the write set. Password/secret values ARE stored: the ledger's
   *  purpose is knowing what a credential became (same protection level as evidence). */
  fields: Record<string, string>;
  method: string;
  url: string;
  status: number;
  /** Evidence id of the request/response that performed the write. */
  evidenceId?: string;
}

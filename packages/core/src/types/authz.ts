// Authorization-testing contracts — discovery is kept strictly separate from
// verified ownership / access expectations. TRUST BOUNDARY:
//
//   * "operator" basis = launch-time configuration ONLY (manifest auth.roles[]
//     principal/tenant/identityUrl + auth.expectedAccess). Tool arguments and
//     model-authored text are NEVER an operator basis — the model cannot
//     declare its way into an ownership or deny expectation.
//   * "identity-binding" = the object's own response carries an explicit owner
//     field (ownerId/userId/…) matching the subject's *verified* principal —
//     where a principal is established by an independent identity response
//     fetched AS that session (a whoami-style endpoint returning DIFFERENT
//     principals under different sessions — a static URL fails that self-test)
//     or by an operator-declared principal. A role name, a configured username,
//     or an unsigned JWT claim is NOT identity proof.
//   * An access DIFFERENTIAL (subject A reads, subject B denied) is evidence of
//     per-object authorization enforcement — it is NOT ownership proof and is
//     never an OwnershipBasis. A past denial on the same resource TYPE likewise
//     does not create a deny expectation for a different object.
//
// An AuthzObject records what was OBSERVED (which subject read/denied which
// object on which endpoint/tenant, backed by evidence ids). Ownership is set
// only when ownerBasis records what actually established it. An AuthzComparison
// is one bounded A/B test on a known object — owner baseline, compare replays,
// the actual denied control — so a finding's cited evidence can be
// provenance-checked against it; a private-looking body alone cannot confirm.

/** What established the object's ownership. (An observed access differential is NOT ownership.) */
export type OwnershipBasis = "operator" | "identity-binding";

export interface AuthzObject {
  /** Stable identity: resourceType | endpoint | operationKey | tenant | objectId — the same id
   *  value under a different tenant, endpoint, or resource type is a DIFFERENT object. */
  key: string;
  /** Logical resource type ("order", the param/root-field name). */
  resourceType: string;
  /** The object identifier value. */
  objectId: string;
  /** urlTemplate / "POST /graphql" the object was observed on. */
  endpoint: string;
  /** GraphQL operationKey when the object lives behind an operation. */
  operationKey?: string;
  /** Tenant the object belongs to — only when tenant context is established (operator-declared). */
  tenant?: string;
  /** Subjects OBSERVED reading this object (role labels; pair with principals in evidence). */
  observedBy: string[];
  /** Subjects OBSERVED denied this object. */
  deniedFor: string[];
  /** Verified owner subject — set only when ownerBasis records the establishment mechanism.
   *  owner + ownerBasis + ownerEvidenceIds are ONE ATOMIC TUPLE: a writer establishes ownership by
   *  passing all three together; a bare `owner` without basis+evidence is dropped, and a new owner
   *  never inherits a stale basis or the previous owner's establishing evidence. */
  owner?: string;
  ownerBasis?: OwnershipBasis;
  /** The evidence ids that established THIS owner (the owner baseline carrying the owner-field
   *  binding, or the manifest-derived record). Moves only with owner+ownerBasis. */
  ownerEvidenceIds?: string[];
  /** Provenance: evidence ids behind the observations. */
  evidenceIds: string[];
  /** ISO-8601 */
  updatedAt: string;
}

export type AuthzAction = "read" | "write";

export type AuthzOutcome =
  | "unexpected-access" // compare subject accessed an object it had a VERIFIED deny-expectation for
  | "denied-as-expected" // compare subject was denied (clean result for that exact comparison)
  | "allowed" // access expected (shared/public object or an operator-declared allow)
  | "inconclusive" // unexpected-looking access but ownership/expectation unproven — a lead, never a finding
  | "unverified"; // the comparison could not run soundly (no owner baseline, dead/missing session, transport)

export type ExpectationBasis =
  | "operator" // launch-config expectedAccess metadata (never a tool argument)
  | "acl" // the object's own explicit grant list (acl/permissions/sharedWith/…) excludes the compare subject
  | "observed-denial" // this exact object was previously observed denied for this compare subject
  | "none"; // no verified expectation — outcome can never be "unexpected-access"

export interface AuthzComparison {
  id: string;
  /** AuthzObject.key of the object under test. */
  objectKey: string;
  endpoint: string;
  operationKey?: string;
  action: AuthzAction;
  /** Verified owner subject (the baseline leg) + its established principal when known. */
  ownerSubject: string;
  ownerPrincipal?: string;
  /** The compared subject + its established principal when known. */
  compareSubject: string;
  comparePrincipal?: string;
  /** Owner's baseline read evidence id (must carry the object, not an error). */
  ownerEvidenceId?: string;
  /** Identity-probe evidence ids per subject ("whoami" legs that established the principals). */
  identityEvidenceIds: string[];
  /** Negative-control evidence ids — the actual DENIED request(s) (non-existent id as the compare subject). */
  deniedEvidenceIds: string[];
  /** The compare subject's replay evidence ids (the actual access attempts). */
  compareEvidenceIds: string[];
  /** The expectation the compare subject was tested against. */
  expectation: "deny" | "allow" | "unknown";
  expectationBasis: ExpectationBasis;
  /** true only when the subjects' tenants are independently established via launch config —
   *  never inferred from a stray tenantId response field or role labels. */
  tenantBoundary: boolean;
  outcome: AuthzOutcome;
  reason?: string;
  /** ISO-8601 */
  at: string;
}

/** An operator-declared access rule (manifest `auth.expectedAccess`, launch-time config — model tool
 *  arguments can never produce one). It is the ONLY way a "should be denied" / "should be allowed"
 *  expectation enters the system: "role B must not reach object X" lets a denied-by-design control be
 *  told apart from a real exposure, and a declared allow keeps shared/public/admin access out of findings. */
export interface ExpectedAccessRule {
  /** Object identifier the rule covers (matches AuthzObject.objectId / a check row's resource). */
  object?: string;
  /** Endpoint template the rule covers ("/orders/{id}", "POST /graphql", or an operationKey). */
  endpoint?: string;
  /** Role label the rule applies to. */
  role: string;
  /** Whether that role is expected to be allowed. */
  allow: boolean;
  /** Optional tenant scope the rule is bound to. */
  tenant?: string;
  /** Free-text basis ("B is a non-owner", "admin reaches everything"). */
  note?: string;
}

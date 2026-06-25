// @veritas/scanner — Phase2: 汎用 validator カタログ + 証拠規律。

export type { HttpClient, HttpRequest, HttpResponse, FetchHttpClientOptions, FakeResponder } from "./http.js";
export { FetchHttpClient, FakeHttpClient } from "./http.js";

export { EvidenceStore, readEvidenceArtifact } from "./evidence.js";
export type { EvidenceInput, EvidenceRecord, EvidenceKind, EvidenceArtifact } from "./evidence.js";

export { runValidator, makeTarget, concretizeApiUrl } from "./validator.js";
export type {
  Validator,
  ScanTarget,
  Probe,
  ProbeEval,
  ProbeStatus,
  ProbeOutcome,
  RunOptions,
} from "./validator.js";

export { CATALOG } from "./catalog.js";
export { exposedFile } from "./validators/exposed-file.js";
export { authRequired } from "./validators/auth-required.js";
export { corsMisconfig } from "./validators/cors.js";

export { scanScreen, scanInventory } from "./scan.js";
export type { ScanScreenResult, ScanInventoryHooks, ScanInventoryResult } from "./scan.js";

export { SECURITY_HEADERS, auditHeaders } from "./headers.js";
export type { HeaderRule } from "./headers.js";

export { parseBurpReport, burpSeverity, coarseCategory } from "./burp.js";
export type { BurpIssue } from "./burp.js";
export { startBurpScan, getBurpScan, restIssuesToBurpIssues, pickBurpConfigs, dedupSeedUrls } from "./burp-rest.js";
export type { BurpScanRequest, BurpScanStatus } from "./burp-rest.js";
export { mergeBurpIssues } from "./burp-merge.js";
export type { MergeBurpOptions, MergeBurpResult } from "./burp-merge.js";
export { submitAudit, getAuditStatusAll, getAuditIssues, resetAudit, auditIssuesToBurpIssues, buildRawRequest } from "./burp-audit.js";
export type { BurpAuditConn, AuditSubmit, AuditHostStatus } from "./burp-audit.js";
export { oobStatus, oobPayload, oobPoll } from "./burp-oob.js";
export type { OobInteraction } from "./burp-oob.js";

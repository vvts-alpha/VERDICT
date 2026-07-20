// @veritas/asr — Attack Surface Recon. Design source of truth: docs/ASR.md.
//
// A one-shot recon phase to the *left* of `survey`: a wildcard / root domain -> discover assets -> map their
// surface lightly -> score them as attack targets -> hand the prioritized list to `pilot`. Wide-shallow triage
// that feeds VERDICT's deep-narrow assessment. NOT "attack surface management" (no continuous monitoring).
//
// P0 lands in slices; this file re-exports each module as it arrives.
export * from "./discovery.js";
export * from "./sources.js";
export * from "./import.js";
export * from "./run-tool.js";
export * from "./tools.js";
export * from "./promote.js";
export * from "./probe.js";
export * from "./surface.js";
export * from "./listing.js";
export * from "./takeover.js";
export * from "./findings.js";
export * from "./score.js";
export * from "./triage.js";
export * from "./io.js";

// Static DOM-XSS sink analysis for first-party JS bundles (used by analyze_js).
//
// Two stages, hybrid by design:
//   1. REGEX PRE-FILTER (scanJsSinks) — cheap, high-recall: locate dangerous sinks (innerHTML/eval/document.write/…)
//      and note whether a taint SOURCE (location.hash/search, referrer, window.name, postMessage, …) sits near each.
//      Minified framework code uses innerHTML heavily, so a sink ALONE is mostly noise; a sink WITH a nearby source
//      is the real signal. We keep every high-danger sink (eval/Function/document.write) but require a nearby source
//      for the noisy ones (innerHTML/.html()).
//   2. LLM REFINEMENT (aiRefineSinks) — precision: hand only the small candidate SLICES (never the whole minified
//      bundle) to the model, which reasons about the local source→sink dataflow, deobfuscates a little, and returns
//      structured candidates with a confidence + a route hint. Falls back to the regex verdict if no LLM is available
//      or the model output doesn't parse.
//
// Output = JsSink[] LEADS. They are NEVER auto-confirmed: DOM XSS is confirmed only at runtime by probe_dom_xss
// executing a payload in a real browser (evidence discipline). The route hints feed exactly that.

import type { LlmClient } from "@veritas/llm";
import { extractJson } from "@veritas/llm";
import { z } from "zod";
import type { JsSink } from "@veritas/core";

/** A dangerous DOM sink: a string that becomes live HTML, executable code, or a navigation. */
const SINKS: { name: string; re: RegExp; danger: "high" | "med" }[] = [
  { name: "innerHTML", re: /\.innerHTML\s*=|\[\s*["']innerHTML["']\s*\]\s*=/g, danger: "med" },
  { name: "outerHTML", re: /\.outerHTML\s*=/g, danger: "med" },
  { name: "insertAdjacentHTML", re: /insertAdjacentHTML\s*\(/g, danger: "med" },
  { name: "document.write", re: /document\s*\.\s*write(?:ln)?\s*\(/g, danger: "high" },
  { name: "srcdoc", re: /\.srcdoc\s*=/g, danger: "med" },
  { name: "eval", re: /\beval\s*\(/g, danger: "high" },
  { name: "Function", re: /\bnew\s+Function\s*\(|[^.\w]Function\s*\(/g, danger: "high" },
  { name: "setTimeout(string)", re: /set(?:Timeout|Interval)\s*\(\s*["'`]/g, danger: "high" },
  { name: "jQuery.html", re: /\.html\s*\(\s*[^)\s]/g, danger: "med" },
  { name: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML/g, danger: "med" },
  // Angular's DomSanitizer bypass — never framework-internal, it is app code deliberately trusting raw HTML/URL
  // (the canonical Angular DOM-XSS sink, e.g. Juice Shop's search). Always high-danger.
  { name: "bypassSecurityTrust", re: /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(/g, danger: "high" },
  { name: "location", re: /\blocation\s*\.\s*(?:href|assign|replace)\s*[=(]|[^.\w]location\s*=[^=]/g, danger: "med" },
  { name: "window.open", re: /window\s*\.\s*open\s*\(/g, danger: "med" },
  { name: "setAttribute(danger)", re: /setAttribute\s*\(\s*["'](?:src|href|on\w+|srcdoc|formaction)["']/gi, danger: "med" },
];

/** A taint SOURCE: attacker/user-controllable input a DOM-XSS flows from.
 *  NOTE: no `g` flag — these are used only with .test(), and a global regex's .test() advances lastIndex
 *  (stateful across calls). matchAll (used for SINKS) needs `g` but does not mutate the original's lastIndex. */
const SOURCES: { name: string; re: RegExp }[] = [
  { name: "location.hash", re: /location\s*\.\s*hash/ },
  { name: "location.search", re: /location\s*\.\s*search/ },
  { name: "location.href", re: /location\s*\.\s*href/ },
  { name: "document.URL", re: /document\s*\.\s*(?:URL|documentURI|baseURI)/ },
  { name: "document.referrer", re: /document\s*\.\s*referrer/ },
  { name: "window.name", re: /window\s*\.\s*name/ },
  { name: "document.cookie", re: /document\s*\.\s*cookie/ },
  { name: "postMessage", re: /addEventListener\s*\(\s*["']message["']|\.onmessage\s*=/ },
  { name: "URLSearchParams", re: /URLSearchParams|new\s+URL\s*\(/ },
  { name: "route-param", re: /ActivatedRoute|route\.snapshot|this\.\$route|useParams\s*\(|useSearchParams\s*\(/ },
];

const WINDOW = 160; // chars of context extracted around a sink for the snippet
const SOURCE_RADIUS = 500; // how far around a sink a source still counts as "near"
const MAX_SCAN = 200; // safety ceiling on total slices from ONE bundle (priority-sorted; a truncation is surfaced, never silent)
const AI_BATCH = 30; // slices per LLM refinement call — ALL slices are analyzed, in batches (no candidate is dropped un-assessed)

/** One regex-located sink occurrence, with local context. */
export interface RawSinkHit {
  sink: string;
  danger: "high" | "med";
  snippet: string;
  /** a taint source found within SOURCE_RADIUS of this sink, if any */
  nearSource?: string;
}

const norm = (s: string): string => s.replace(/\s+/g, " ").trim();

/**
 * Regex pre-filter: return the candidate sink hits in a bundle body (no LLM). We do NOT drop hits on a dumb heuristic
 * (a source-less sink is kept — the LLM, not a regex, decides what is real); dedup of identical slices is the only
 * removal. Prioritized (nearby source first, then high-danger) so that IF the safety ceiling truncates a pathological
 * bundle, the most promising slices survive — and the truncation is surfaced to the caller, never silent.
 */
export function scanJsSinks(body: string): RawSinkHit[] {
  if (!body) return [];
  const hits: RawSinkHit[] = [];
  const seen = new Set<string>();
  for (const s of SINKS) {
    for (const m of body.matchAll(s.re)) {
      const at = m.index ?? 0;
      const from = Math.max(0, at - WINDOW);
      const snippet = norm(body.slice(from, at + WINDOW));
      const dedup = `${s.name}:${snippet.slice(0, 90)}`;
      if (seen.has(dedup)) continue;
      // is a taint source near this sink? (a PRIORITY signal, not a filter — source-less sinks are still kept)
      const ctx = body.slice(Math.max(0, at - SOURCE_RADIUS), at + SOURCE_RADIUS);
      let nearSource: string | undefined;
      for (const src of SOURCES)
        if (src.re.test(ctx)) {
          nearSource = src.name;
          break;
        }
      seen.add(dedup);
      hits.push({ sink: s.name, danger: s.danger, snippet: snippet.slice(0, 220), ...(nearSource ? { nearSource } : {}) });
    }
  }
  // prioritize: has a nearby source first, then high-danger, then the rest (matters only if the ceiling truncates).
  hits.sort((a, b) => Number(!!b.nearSource) - Number(!!a.nearSource) || (b.danger === "high" ? 1 : 0) - (a.danger === "high" ? 1 : 0));
  return hits.slice(0, MAX_SCAN);
}

/** Convert a raw regex hit to a JsSink lead (the no-LLM fallback verdict). */
function rawToSink(h: RawSinkHit): JsSink {
  return {
    sink: h.sink,
    ...(h.nearSource ? { source: h.nearSource } : {}),
    snippet: h.snippet,
    confidence: h.nearSource ? "medium" : "low",
    rationale: h.nearSource
      ? `sink '${h.sink}' with taint source '${h.nearSource}' nearby (regex only — not dataflow-verified)`
      : `dangerous sink '${h.sink}' present (regex only — no user-controlled source proven near it)`,
    ai: false,
  };
}

const AiCand = z.object({
  index: z.number().int().nonnegative(),
  isCandidate: z.boolean(),
  source: z.string().nullish(),
  confidence: z.enum(["high", "medium", "low"]),
  rationale: z.string().min(1),
  routeHint: z.string().nullish(),
});
const AiOut = z.object({ candidates: z.array(AiCand) });

const SYSTEM =
  "You are a web security auditor reviewing FIRST-PARTY JavaScript for DOM-based XSS. You are given code slices, each around a dangerous sink. Decide, per slice, whether attacker-controllable input (URL hash/query, document.referrer, window.name, postMessage data, cookies, SPA route params) can reach the sink WITHOUT proper sanitization/encoding. Ignore framework-internal or clearly-safe uses (constant strings, values that are escaped/encoded, trusted config). One exception: an EXPLICIT sanitizer bypass (Angular bypassSecurityTrustHtml/Url/etc., React dangerouslySetInnerHTML, eval/new Function) is app code deliberately opting out of XSS protection — treat it as a candidate (at least low/medium) unless the argument is plainly a hardcoded constant, even when you cannot see the source in the slice; note in the rationale that the source should be confirmed. Be precise otherwise — a false candidate wastes the operator's time. Reply with JSON only.";

/** LLM refinement over the regex slices → precise JsSink candidates. Falls back to rawToSink on any failure. */
export async function aiRefineSinks(llm: LlmClient, bundleUrl: string, hits: RawSinkHit[]): Promise<JsSink[]> {
  if (hits.length === 0) return [];
  const list = hits.map((h, i) => `#${i} sink=${h.sink}${h.nearSource ? ` nearSource=${h.nearSource}` : ""}\n   ${h.snippet}`).join("\n");
  const prompt = `Bundle: ${bundleUrl}\nEach entry is a code slice around a sink. For EACH index, return an object {index, isCandidate, source, confidence, rationale, routeHint}. isCandidate=true only for a real DOM-XSS where a user-controllable source reaches the sink unsanitized. source = the taint source (or null). confidence = high|medium|low. rationale = one short line. routeHint = a URL path/hash that would trigger it (e.g. "#/search?q={{XSS}}") or null. Return {"candidates":[...]} covering every index.\n\n${list}`;
  try {
    const res = await llm.complete({ system: SYSTEM, prompt, timeoutMs: 60000 });
    const parsed = AiOut.safeParse(extractJson(res.text));
    if (!parsed.success) return hits.map(rawToSink);
    const byIdx = new Map(parsed.data.candidates.map((c) => [c.index, c]));
    const out: JsSink[] = [];
    hits.forEach((h, i) => {
      const c = byIdx.get(i);
      if (!c) {
        // the model skipped this slice — keep it as a low-confidence regex lead so nothing is silently dropped
        out.push(rawToSink(h));
        return;
      }
      if (!c.isCandidate) return; // the model cleared it (framework-safe / sanitized)
      out.push({
        sink: h.sink,
        ...(c.source ? { source: c.source } : h.nearSource ? { source: h.nearSource } : {}),
        snippet: h.snippet,
        confidence: c.confidence,
        rationale: c.rationale.slice(0, 200),
        ...(c.routeHint ? { routeHint: c.routeHint.slice(0, 120) } : {}),
        ai: true,
      });
    });
    return out;
  } catch {
    return hits.map(rawToSink);
  }
}

export interface JsSinkAnalysis {
  sinks: JsSink[];
  /** total sink slices the regex found (before the LLM cleared any) — so the caller can report true coverage */
  scanned: number;
  /** true if the bundle had more sinks than the safety ceiling (MAX_SCAN) and the tail was not analyzed */
  truncated: boolean;
}

/**
 * Analyze one bundle body for DOM-XSS sink candidates. The regex pre-filter always runs; when an LLM is supplied,
 * EVERY slice is refined (in batches — nothing is dropped un-assessed), otherwise the regex verdict is returned for
 * all of them. Best-effort — a failed batch degrades to its regex leads, never throws.
 */
export async function analyzeJsSinksFull(llm: LlmClient | undefined, bundleUrl: string, body: string): Promise<JsSinkAnalysis> {
  const hits = scanJsSinks(body);
  const truncated = hits.length >= MAX_SCAN;
  if (hits.length === 0) return { sinks: [], scanned: 0, truncated };
  if (!llm) return { sinks: hits.map(rawToSink), scanned: hits.length, truncated };
  const sinks: JsSink[] = [];
  for (let i = 0; i < hits.length; i += AI_BATCH) sinks.push(...(await aiRefineSinks(llm, bundleUrl, hits.slice(i, i + AI_BATCH))));
  return { sinks, scanned: hits.length, truncated };
}

/** Back-compat convenience: just the candidate list. */
export async function analyzeJsSinks(llm: LlmClient | undefined, bundleUrl: string, body: string): Promise<JsSink[]> {
  return (await analyzeJsSinksFull(llm, bundleUrl, body)).sinks;
}

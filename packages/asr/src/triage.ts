// ASR ④ AI triage (P1) — Claude classifies a discovered host as an attack target: category / band / rationale /
// first attack-angle. A LEAD, never a finding (confirmed vulns stay in pilot's evidence discipline). Runs on the
// top-N by deterministic score to bound LLM cost; opt-in via `asr --triage`. Uses the claude CLI subscription (no
// metered API) at runtime; tests use FakeLlmClient.

import type { Asset, AssetBand, AssetTriage } from "@veritas/core";
import { extractJson, type LlmClient } from "@veritas/llm";

const BANDS: readonly AssetBand[] = ["critical", "high", "medium", "low"];

function coerceBand(v: unknown, fallback: AssetBand): AssetBand {
    return typeof v === "string" && (BANDS as readonly string[]).includes(v) ? (v as AssetBand) : fallback;
}
function str(v: unknown, max: number, fallback = ""): string {
    return typeof v === "string" && v.trim().length > 0 ? v.trim().slice(0, max) : fallback;
}

const TRIAGE_SYSTEM =
    "You are an attack-surface recon triage assistant. You classify a single discovered host as an ATTACK TARGET " +
    "for an authorized security assessment. This is prioritization / a lead — never a vulnerability finding. " +
    "Answer with ONLY a JSON object, no prose.";

/** The per-host bundle handed to the model (deterministic signals + score). */
export function buildTriagePrompt(asset: Asset): string {
    const paths = (asset.notablePaths ?? []).map((h) => `${h.path} (${h.note})`).join(", ") || "none";
    const comp = asset.score ? Object.entries(asset.score.components).map(([k, v]) => `${k}=${v}`).join(" ") : "n/a";
    return [
        `host: ${asset.host}`,
        `http: ${asset.scheme ?? "?"} status=${asset.status ?? "?"} title=${JSON.stringify(asset.title)}`,
        `tech: ${asset.tech.join(", ") || "unknown"}`,
        `notable paths: ${paths}`,
        `deterministic score: ${asset.score?.total ?? 0} (${asset.score?.band ?? "low"}) [${comp}]`,
        "",
        "Return exactly this JSON shape:",
        '{"category":"login|api|admin|staging|internal-tool|marketing|parked|other","band":"critical|high|medium|low","rationale":"one sentence","angle":"first concrete thing to try, or empty"}',
    ].join("\n");
}

/** Ask the model to triage one asset. Returns null if the output can't be parsed into a triage. */
export async function triageAsset(asset: Asset, llm: LlmClient, model?: string): Promise<AssetTriage | null> {
    const res = await llm.complete({
        system: TRIAGE_SYSTEM,
        prompt: buildTriagePrompt(asset),
        timeoutMs: 60_000,
        ...(model ? { model } : {}),
    });
    let parsed: unknown;
    try {
        parsed = extractJson(res.text);
    } catch {
        return null; // the model didn't return JSON
    }
    if (parsed === null || typeof parsed !== "object") return null;
    const o = parsed as Record<string, unknown>;
    return {
        category: str(o.category, 40, "other"),
        band: coerceBand(o.band, asset.score?.band ?? "low"),
        rationale: str(o.rationale, 300),
        angle: str(o.angle, 300),
    };
}

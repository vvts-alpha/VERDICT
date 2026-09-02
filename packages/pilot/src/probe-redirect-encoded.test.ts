// probe_redirect against a base64-wrapped return-URL param (the SSO_ORIG_URI shape): a plaintext payload would be
// base64-decoded to garbage and never redirect — the probe must re-encode the OOB host to reach the sink.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";

const BASE = "https://app.test/";
type Req = { url: string; headers?: Record<string, string>; body?: string | null };
type Res = { status: number; finalUrl: string; durationMs: number; headers: Record<string, string>; body: string };

function fakeSession(dir: string, send: (req: Req) => Promise<Res>): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(BASE), targetUrl: BASE, currentScreenId: "s-1", currentCookie: "", currentBearer: "",
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
  } as unknown as PilotSession;
}
async function callTool(dir: string, name: string, args: Record<string, unknown>, send: (req: Req) => Promise<Res>): Promise<Record<string, unknown>> {
  const s = fakeSession(dir, send);
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = await t.handler(args, {});
  (s as unknown as { store: AssessmentStore }).store.close();
  return JSON.parse(out.content[0]!.text);
}

test("probe_redirect confirms an open redirect hidden behind a base64-wrapped SSO_ORIG_URI param", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-redir-"));
  try {
    // The app base64-DECODES the return-URL param and 302s there — so only a base64-wrapped payload reaches the sink.
    const send = async (req: Req): Promise<Res> => {
      const v = new URL(req.url).searchParams.get("SSO_ORIG_URI") ?? "";
      let target = "";
      try { target = Buffer.from(v.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"); } catch { /* not base64 */ }
      return /^https?:\/\//.test(target)
        ? { status: 302, finalUrl: req.url, durationMs: 3, headers: { location: target }, body: "" }
        : { status: 200, finalUrl: req.url, durationMs: 3, headers: {}, body: "home" };
    };
    // the param already carries a base64 return URL (as on a real F5/SSO login)
    const seed = Buffer.from("https://app.test/home", "utf8").toString("base64");
    const url = `${BASE}F5Networks-SSO-Req?SSO_ORIG_URI=${encodeURIComponent(seed)}`;
    return callTool(dir, "probe_redirect", { url, param: "SSO_ORIG_URI" }, send).then((r) => {
      assert.ok(r.negativeControl && Array.isArray(r.positiveReplays) && (r.positiveReplays as unknown[]).length === 2, "confirmed the wrapped open redirect");
      assert.match(String(r.effectMarker ?? r.verdict ?? ""), /veritas-oob\.example/);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

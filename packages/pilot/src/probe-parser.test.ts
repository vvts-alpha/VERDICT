// probe_parser: benign malformed-input probes elicit parser-specific errors → backend-lib GUESSES.
// Also covers fingerprint_scan's zero-cost evidence sweep (bodies already in evidence get scanned).
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { EvidenceStore } from "@veritas/scanner";
import type { PilotSession } from "./tools.js";
import { buildTools } from "./tools.js";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";

type Req = { url: string; method?: string; headers?: Record<string, string>; body?: string | null; multipart?: unknown };
type Res = { status: number; finalUrl: string; durationMs: number; headers: Record<string, string>; body: string; truncated?: boolean };
type Tool = { name: string; handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
const fixtureStores = new Map<string, AssessmentStore>();

function fakeSession(dir: string, send: (req: Req) => Promise<Res>, opts: { base?: string } = {}): PilotSession {
  const base = opts.base ?? "https://app.test/";
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  fixtureStores.set(dir, store);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(base),
    targetUrl: base,
    currentScreenId: "s-1",
    currentCookie: "sid=abc",
    currentBearer: "",
    currentRole: "alice",
    roleCreds: new Map([["alice", { username: "alice", password: "x" }]]),
    roleCookieFiles: new Map(),
    roleDescriptions: new Map(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
    findings: [],
    findingsByKey: new Map(),
    recordCalls: 0,
    findCounter: 0,
  } as unknown as PilotSession;
}

async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as Tool;
  return JSON.parse((await t.handler(args, {})).content[0]!.text) as Record<string, unknown>;
}

async function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "verdict-parser-"));
  try {
    await fn(dir);
  } finally {
    fixtureStores.get(dir)?.close();
    fixtureStores.delete(dir);
    rmSync(dir, { recursive: true, force: true });
  }
}

test("probe_parser elicits parser errors and names the backend library guess", async () => {
  await withDir(async (dir) => {
    const sent: Req[] = [];
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      sent.push(req);
      // The fake "server" runs Pillow: corrupt images crash into UnidentifiedImageError.
      return { status: 400, finalUrl: req.url, durationMs: 1, headers: {}, body: `{"detail":"PIL.UnidentifiedImageError: cannot identify image file"}` };
    });
    const out = await run(s, "probe_parser", { urls: ["https://app.test/upload/avatar"] });
    const results = out.results as Array<{ url: string; sends: Array<{ tag: string; status: number; evidenceId: string; libs: string[] }>; libs: Array<{ name: string; version: string | null }> }>;
    assert.equal(results.length, 1);
    const r = results[0]!;
    assert.equal(r.sends.length, 6, `expected 6 malformed probes, got ${r.sends.length}`);
    assert.ok(r.sends.every((x) => x.evidenceId), "every send must be recorded as evidence");
    assert.ok(r.libs.some((l) => l.name === "Pillow (PIL)"), `expected Pillow guess, got ${r.libs.map((l) => l.name)}`);
    // Multipart uploads only — the elicitors never carry exploit payloads.
    assert.ok(sent.every((q) => q.method === "POST" && q.multipart), "every probe is a multipart POST");
    assert.equal(sent.length, 6);
  });
});

test("probe_parser refuses non-upload paths without force and honors the scope gate", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => ({ status: 200, finalUrl: req.url, durationMs: 1, headers: {}, body: "ok" }));
    const out = await run(s, "probe_parser", { urls: ["https://app.test/api/users", "https://evil.test/x"] });
    const results = out.results as Array<{ url: string; note?: string }>;
    assert.match(results[0]!.note ?? "", /file-processing endpoint/);
    assert.equal(results[1]!.note, "out of scope");
  });
});

test("fingerprint_scan sweeps already-recorded evidence bodies for backend-lib guesses", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => ({
      status: 200,
      finalUrl: req.url,
      durationMs: 1,
      headers: { server: "nginx/1.24.0" },
      body: "<html><body>ok</body></html>",
    }));
    // An earlier probe recorded an error body that leaked the YAML stack — no new send needed.
    s.evidence.record({
      screenId: "s-1",
      validator: "claude-pilot-sqli",
      kind: "positive_replay",
      request: { method: "POST", url: "https://app.test/import", headers: {}, body: "x" },
      response: { status: 500, finalUrl: "https://app.test/import", headers: {}, durationMs: 1, truncated: false, bodyBytes: 80, body: "org.yaml.snakeyaml.error.YAMLException: at org.yaml.snakeyaml-1.33.jar" },
      note: "earlier probe",
    });
    const out = await run(s, "fingerprint_scan", { urls: ["https://app.test/"] });
    const libs = out.backendLibs as Array<{ name: string; version: string | null; evidenceRef?: string }>;
    assert.ok(libs.some((l) => l.name.toLowerCase() === "snakeyaml" && l.version === "1.33"), `expected snakeyaml 1.33 from evidence sweep, got ${libs.map((l) => `${l.name}@${l.version}`)}`);
    assert.ok(libs.some((l) => l.evidenceRef), "evidence-swept libs carry the source evidence id");
    const comps = out.components as Array<{ name: string }>;
    assert.ok(comps.some((c) => c.name === "nginx"), "front tech still extracted");
    const hints = out.backendLibHints as string[];
    assert.ok(hints.some((h) => /YAML/i.test(h)), "yaml unsafe-load hint surfaced");
  });
});

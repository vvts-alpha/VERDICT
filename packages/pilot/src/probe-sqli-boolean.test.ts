// Boolean SQLi oracle: Drupal/marketing HTML length is not confirmation; JSON extra rows still are.
// Valero GET /search?search= was High-confirmed off ~120 B of HTML chrome between unmatched TRUE/FALSE strings.
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

function fakeSession(dir: string, send: (req: { url: string }) => Promise<unknown>): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  const http = { send, effectiveHeaders: (h: Record<string, string>) => h };
  return {
    http,
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(BASE),
    targetUrl: BASE,
    currentScreenId: "s-1",
    currentCookie: "",
    currentBearer: "",
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
  } as unknown as PilotSession;
}

async function callTool(dir: string, name: string, args: Record<string, unknown>, send: (req: { url: string }) => Promise<unknown>): Promise<Record<string, unknown>> {
  const s = fakeSession(dir, send);
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = await t.handler(args, {});
  (s as unknown as { store: AssessmentStore }).store.close();
  return JSON.parse(out.content[0]!.text);
}

function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-sqli-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const q = (url: string): string => {
  try {
    return new URL(url).searchParams.get("search") ?? "";
  } catch {
    return "";
  }
};

test("probe_sqli does NOT confirm boolean SQLi on a Drupal HTML search page (Valero-shaped ~120 B delta)", async () => {
  await withDir(async (dir) => {
    const chrome = `<!DOCTYPE html><html lang="en"><head><title>Search | Valero</title></head><body class="path-search">` + "n".repeat(32000);
    const send = async (req: { url: string }) => {
      const s = q(req.url);
      const echo = `<h1>Search</h1><div class="search-results">Results for ${s}</div>`;
      // FALSE tautology pages were slightly LONGER (the Valero artifact); TRUE / benign share a shorter chrome.
      const extra = /1='2|1=2/.test(s) ? "y".repeat(120) : "";
      return { status: 200, finalUrl: req.url, durationMs: 4, headers: {}, body: chrome + echo + extra + "</body></html>" };
    };
    const out = await callTool(dir, "probe_sqli", { url: BASE + "search", param: "search" }, send);
    assert.notEqual(out.technique, "boolean");
    assert.match(String(out.verdict), /HTML|not confirmed|Drupal|search/i);
    assert.ok(!/CONFIRMED/i.test(String(out.verdict)) || /not confirmed/i.test(String(out.verdict)));
  });
});

test("probe_sqli CONFIRMS boolean SQLi on a JSON search API (Juice Shop-shaped extra rows)", async () => {
  await withDir(async (dir) => {
    const send = async (req: { url: string }) => {
      const s = q(req.url);
      const tautology = /1='1|OR 1=1|\('1'='1/i.test(s);
      const contradiction = /1='2|OR 1=2|\('1'='2/i.test(s);
      let body: string;
      if (tautology) body = JSON.stringify({ status: "success", data: Array.from({ length: 36 }, (_, i) => ({ id: i, name: "Apple Juice (1000ml) extra row" })) });
      else if (contradiction) body = JSON.stringify({ status: "success", data: [] });
      else body = JSON.stringify({ status: "success", data: [{ id: 1, name: "Apple Juice (500ml)" }] });
      return { status: 200, finalUrl: req.url, durationMs: 3, headers: { "content-type": "application/json" }, body };
    };
    const out = await callTool(dir, "probe_sqli", { url: BASE + "search", param: "search" }, send);
    assert.equal(out.technique, "boolean");
    assert.match(String(out.verdict), /CONFIRMED/);
    assert.ok(Array.isArray(out.positiveReplays) && (out.positiveReplays as unknown[]).length === 2);
  });
});

test("probe_sqli still confirms TIME-BASED blind SQLi when the body is HTML (length is not the oracle)", async () => {
  await withDir(async (dir) => {
    const page = `<!DOCTYPE html><html><body>${"x".repeat(8000)}search</body></html>`;
    const send = async (req: { url: string }) => {
      const s = q(req.url);
      const slow = /SLEEP\(5\)|pg_sleep|WAITFOR/i.test(s);
      return { status: 200, finalUrl: req.url, durationMs: slow ? 5200 : 5, headers: {}, body: page };
    };
    const out = await callTool(dir, "probe_sqli", { url: BASE + "search", param: "search" }, send);
    assert.equal(out.technique, "time-based");
    assert.match(String(out.verdict), /BLIND SQLi CONFIRMED/i);
  });
});

// Out-of-scope landing + frontier residue (the a-mvor6nuu survey_done deadlock): a navigation that
// bounces OFF-TARGET (open redirect / affiliate hop) must not enroll the external page, and the
// requested URL must not stay pending in the frontier forever — else unionFrontier never empties and
// survey_done can never pass.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { FakeDriver, InventoryBuilder } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";

const base = "http://app.test/";
const dir = mkdtempSync(join(tmpdir(), "veritas-oos-"));
let dbN = 0;
after(() => rmSync(dir, { recursive: true, force: true }));

function session(site: Record<string, Partial<import("@veritas/crawler").Observation>>): PilotSession {
  const store = AssessmentStore.open(join(dir, `s${dbN++}.sqlite`));
  const scope = deriveScopeFromSingleUrl(base);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope });
  const driver = Object.assign(new FakeDriver(site), { saveScreenshot: async () => false });
  return {
    driver,
    http: new FetchHttpClient({ allow: () => true }),
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, `art-${dbN}`)),
    inv: new InventoryBuilder(),
    scope,
    targetUrl: base,
    artifactsDir: dir,
    currentScreenId: "s-1",
    currentCookie: "sess=alice",
    currentBearer: "",
    currentRole: "alice",
    roleCreds: new Map(),
    roleCookieFiles: new Map(),
    roleDescriptions: new Map(),
    roleNames: new Set(["alice"]),
    visited: new Set<string>(),
    frontier: new Set<string>(),
    refererGated: new Set<string>(),
    visitedByRole: new Map<string, Set<string>>(),
    roleSurveyCounts: new Map<string, number>(),
    roleLoginAttempts: new Map<string, number>(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
  } as unknown as PilotSession;
}

async function call(s: PilotSession, name: string, args: Record<string, unknown>): Promise<string> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  return (await t.handler(args, {})).content[0]!.text;
}
const close = (s: PilotSession): void => (s as unknown as { store: { close(): void } }).store.close();

test("open-redirect hop landing out of scope: not enrolled, frontier cleared, hop marked navigated", async () => {
  const ext = "https://evil.example/landing";
  const s = session({
    [`${base}redirect?to=${encodeURIComponent(ext)}`]: {
      finalUrl: ext,
      visibleText: "Totally external page",
      links: [`${ext}more`, `${ext}deeper`],
    },
  });
  try {
    const hop = `${base}redirect?to=${encodeURIComponent(ext)}`;
    s.frontier.add(hop); // discovered earlier — pending
    const out = await call(s, "browser_navigate", { url: hop });
    const r = JSON.parse(out);
    assert.equal(r.outOfScope, true);
    assert.equal(r.finalUrl, ext);
    assert.equal(s.inv.screens().length, 0, "external landing must not be enrolled as a screen");
    assert.equal(s.frontier.has(hop), false, "requested URL cleared from the frontier");
    assert.equal(s.frontier.size, 0, "external links must not seed the frontier");
    assert.ok(s.visited.has(hop), "hop counted as exercised");
    assert.ok(s.navigatedByRole?.get("alice")?.has(hop), "hop recorded as navigated for the role");
  } finally {
    close(s);
  }
});

test("in-scope redirect: requested URL cleared from frontier too (no residue)", async () => {
  const s = session({
    [`${base}old-path`]: { finalUrl: `${base}new-path`, visibleText: "The new path" },
  });
  try {
    s.frontier.add(`${base}old-path`);
    const out = await call(s, "browser_navigate", { url: `${base}old-path` });
    const r = JSON.parse(out);
    assert.equal(r.finalUrl, `${base}new-path`);
    assert.equal(s.frontier.has(`${base}old-path`), false, "requested URL must not stay pending");
    assert.equal(s.visited.has(`${base}old-path`), true);
    assert.equal(s.inv.screens().length, 1);
  } finally {
    close(s);
  }
});

test("survey_done passes after an out-of-scope hop — no frontier deadlock", async () => {
  const ext = "https://evil.example/x";
  const s = session({
    [`${base}redirect?to=${encodeURIComponent(ext)}`]: { finalUrl: ext, visibleText: "external" },
    [`${base}home`]: { visibleText: "Welcome home" },
  });
  try {
    (s.roleLoginAttempts ??= new Map()).set("alice", 1); // tried-but-unmapped passes the auth gate with a warning
    await call(s, "browser_navigate", { url: `${base}home` });
    await call(s, "browser_navigate", { url: `${base}redirect?to=${encodeURIComponent(ext)}` });
    const done = await call(s, "survey_done", { summary: "all mapped" });
    assert.match(done, /survey complete/);
    assert.equal(s.surveyDone, true);
  } finally {
    close(s);
  }
});

test("survey_done ignores pending entries the role already navigated (persisted bookkeeping drift)", async () => {
  const s = session({
    [`${base}home`]: { visibleText: "Welcome home" },
  });
  try {
    (s.roleLoginAttempts ??= new Map()).set("alice", 1);
    await call(s, "browser_navigate", { url: `${base}home` });
    // Drift: a URL the role navigated stays in pending (e.g. restored from a pre-fix progress event).
    const stale = `${base}redirect?to=https%3A%2F%2Fevil.example%2F`;
    s.frontier.add(stale);
    s.navigatedByRole = new Map([["alice", new Set([`${base}home`, stale])]]);
    const done = await call(s, "survey_done", { summary: "drift cleared" });
    assert.match(done, /survey complete/, `expected survey_done to pass, got: ${done.slice(0, 160)}`);
  } finally {
    close(s);
  }
});

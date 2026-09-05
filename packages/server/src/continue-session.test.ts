import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { continueSession, SessionContinuationError } from "./continue-session.js";

function fixture(t: { after(fn: () => void): void }) {
  const root = mkdtempSync(join(tmpdir(), "verdict-continue-"));
  mkdirSync(join(root, "run"));
  const store = AssessmentStore.open(join(root, "run", "state.sqlite"));
  const scope = deriveScopeFromSingleUrl("https://app.test");
  store.createAssessment({ id: "run", target: { kind: "single_url", url: "https://app.test", followLinks: true, maxDepth: 1 }, scope });
  store.upsertHandoff("run", { id: "login", reason: "auth", url: "https://app.test/login", status: "pending", message: "login", createdAt: new Date().toISOString(), resolvedAt: null });
  store.setPaused("run", true, "login");
  const capture = join(root, "session.json");
  writeFileSync(capture, JSON.stringify({ cookies: [{ name: "sid", value: "test", domain: "app.test", path: "/" }], origins: [] }));
  t.after(() => { store.close(); rmSync(root, { recursive: true, force: true }); });
  return { root, store, capture, scope };
}

test("active login continuation queues auth and unpauses without spawning twice", (t) => {
  const f = fixture(t);
  const result = continueSession(f.root, "run", { cookieFile: f.capture, handoffId: "login" }, f.store, { isRunning: () => true, resume: () => assert.fail("must not respawn") });
  assert.equal(result.action, "injected");
  assert.equal(f.store.controlCommandsSince("run", 0)[0]?.cmd.injectCookieFile, f.capture);
  assert.equal(f.store.isPaused("run"), false);
  assert.equal(f.store.loadAssessment("run")?.handoffs[0]?.status, "resolved");
});

test("stopped login continuation saves fresh auth before restart and preserves scope and other roles", (t) => {
  const f = fixture(t);
  const manifest = { target: "https://app.test", scope: f.scope, http: { headers: { "X-Tenant": "demo" } }, auth: { roles: [{ name: "user", cookieFile: "old.json" }, { name: "admin", cookieFile: "admin.json" }] } };
  const path = join(f.root, "run", "manifest.json");
  writeFileSync(path, JSON.stringify(manifest));
  let restarted = 0;
  const supervisor = { isRunning: () => false, resume: () => {
    const saved = JSON.parse(readFileSync(path, "utf8"));
    assert.equal(saved.auth.roles[0].cookieFile, f.capture);
    assert.equal(saved.auth.roles[1].cookieFile, "admin.json");
    assert.deepEqual(saved.scope, f.scope);
    assert.deepEqual(saved.http, manifest.http);
    restarted++;
  } };
  assert.throws(() => continueSession(f.root, "run", { cookieFile: f.capture }, f.store, supervisor), (e: unknown) => e instanceof SessionContinuationError && e.roles?.length === 2);
  assert.equal(restarted, 0);
  const result = continueSession(f.root, "run", { cookieFile: f.capture, role: "user", handoffId: "login" }, f.store, supervisor);
  assert.equal(result.action, "restarted");
  assert.equal(restarted, 1);
});

test("continuation rejects empty captures, outside files, and non-auth handoffs", (t) => {
  const f = fixture(t);
  const supervisor = { isRunning: () => false, resume: () => assert.fail("must not restart") };
  writeFileSync(f.capture, "{}");
  assert.throws(() => continueSession(f.root, "run", { cookieFile: f.capture }, f.store, supervisor), /non-empty/);
  const outside = mkdtempSync(join(tmpdir(), "verdict-outside-"));
  t.after(() => rmSync(outside, { recursive: true, force: true }));
  writeFileSync(join(outside, "capture.json"), '{"cookies":[{}]}');
  symlinkSync(join(outside, "capture.json"), join(f.root, "link.json"));
  assert.throws(() => continueSession(f.root, "run", { cookieFile: join(f.root, "link.json") }, f.store, supervisor), /inside/);
  writeFileSync(f.capture, '{"cookies":[{}]}');
  f.store.upsertHandoff("run", { id: "approval", reason: "approval", url: null, status: "pending", message: "approval", createdAt: new Date().toISOString(), resolvedAt: null });
  assert.throws(() => continueSession(f.root, "run", { cookieFile: f.capture, handoffId: "approval" }, f.store, supervisor), /not a login/);
});

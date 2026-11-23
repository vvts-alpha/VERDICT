import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { startServer } from "./index.js";
import { UsersDb } from "./users-db.js";
import { hashPassword } from "./passwords.js";

const PW = { alice: "pw-alice-longenough", bob: "pw-bob-longenough" };

async function multiUserRig() {
  const runsDir = mkdtempSync(join(tmpdir(), "verdict-launch-runs-"));
  const dbDir = mkdtempSync(join(tmpdir(), "verdict-launch-db-"));
  const cliDir = mkdtempSync(join(tmpdir(), "verdict-launch-cli-"));
  const fakeCli = join(cliDir, "fake-cli.js");
  writeFileSync(fakeCli, "console.log('ok');\n");
  const db = UsersDb.open(join(dbDir, "server.db"));
  const alice = db.createUser({ username: "alice", passwordHash: hashPassword(PW.alice), role: "user" });
  const bob = db.createUser({ username: "bob", passwordHash: hashPassword(PW.bob), role: "user" });
  for (const [id, owner] of [["a-alice", alice.id], ["a-bob", bob.id]] as const) {
    mkdirSync(join(runsDir, id));
    writeFileSync(join(runsDir, id, "attended_session_shop.test.json"), JSON.stringify({ cookies: [{ name: "sid", value: id }] }));
    db.setRunOwner(id, owner);
  }
  const srv = await startServer({ runsDir, usersDb: db, pollMs: 50, runLauncher: { runsDir, cliPath: fakeCli, nodePath: process.execPath } });
  const login = async (username: string, password: string): Promise<string> => {
    const res = await fetch(`${srv.url}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password }) });
    return (res.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
  };
  return {
    srv, runsDir, db, login,
    async close() {
      await srv.close();
      db.close();
      for (const d of [runsDir, dbDir, cliDir]) rmSync(d, { recursive: true, force: true });
    },
  };
}

function launch(url: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(`${url}/api/run`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
}

const manifest = (cookieFile?: string) => ({ target: "https://evil.example/", ...(cookieFile ? { auth: { roles: [{ name: "user", cookieFile }] } } : {}) });

test("multi-user /api/run rejects custom wordlist paths and cookie files outside the caller's runs", async () => {
  const r = await multiUserRig();
  try {
    const cookie = { cookie: await r.login("alice", PW.alice) };
    for (const wordlist of ["/etc/passwd", join(r.runsDir, "a-bob", "manifest.json"), "../../proc/self/environ"]) {
      const res = await launch(r.srv.url, { command: "pilot", manifest: manifest(), options: { wordlist } }, cookie);
      assert.equal(res.status, 400, wordlist);
      assert.match((await res.json() as { error: string }).error, /wordlist must be one of/);
    }
    for (const cookieFile of [join(r.runsDir, "a-bob", "attended_session_shop.test.json"), "/etc/hosts", join(r.runsDir, "a-alice", "..", "a-bob", "attended_session_shop.test.json")]) {
      const res = await launch(r.srv.url, { command: "pilot", manifest: manifest(cookieFile) }, cookie);
      assert.equal(res.status, 400, cookieFile);
    }
    const bad = await launch(r.srv.url, { command: "pilot", manifest: { target: "https://evil.example/", auth: { roles: [{ name: "u", cookie_file_path: "/etc/hosts" }] } } }, cookie);
    assert.equal(bad.status, 400);
    const ok = await launch(r.srv.url, { command: "pilot", manifest: manifest(join(r.runsDir, "a-alice", "attended_session_shop.test.json")), options: { wordlist: "extended" } }, cookie);
    assert.equal(ok.status, 200);
  } finally { await r.close(); }
});

test("multi-user resume and continue-session refuse saved or supplied paths outside the caller's runs", async () => {
  const r = await multiUserRig();
  try {
    const cookie = { cookie: await r.login("alice", PW.alice) };
    writeFileSync(join(r.runsDir, "a-alice", "run.json"), JSON.stringify({ command: "pilot", options: { wordlist: "/etc/passwd" } }));
    const resume = await fetch(`${r.srv.url}/api/run/a-alice/resume`, { method: "POST", headers: cookie });
    assert.equal(resume.status, 400);
    writeFileSync(join(r.runsDir, "a-alice", "run.json"), JSON.stringify({ command: "pilot", options: {} }));
    writeFileSync(join(r.runsDir, "a-alice", "manifest.json"), JSON.stringify(manifest(join(r.runsDir, "a-bob", "attended_session_shop.test.json"))));
    const resumeCookie = await fetch(`${r.srv.url}/api/run/a-alice/resume`, { method: "POST", headers: cookie });
    assert.equal(resumeCookie.status, 400);
    assert.match((await resumeCookie.json() as { error: string }).error, /inside one of your assessment directories/);
    writeFileSync(join(r.runsDir, "a-alice", "manifest.json"), JSON.stringify(manifest()));
    const store = AssessmentStore.open(join(r.runsDir, "a-alice", "state.sqlite"));
    store.createAssessment({ id: "a-alice", target: { kind: "single_url", url: "https://evil.example/", followLinks: true, maxDepth: 1 }, scope: deriveScopeFromSingleUrl("https://evil.example/") });
    store.close();
    const cont = await fetch(`${r.srv.url}/api/assessments/a-alice/continue-session`, {
      method: "POST", headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ cookieFile: join(r.runsDir, "a-bob", "attended_session_shop.test.json") }),
    });
    assert.equal(cont.status, 400);
    assert.match((await cont.json() as { error: string }).error, /inside one of your assessment directories/);
  } finally { await r.close(); }
});

test("single-operator serve accepts only bundled wordlists; the token-gated desktop keeps local paths", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "verdict-launch-single-"));
  const cliPath = join(runsDir, "..", `fake-cli-${process.pid}.js`);
  writeFileSync(cliPath, "console.log('ok');\n");
  const runLauncher = { runsDir, cliPath, nodePath: process.execPath };
  const serve = await startServer({ runsDir, runLauncher });
  const desktop = await startServer({ runsDir, runLauncher, localAuthToken: "launch-secret" });
  try {
    assert.equal((await launch(serve.url, { command: "pilot", manifest: manifest(), options: { wordlist: "/etc/passwd" } })).status, 400);
    assert.equal((await launch(serve.url, { command: "pilot", manifest: manifest("/etc/hosts") })).status, 400);
    assert.equal((await launch(serve.url, { command: "pilot", manifest: manifest(), options: { wordlist: "standard" } })).status, 200);
    assert.equal((await launch(desktop.url, { command: "pilot", manifest: manifest("/etc/hosts"), options: { wordlist: "/etc/hosts" } }, { "x-verdict-token": "launch-secret" })).status, 200);
  } finally {
    await serve.close();
    await desktop.close();
    rmSync(runsDir, { recursive: true, force: true });
    rmSync(cliPath, { force: true });
  }
});

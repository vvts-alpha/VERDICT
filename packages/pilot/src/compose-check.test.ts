import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { InventoryBuilder } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";

// compose_check = the model-built verification tool: legs with per-leg sessions run in order, the
// declared expectations are evaluated deterministically, and ONE ledger row lands under the
// declared checkClass (a raw http_request sequence leaves the plan slot open — this closes it).

let server: Server;
let base = "";
let dir = "";
let dbN = 0;
const seen: { url: string; cookie?: string }[] = [];

before(async () => {
  server = createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    seen.push({ url: u.pathname + u.search, cookie: req.headers.cookie });
    if (u.pathname === "/protected") {
      if (!req.headers.cookie) { res.writeHead(401); res.end("denied"); return; }
      res.writeHead(200); res.end(`{"ok":true,"view":"${u.searchParams.get("view") ?? "self"}"}`);
      return;
    }
    if (u.pathname === "/state") { res.writeHead(200); res.end(`{"note":"verdict-landed-9"}`); return; }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  dir = mkdtempSync(join(tmpdir(), "verdict-compose-"));
});
after(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

function session(extra: Partial<PilotSession> = {}): PilotSession {
  const store = AssessmentStore.open(join(dir, `s${dbN++}.sqlite`));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) });
  return {
    http: new FetchHttpClient({ allow: (url: string) => url.startsWith(base.replace(/\/$/, "")) }),
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, `art-${dbN}`)),
    inv: new InventoryBuilder(),
    scope: deriveScopeFromSingleUrl(base),
    targetUrl: base,
    currentScreenId: "s-0001",
    currentCookie: "sess=victim",
    currentBearer: "",
    currentRole: "userA",
    roleCreds: new Map(),
    roleCookieFiles: new Map(),
    roleDescriptions: new Map(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
    ...extra,
  } as unknown as PilotSession;
}

async function run(s: PilotSession, args: Record<string, unknown>): Promise<{ verdict?: string; checkStatus?: string; evidenceIds?: { control: string[]; attack: string[]; verify: string[] }; reason?: string; raw: string }> {
  const t = buildTools(s).find((x) => x.name === "compose_check")!;
  const content = (await t.handler(args as never, {} as never)).content[0];
  assert.ok(content && content.type === "text");
  const out = content.text;
  try { return { ...JSON.parse(out), raw: out }; } catch { return { raw: out }; }
}

test("matched: denied control + marker-carrying attack/verify legs → ledger 'found' under the declared class", async () => {
  const s = session();
  try {
    const r = await run(s, {
      checkClass: "custom-tamper", target: "GET /protected",
      legs: [
        { kind: "control", method: "GET", url: `${base}protected`, role: "unauth" },
        { kind: "attack", method: "GET", url: `${base}protected?view=victim` },
        { kind: "verify", method: "GET", url: `${base}state` },
      ],
      expect: { controlMustDeny: true, marker: "verdict-landed-9", markerIn: "verify" },
    });
    assert.equal(r.verdict, "matched", r.raw);
    assert.equal(r.checkStatus, "found", r.raw);
    assert.equal(r.evidenceIds!.control.length, 1);
    assert.equal(r.evidenceIds!.verify.length, 1);
    const row = s.store.checks("a-1").find((c) => c.checkClass === "custom-tamper");
    assert.equal(row?.status, "found");
    // the unauth control leg really carried no cookie
    const ctrlReq = seen.find((x) => x.url === "/protected" && x.cookie === undefined);
    assert.ok(ctrlReq, "control leg sent without session material");
  } finally {
    s.store.close();
  }
});

test("a declared expectation contradicted → refuted → tested-clean, not found", async () => {
  const s = session();
  try {
    const r = await run(s, {
      checkClass: "custom-tamper", target: "GET /protected",
      legs: [
        { kind: "control", method: "GET", url: `${base}protected` }, // authed → NOT denied
        { kind: "attack", method: "GET", url: `${base}protected?view=victim` },
      ],
      expect: { controlMustDeny: true },
    });
    assert.equal(r.verdict, "refuted", r.raw);
    assert.equal(r.checkStatus, "tested-clean", r.raw);
  } finally {
    s.store.close();
  }
});

test("matched but no control leg → unverified lead (never 'found' without discrimination)", async () => {
  const s = session();
  try {
    const r = await run(s, {
      checkClass: "custom-tamper", target: "GET /state",
      legs: [{ kind: "attack", method: "GET", url: `${base}state` }],
      expect: { marker: "verdict-landed-9" },
    });
    assert.equal(r.verdict, "matched", r.raw);
    assert.equal(r.checkStatus, "unverified", r.raw);
    assert.match(r.reason ?? "", /no discriminating control/);
  } finally {
    s.store.close();
  }
});

test("idor checkClass matched → capped at 'suspected' (dedicated verifier still required)", async () => {
  const s = session();
  try {
    const r = await run(s, {
      checkClass: "idor", target: "GET /protected",
      legs: [
        { kind: "control", method: "GET", url: `${base}protected`, role: "unauth" },
        { kind: "attack", method: "GET", url: `${base}protected?view=victim` },
        { kind: "verify", method: "GET", url: `${base}state` },
      ],
      expect: { controlMustDeny: true, marker: "verdict-landed-9", markerIn: "verify" },
    });
    assert.equal(r.checkStatus, "suspected", r.raw);
    assert.match(r.reason ?? "", /dedicated verifier|probe_authz/i);
    const row = s.store.checks("a-1").find((c) => c.checkClass === "idor");
    assert.equal(row?.status, "suspected");
  } finally {
    s.store.close();
  }
});

test("an out-of-scope leg refuses the WHOLE check before any request leaves", async () => {
  const s = session();
  try {
    const before = seen.length;
    const r = await run(s, {
      checkClass: "ssrf", target: "GET /x",
      legs: [
        { kind: "control", method: "GET", url: `${base}state` },
        { kind: "attack", method: "GET", url: "http://169.254.169.254/latest/meta-data" },
      ],
    });
    assert.match(r.raw, /out of scope/);
    assert.equal(seen.length, before, "nothing was sent");
    assert.equal(s.store.checks("a-1").length, 0, "no ledger row for a refused check");
  } finally {
    s.store.close();
  }
});

test("a leg role with no session material refuses before firing (usable roles listed)", async () => {
  const s = session({ roleCreds: new Map([["userB", { username: "b", password: "p" }]]) }); // creds-only → no replayable material
  try {
    const before = seen.length;
    const r = await run(s, {
      checkClass: "idor", target: "GET /protected",
      legs: [{ kind: "attack", method: "GET", url: `${base}protected`, role: "userB" }],
    });
    assert.match(r.raw, /no replayable session material|usable now/);
    assert.equal(seen.length, before);
  } finally {
    s.store.close();
  }
});

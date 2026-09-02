import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore, FakeOobProvider } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { HttpRequest } from "@veritas/scanner";

const BASE = "https://app.test/";
const resp = (status: number, body: string) => ({
  status,
  finalUrl: BASE,
  durationMs: 1,
  headers: {},
  body,
});

function fakeSession(dir: string, send: (req: HttpRequest) => Promise<unknown>, oob?: FakeOobProvider): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(BASE),
    targetUrl: BASE,
    currentScreenId: "s-1",
    currentCookie: "",
    currentBearer: "",
    currentRole: "",
    roleCreds: new Map(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
    ...(oob ? { oob } : {}),
  } as unknown as PilotSession;
}

async function callOob(
  dir: string,
  send: (req: HttpRequest) => Promise<unknown>,
  oob: FakeOobProvider | undefined,
): Promise<string> {
  const s = fakeSession(dir, send, oob);
  const t = buildTools(s).find((x) => (x as { name: string }).name === "probe_oob") as {
    handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>;
  };
  const out = await t.handler({ method: "GET", url: `${BASE}fetch?u=http://{{OOB}}/`, waitSec: 1 }, {});
  s.store.close();
  return out.content[0]!.text;
}

function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-oob-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("probe_oob is NOT AVAILABLE without a provider", async () => {
  await withDir(async (dir) => {
    const text = await callOob(dir, async () => resp(200, "ok"), undefined);
    assert.match(text, /OOB NOT AVAILABLE/);
  });
});

test("probe_oob CONFIRMS when the provider reports a callback", async () => {
  await withDir(async (dir) => {
    const fake = new FakeOobProvider({
      host: "abc.oob.test",
      id: "nid",
      hits: [{ id: "nid", type: "DNS", time: Date.now() + 60_000, clientIp: "9.9.9.9" }],
    });
    const seen: string[] = [];
    const send = async (req: HttpRequest) => {
      seen.push(req.url);
      return resp(200, "ok");
    };
    const text = await callOob(dir, send, fake);
    const out = JSON.parse(text) as { verdict: string; oobHost: string; provider: string };
    assert.match(out.verdict, /OOB CONFIRMED/);
    assert.equal(out.oobHost, "abc.oob.test");
    assert.equal(out.provider, "fake");
    assert.ok(seen.some((u) => u.includes("abc.oob.test")));
    assert.ok(seen.some((u) => u.includes("verdict-oob-noref-")));
  });
});

test("probe_oob does NOT confirm when the provider stays silent", async () => {
  await withDir(async (dir) => {
    const fake = new FakeOobProvider({ host: "abc.oob.test", id: "nid", hits: [] });
    const text = await callOob(dir, async () => resp(200, "ok"), fake);
    const out = JSON.parse(text) as { verdict: string };
    assert.match(out.verdict, /not confirmed/);
  });
});

test("probe_oob reports a poll error instead of a silent not-confirmed", async () => {
  await withDir(async (dir) => {
    const oob = {
      kind: "fake" as const,
      payload: async () => ({ host: "x.oob.test", id: "nid" }),
      poll: async () => {
        throw new Error("interactsh poll failed: HTTP 401");
      },
    };
    const text = await callOob(dir, async () => resp(200, "ok"), oob as unknown as FakeOobProvider);
    const out = JSON.parse(text) as { verdict: string };
    assert.match(out.verdict, /OOB poll error/);
    assert.match(out.verdict, /401/);
  });
});

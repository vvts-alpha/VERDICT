// REAL-HTTP end-to-end for the new probes: an in-process, deliberately-vulnerable server exercised by the ACTUAL probe
// handlers over real sockets (FetchHttpClient, not a fake). Proves each oracle confirms against a real server.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPairSync, createSign, createVerify, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PUB_PEM = publicKey.export({ type: "spki", format: "pem" }).toString();
const JWK_PUB = { ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>), use: "sig", kid: "1" };
const b64url = (s: string): string => Buffer.from(s).toString("base64url");
const PP_MARKER = "verdictPP9137";

function issueRs256(payload: Record<string, unknown>): string {
  const h = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "1" }));
  const p = b64url(JSON.stringify(payload));
  const sig = createSign("RSA-SHA256").update(`${h}.${p}`).sign(privateKey).toString("base64url");
  return `${h}.${p}.${sig}`;
}
function verifyToken(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length < 2 || !parts[0] || !parts[1]) return null;
  let header: { alg?: string };
  try { header = JSON.parse(Buffer.from(parts[0], "base64url").toString()); } catch { return null; }
  const data = `${parts[0]}.${parts[1]}`;
  if (header.alg === "HS256") {
    // NAIVE verifier — verifies the HMAC with the RSA PUBLIC KEY (the RS256->HS256 key-confusion vuln).
    const expect = createHmac("sha256", PUB_PEM).update(data).digest("base64url").replace(/=+$/, "");
    if ((parts[2] ?? "").replace(/=+$/, "") !== expect) return null;
  } else if (header.alg === "RS256") {
    if (!createVerify("RSA-SHA256").update(data).verify(publicKey, Buffer.from(parts[2] ?? "", "base64url"))) return null;
  } else return null;
  try { return JSON.parse(Buffer.from(parts[1], "base64url").toString()); } catch { return null; }
}
// naive recursive merge — the prototype-pollution sink
function merge(t: Record<string, unknown>, s: Record<string, unknown>): Record<string, unknown> {
  for (const k in s) {
    const v = s[k];
    if (v && typeof v === "object") { if (typeof t[k] !== "object" || t[k] === null) t[k] = {}; merge(t[k] as Record<string, unknown>, v as Record<string, unknown>); }
    else t[k] = v;
  }
  return t;
}
const readBody = (req: http.IncomingMessage): Promise<string> => new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b)); });

let server: http.Server;
let base = "";
let dir = "";

before(async () => {
  server = http.createServer(async (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const origin = req.headers.origin as string | undefined;
    if (u.pathname === "/api/me") { res.setHeader("content-type", "application/json"); if (origin) { res.setHeader("access-control-allow-origin", origin); res.setHeader("access-control-allow-credentials", "true"); } res.end('{"id":1}'); return; }
    if (u.pathname === "/.well-known/jwks.json") { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [JWK_PUB] })); return; }
    if (u.pathname === "/login" && req.method === "POST") { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ token: issueRs256({ sub: "user", role: "user" }) })); return; }
    if (u.pathname === "/api/whoami") { const p = verifyToken((req.headers.authorization ?? "").replace(/^Bearer /, "")); res.setHeader("content-type", "application/json"); if (p) { res.statusCode = 200; res.end(JSON.stringify({ user: p.sub, role: p.role })); } else { res.statusCode = 401; res.end('{"error":"invalid token"}'); } return; }
    if (u.pathname === "/api/profile" && req.method === "POST") { try { merge({}, JSON.parse(await readBody(req))); } catch { /* ignore */ } res.setHeader("content-type", "application/json"); res.end('{"ok":true}'); return; }
    if (u.pathname === "/api/config") { const out: Record<string, unknown> = {}; for (const k in {}) out[k] = (Object.prototype as Record<string, unknown>)[k]; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ config: out })); return; }
    if (u.pathname === "/sso") { const next = u.searchParams.get("SSO_ORIG_URI") ?? ""; let target = ""; try { target = Buffer.from(next.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString(); } catch { /* not b64 */ } if (/^https?:\/\//.test(target)) { res.statusCode = 302; res.setHeader("location", target); res.end(""); } else { res.statusCode = 200; res.end("home"); } return; }
    res.statusCode = 404; res.end("nf");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  dir = mkdtempSync(join(tmpdir(), "veritas-realhttp-"));
});
after(() => { server.close(); delete (Object.prototype as Record<string, unknown>)[PP_MARKER]; rmSync(dir, { recursive: true, force: true }); });

function session(): PilotSession {
  const store = AssessmentStore.open(join(dir, `s${Math.abs(base.length + Object.keys({}).length)}.sqlite`));
  try { store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) }); } catch { /* exists */ }
  return {
    http: new FetchHttpClient({ allow: (url: string) => url.startsWith(base.replace(/\/$/, "")) }),
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(base), targetUrl: base, currentScreenId: "s-1", currentCookie: "", currentBearer: "",
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
  } as unknown as PilotSession;
}
async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  return JSON.parse((await t.handler(args, {})).content[0]!.text);
}

test("REAL-HTTP probe_cors confirms arbitrary-origin reflection with credentials", async () => {
  const r = await run(session(), "probe_cors", { url: base + "api/me" });
  assert.equal(r.confirmed, true);
  assert.equal(r.severity, "high");
});

test("REAL-HTTP probe_redirect confirms a base64-wrapped SSO_ORIG_URI open redirect", async () => {
  const seed = Buffer.from(base + "home", "utf8").toString("base64");
  const r = await run(session(), "probe_redirect", { url: `${base}sso?SSO_ORIG_URI=${encodeURIComponent(seed)}`, param: "SSO_ORIG_URI" });
  assert.ok(Array.isArray(r.positiveReplays) && (r.positiveReplays as unknown[]).length === 2, JSON.stringify(r));
});

test("REAL-HTTP probe_jwt confirms RS256->HS256 key confusion (fetches JWKS, forges, replays)", async () => {
  const s = session();
  const login = await (s as unknown as { http: FetchHttpClient }).http.send({ method: "POST", url: base + "login", headers: { "content-type": "application/json" }, body: "{}" });
  (s as unknown as { currentBearer: string }).currentBearer = JSON.parse(login.body).token;
  const r = await run(s, "probe_jwt", { url: base + "api/whoami", jwksUrl: base + ".well-known/jwks.json", claimKey: "role", claimValue: "admin" });
  assert.match(String(r.technique ?? ""), /key-confusion/, JSON.stringify(r));
});

test("REAL-HTTP probe_proto confirms prototype pollution via a deep-merge sink (for-in reflects it)", async () => {
  const r = await run(session(), "probe_proto", { url: base + "api/profile", followUrl: base + "api/config" });
  assert.equal(r.confirmed, true, JSON.stringify(r));
  assert.equal(r.effectMarker, PP_MARKER + "VAL");
});

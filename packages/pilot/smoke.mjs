import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, newAssessmentId, deriveScopeFromSingleUrl } from "@veritas/core";
import { runPilot } from "./dist/run.js";

const target = "http://127.0.0.1:8091/";
const id = newAssessmentId();
const dir = mkdtempSync(join(tmpdir(), "pilot-"));
const store = AssessmentStore.open(join(dir, "state.sqlite"));
const scope = deriveScopeFromSingleUrl(target);
store.createAssessment({ id, target: { kind: "single_url", url: target, followLinks: true, maxDepth: 6 }, scope });

const roleCreds = new Map([
  ["alice", { username: "alice", password: "pw1" }],
  ["bob", { username: "bob", password: "pw2" }],
]);

console.log(`pilot assessment ${id} → ${target}\n`);
const res = await runPilot({
  store,
  assessmentId: id,
  targetUrl: target,
  scope,
  profileDir: join(dir, "profile"),
  artifactsDir: join(dir, "artifacts"),
  roleCreds,
  model: process.env.PILOT_MODEL ?? "claude-sonnet-4-6",
  maxTurns: Number(process.env.PILOT_MAXTURNS ?? 50),
  headless: true,
  noSandbox: true,
  onText: (t) => console.log(`\n🤖 ${t}`),
  onTool: (n, i) => console.log(`  ⚙ ${n.replace("mcp__veritas__", "")} ${JSON.stringify(i).slice(0, 200)}`),
});

console.log("\n=== RESULT ===");
console.log(`turns: ${res.turns} | findings: ${res.findings.length}`);
for (const f of res.findings) console.log(`  - [${f.severity}] ${f.title}  (evidence: ${f.evidenceIds.join(", ")})`);
console.log("\nsummary:", res.summary);
process.exit(0);

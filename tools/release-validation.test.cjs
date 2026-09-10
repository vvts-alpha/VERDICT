const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { sha256, validateBuildRuns, validateArtifact, validateLiveEvidence, renderNotes, validateDownloadLinks } = require("./release-validation.cjs");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "verdict-release-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const name = "VERDICT.Setup.2026.9.12.exe";
  fs.writeFileSync(path.join(directory, name), "immutable installer fixture");
  const manifest = { schemaVersion: 1, sourceCommit: "a".repeat(40), version: "2026.9.12", platform: "win32", arch: "x64",
    runtime: { electron: "44.3.0", node: "24.20.0" }, checks: { installerContents: "pass", cli: "pass", nativeSdk: "pass", gui: "pass", localApiAuth: "pass" },
    checkedAt: new Date().toISOString(), unpackedBytes: 1000, privateFiles: [], foreignPackages: [], installer: { name, bytes: fs.statSync(path.join(directory, name)).size, sha256: sha256(path.join(directory, name)) } };
  const expected = { commit: manifest.sourceCommit, version: manifest.version, electron: "44.3.0", previousVersion: "v2026.9.11-1", previousBytes: 30 };
  return { directory, manifest, expected };
}

test("accepts the verified artifact and renders notes with measured validation", t => {
  const { directory, manifest, expected } = fixture(t);
  validateArtifact(manifest, directory, expected);
  const notes = renderNotes({ summary: "Fix a concrete behavior.", changes: ["Remove foreign binaries."], upgrade: ["Install this version."], knownLimitations: ["Live checks covered one provider."] }, manifest, "https://example.invalid/build", "https://example.invalid/ci");
  for (const heading of ["Summary", "Changes", "Upgrade", "Validation", "Known limitations"]) assert.match(notes, new RegExp(`## ${heading}\\n`));
  assert.ok(notes.includes(manifest.installer.sha256));
});

for (const [name, mutate] of [
  ["wrong source", m => { m.sourceCommit = "b".repeat(40); }],
  ["wrong runtime", m => { m.runtime.electron = "38.0.0"; }],
  ["unsupported Node", m => { m.runtime.node = "22.18.0"; }],
  ["foreign operating system", m => { m.platform = "linux"; }],
  ["foreign architecture", m => { m.arch = "arm64"; }],
  ["skipped GUI test", m => { m.checks.gui = "skipped"; }],
  ["failed CLI", m => { m.checks.cli = "fail"; }],
  ["missing authentication test", m => { delete m.checks.localApiAuth; }],
  ["private data", m => { m.privateFiles.push("settings.json"); }],
  ["foreign SDK", m => { m.foreignPackages.push("claude-agent-sdk-linux-x64"); }],
  ["oversized installer", m => { m.installer.bytes = 272_599_584; }],
  ["oversized unpacked app", m => { m.unpackedBytes = 1_147_700_768; }],
  ["changed checksum", m => { m.installer.sha256 = "0".repeat(64); }],
  ["misnamed asset", m => { m.installer.name = "../installer.exe"; }],
  ["mislabeled version", m => { m.version = "2026.9.11"; }],
]) test(`release refuses ${name}`, t => {
  const { directory, manifest, expected } = fixture(t);
  mutate(manifest);
  assert.throws(() => validateArtifact(manifest, directory, expected));
});

test("release refuses a replaced installer even when metadata is unchanged", t => {
  const { directory, manifest, expected } = fixture(t);
  fs.writeFileSync(path.join(directory, manifest.installer.name), "tampered! installer fixture");
  assert.throws(() => validateArtifact(manifest, directory, expected));
});

test("release refuses growth and non-increasing stable versions", t => {
  const { directory, manifest, expected } = fixture(t);
  assert.throws(() => validateArtifact(manifest, directory, { ...expected, previousBytes: 1 }));
  assert.throws(() => validateArtifact(manifest, directory, { ...expected, previousVersion: "2026.9.12" }));
  assert.throws(() => validateArtifact(manifest, directory, { ...expected, previousVersion: "2026.10.1" }));
});

test("failed, pending, mismatched, and unrelated CI runs cannot be promoted", () => {
  const build = { workflow_id: 42, status: "completed", conclusion: "success", head_branch: "main", head_sha: "a".repeat(40) };
  const ci = { status: "completed", conclusion: "success", head_sha: build.head_sha };
  validateBuildRuns(build, ci, 42);
  assert.throws(() => validateBuildRuns({ ...build, conclusion: "failure" }, ci, 42));
  assert.throws(() => validateBuildRuns({ ...build, status: "in_progress" }, ci, 42));
  assert.throws(() => validateBuildRuns(build, { ...ci, conclusion: "failure" }, 42));
  assert.throws(() => validateBuildRuns(build, { ...ci, head_sha: "b".repeat(40) }, 42));
  assert.throws(() => validateBuildRuns(build, ci, 43));
});

test("live evidence must cover this exact installer, source, and model tool roundtrip", t => {
  const { manifest } = fixture(t);
  const live = structuredClone(manifest);
  Object.assign(live.checks, { models: "pass", browser: "pass", modelToolRoundtrip: "pass" });
  validateLiveEvidence(live, manifest);
  live.installer.sha256 = "b".repeat(64);
  assert.throws(() => validateLiveEvidence(live, manifest));
  live.installer.sha256 = manifest.installer.sha256;
  live.checks.modelToolRoundtrip = "not-run";
  assert.throws(() => validateLiveEvidence(live, manifest));
});

test("public evidence rejects unexpected credential fields and stale results", t => {
  const { manifest } = fixture(t);
  const live = structuredClone(manifest);
  Object.assign(live.checks, { models: "pass", browser: "pass", modelToolRoundtrip: "pass" });
  assert.throws(() => validateLiveEvidence({ ...live, apiKey: "private-fixture" }, manifest));
  assert.throws(() => validateLiveEvidence({ ...live, checkedAt: "2020-01-01T00:00:00Z" }, manifest));
  assert.throws(() => validateLiveEvidence({ ...live, checkedAt: "invalid" }, manifest));
});

test("download instructions cannot send users back to a superseded release", () => {
  validateDownloadLinks("[Download](https://github.com/vvts-alpha/VERDICT/releases/latest)");
  assert.throws(() => validateDownloadLinks("[Download](https://github.com/vvts-alpha/VERDICT/releases/download/v2026.9.7/VERDICT.Setup.2026.9.7.exe)"));
  validateDownloadLinks(fs.readFileSync(path.join(__dirname, "../README.md"), "utf8"));
});

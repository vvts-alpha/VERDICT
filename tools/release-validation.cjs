const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const REQUIRED_CHECKS = ["installerContents", "cli", "nativeSdk", "gui", "localApiAuth"];
const MAX_INSTALLER_BYTES = 200_000_000;
const MAX_UNPACKED_BYTES = 800_000_000;
const MAX_GROWTH_RATIO = 1.2;

function sha256(file) {
  const hash = crypto.createHash("sha256");
  const descriptor = fs.openSync(file, "r");
  try {
    const buffer = Buffer.alloc(1024 * 1024);
    let length;
    while ((length = fs.readSync(descriptor, buffer)) > 0) hash.update(buffer.subarray(0, length));
    return hash.digest("hex");
  } finally { fs.closeSync(descriptor); }
}

function validateBuildRuns(build, ci, expectedWorkflowId) {
  assert.equal(build.workflow_id, expectedWorkflowId, "Unexpected build workflow");
  assert.equal(build.status, "completed", "Windows build is still running");
  assert.equal(build.conclusion, "success", "Windows build failed");
  assert.equal(build.head_branch, "main", "Release artifacts must come from main");
  assert.match(build.head_sha, /^[a-f0-9]{40}$/);
  assert.equal(ci.head_sha, build.head_sha, "CI and installer source differ");
  assert.equal(ci.status, "completed", "CI is still running");
  assert.equal(ci.conclusion, "success", "CI failed");
}

function validateArtifact(manifest, directory, expected) {
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.sourceCommit, expected.commit, "Artifact source differs from CI");
  assert.equal(manifest.version, expected.version, "Artifact version differs from source");
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/, "Stable releases need a numeric version, without a prerelease suffix");
  assert.equal(manifest.platform, "win32");
  assert.equal(manifest.arch, "x64");
  assert.equal(manifest.runtime.electron, expected.electron, "Packaged Electron differs from pinned version");
  assert.ok(Number(manifest.runtime.node.split(".")[0]) >= 24, "Packaged Node is unsupported");
  for (const check of REQUIRED_CHECKS) assert.equal(manifest.checks[check], "pass", `Missing or failed ${check} check`);
  assert.ok(manifest.unpackedBytes > 0 && manifest.unpackedBytes <= MAX_UNPACKED_BYTES, "Unpacked size exceeds budget");
  assert.deepEqual(manifest.foreignPackages, [], "Foreign native packages are present");
  assert.deepEqual(manifest.privateFiles, [], "Private artifacts are present");
  const asset = manifest.installer;
  assert.equal(asset.name, `VERDICT.Setup.${manifest.version}.exe`, "Installer filename and version differ");
  assert.equal(path.basename(asset.name), asset.name);
  assert.ok(asset.bytes > 0 && asset.bytes <= MAX_INSTALLER_BYTES, "Installer size exceeds budget");
  if (expected.previousBytes) assert.ok(asset.bytes <= expected.previousBytes * MAX_GROWTH_RATIO, "Installer grew by more than 20%; investigate and revise the budget explicitly");
  const file = path.join(directory, asset.name);
  assert.equal(fs.statSync(file).size, asset.bytes, "Installer size differs from manifest");
  assert.equal(sha256(file), asset.sha256, "Installer checksum differs from manifest");
  if (expected.previousVersion) {
    const current = manifest.version.split(".").map(Number);
    const previous = expected.previousVersion.replace(/^v/, "").split("-")[0].split(".").map(Number);
    const firstDifference = current.findIndex((part, index) => part !== previous[index]);
    assert.ok(firstDifference >= 0 && current[firstDifference] > previous[firstDifference], "Release version must increase");
  }
}

function validateLiveEvidence(evidence, manifest) {
  const allowed = new Set(["schemaVersion", "sourceCommit", "version", "platform", "arch", "runtime", "installer", "unpackedBytes", "privateFiles", "foreignPackages", "checks", "checkedAt"]);
  assert.ok(Object.keys(evidence).every(key => allowed.has(key)), "Unexpected fields in public live evidence");
  assert.ok(Object.keys(evidence.runtime).every(key => ["version", "electron", "node", "chrome"].includes(key)), "Unexpected runtime evidence fields");
  assert.ok(Object.keys(evidence.installer).every(key => ["name", "bytes", "sha256"].includes(key)), "Unexpected installer evidence fields");
  assert.ok(Object.keys(evidence.checks).every(key => [...REQUIRED_CHECKS, "models", "browser", "modelToolRoundtrip"].includes(key)), "Unexpected live check fields");
  const age = Date.now() - Date.parse(evidence.checkedAt);
  assert.ok(Number.isFinite(age) && age >= -300_000 && age <= 48 * 60 * 60 * 1000, "Live evidence is missing a timestamp or is older than 48 hours");
  assert.equal(evidence.sourceCommit, manifest.sourceCommit, "Live test source differs from artifact");
  assert.equal(evidence.installer.sha256, manifest.installer.sha256, "Live tests covered a different installer");
  assert.equal(evidence.platform, "win32", "Live checks must run on Windows");
  for (const name of [...REQUIRED_CHECKS, "models", "browser", "modelToolRoundtrip"]) {
    assert.equal(evidence.checks[name], "pass", `Live ${name} check is missing or failed`);
  }
}

function renderNotes(change, manifest, buildUrl, ciUrl) {
  assert.ok(Object.keys(change).every(key => ["summary", "changes", "upgrade", "knownLimitations"].includes(key)), "Unexpected release note fields");
  assert.ok(typeof change.summary === "string" && change.summary.trim(), "Release summary is required");
  for (const key of ["changes", "upgrade", "knownLimitations"]) {
    assert.ok(Array.isArray(change[key]) && change[key].every(item => typeof item === "string" && item.trim()), `Invalid ${key}`);
  }
  assert.ok(change.changes.length && change.upgrade.length, "Changes and upgrade instructions are required");
  const list = items => items.length ? items.map(item => `- ${item}`).join("\n") : "None recorded.";
  return `## Summary\n\n${change.summary}\n\n## Changes\n\n${list(change.changes)}\n\n## Upgrade\n\n${list(change.upgrade)}\n\n## Validation\n\n- [Windows build and packaged application checks](${buildUrl})\n- [Dependency audit, build, typecheck and regression tests](${ciUrl})\n- Source: \`${manifest.sourceCommit}\`\n- Windows x64 installer: ${(manifest.installer.bytes / 1_000_000).toFixed(1)} MB\n- SHA-256: \`${manifest.installer.sha256}\`\n- Packaged runtime: Electron ${manifest.runtime.electron}, Node ${manifest.runtime.node}\n\n## Known limitations\n\n${list(change.knownLimitations)}\n`;
}

module.exports = { REQUIRED_CHECKS, MAX_INSTALLER_BYTES, MAX_UNPACKED_BYTES, MAX_GROWTH_RATIO, sha256, validateBuildRuns, validateArtifact, validateLiveEvidence, renderNotes };

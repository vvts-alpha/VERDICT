const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { sha256, validateBuildRuns, validateArtifact, validateLiveEvidence, renderNotes, validateDownloadLinks } = require("./release-validation.cjs");

const [mode, runId, argument, liveFile] = process.argv.slice(2);
assert.ok(["prepare", "check", "publish"].includes(mode), "Usage: promote-release.cjs prepare <run-id> <directory> | check|publish <run-id> <changes.json> <live-validation.json>");
assert.match(runId ?? "", /^\d+$/, "A Windows workflow run ID is required");
const repository = process.env.GITHUB_REPOSITORY || execFileSync("gh", ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"], { encoding: "utf8" }).trim();
assert.match(repository, /^[\w.-]+\/[\w.-]+$/);
const root = path.resolve(__dirname, "..");
validateDownloadLinks(fs.readFileSync(path.join(root, "README.md"), "utf8"));
function gh(args, input) {
  return execFileSync("gh", args, { input, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
}
function api(endpoint, method = "GET", data) {
  const args = ["api", endpoint, "--method", method];
  if (data !== undefined) args.push("--input", "-");
  const output = gh(args, data === undefined ? undefined : JSON.stringify(data));
  return output.trim() ? JSON.parse(output) : null;
}

const repo = `repos/${repository}`;
const build = api(`${repo}/actions/runs/${runId}`);
const workflow = api(`${repo}/actions/workflows/windows-build.yml`);
const ciRuns = api(`${repo}/actions/workflows/ci.yml/runs?head_sha=${build.head_sha}&per_page=10`).workflow_runs;
assert.ok(ciRuns.length, "No CI result exists for this source commit");
const ci = ciRuns[0];
validateBuildRuns(build, ci, workflow.id);
const sourceFile = api(`${repo}/contents/apps/desktop/package.json?ref=${build.head_sha}`);
const source = JSON.parse(Buffer.from(sourceFile.content, "base64").toString("utf8"));
const latest = api(`${repo}/releases/latest`);
const previousInstaller = latest.assets.find(asset => /^VERDICT[. ]Setup.*\.exe$/.test(asset.name));
assert.ok(previousInstaller, "Previous installer size is unavailable");
const expected = { commit: build.head_sha, version: source.version, electron: source.devDependencies.electron,
  previousVersion: latest.tag_name, previousBytes: previousInstaller.size };
const directory = mode === "prepare" ? path.resolve(argument) : fs.mkdtempSync(path.join(os.tmpdir(), "verdict-publish-"));
if (mode === "prepare") {
  assert.ok(!fs.existsSync(directory), "Prepare needs a fresh directory");
  fs.mkdirSync(directory, { recursive: true });
}
gh(["run", "download", runId, "--repo", repository, "--name", "verdict-windows-installer", "--dir", directory]);
const manifest = JSON.parse(fs.readFileSync(path.join(directory, "artifact-manifest.json"), "utf8"));
validateArtifact(manifest, directory, expected);

if (mode === "prepare") {
  gh(["run", "download", runId, "--repo", repository, "--name", "verdict-windows-unpacked", "--dir", path.join(directory, "win-unpacked")]);
  console.log(JSON.stringify({ directory, sourceCommit: build.head_sha, installer: manifest.installer, next: "Run check-desktop-bundle.cjs on Windows with --live-settings, then check or publish with its live-validation.json." }, null, 2));
  process.exit(0);
}

const localHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
assert.equal(localHead, build.head_sha, "Local release tooling and built source must match");
assert.equal(execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" }).trim(), "", "Commit all source changes before promotion");
const evidence = JSON.parse(fs.readFileSync(liveFile, "utf8"));
validateLiveEvidence(evidence, manifest);
const changes = JSON.parse(fs.readFileSync(argument, "utf8"));
const notes = renderNotes(changes, manifest, build.html_url, ci.html_url);
fs.writeFileSync(path.join(directory, "RELEASE-NOTES.md"), notes);
fs.writeFileSync(path.join(directory, "WINDOWS-QUICKSTART.md"), fs.readFileSync(path.join(root, "templates/windows-quickstart.md"), "utf8").replaceAll("{{VERSION}}", manifest.version));
fs.writeFileSync(path.join(directory, "live-validation.json"), JSON.stringify(evidence, null, 2) + "\n");

// Retain the companion only when its source has not changed. Never silently publish a stale Burp extension.
const compare = api(`${repo}/compare/${latest.target_commitish}...${build.head_sha}`);
assert.ok(compare.files.length < 300, "Compare output may be truncated; companion provenance must be reviewed");
assert.ok(!compare.files.some(file => file.filename.startsWith("tools/burp-audit-ext/")), "Burp extension source changed; build and validate its companion before promoting");
const companion = latest.assets.find(asset => asset.name === "verdict-burp-audit.jar");
assert.ok(companion?.digest?.startsWith("sha256:"), "Companion checksum is unavailable");
gh(["release", "download", latest.tag_name, "--repo", repository, "--pattern", companion.name, "--dir", directory]);
assert.equal(sha256(path.join(directory, companion.name)), companion.digest.slice(7));
const releaseManifest = { schemaVersion: 1, sourceCommit: build.head_sha, version: manifest.version, buildRun: build.html_url, ciRun: ci.html_url,
  installer: manifest.installer, companion: { name: companion.name, sha256: companion.digest.slice(7), fromRelease: latest.tag_name, sourceUnchanged: true } };
fs.writeFileSync(path.join(directory, "release-manifest.json"), JSON.stringify(releaseManifest, null, 2) + "\n");
const names = [manifest.installer.name, companion.name, "WINDOWS-QUICKSTART.md", "artifact-manifest.json", "live-validation.json", "release-manifest.json"];
const assets = names.map(name => ({ name, file: path.join(directory, name), bytes: fs.statSync(path.join(directory, name)).size, sha256: sha256(path.join(directory, name)) }));
fs.writeFileSync(path.join(directory, "SHA256SUMS.txt"), assets.map(asset => `${asset.sha256}  ${asset.name}\n`).join(""));
assets.push({ name: "SHA256SUMS.txt", file: path.join(directory, "SHA256SUMS.txt"), bytes: fs.statSync(path.join(directory, "SHA256SUMS.txt")).size, sha256: sha256(path.join(directory, "SHA256SUMS.txt")) });
console.log(JSON.stringify({ validation: "passed", mode, version: manifest.version, sourceCommit: manifest.sourceCommit, directory, assets: assets.map(({ name, bytes }) => ({ name, bytes })) }, null, 2));
if (mode === "check") process.exit(0);

const tag = `v${manifest.version}`;
let release;
try {
  const existing = JSON.parse(gh(["release", "view", tag, "--repo", repository, "--json", "apiUrl"]));
  release = api(existing.apiUrl);
} catch (error) {
  // Only an absent tag permits creation; any other API problem must fail instead of changing an existing release.
  if (!String(error.stderr ?? error.message).includes("release not found")) throw error;
}
if (release) {
  assert.equal(release.draft, true, "Published releases are immutable");
  assert.equal(release.target_commitish, manifest.sourceCommit, "Existing draft uses a different source");
} else {
  release = api(`${repo}/releases`, "POST", { tag_name: tag, target_commitish: manifest.sourceCommit, name: `${tag} — ${changes.summary}`, body: notes, draft: true, prerelease: false });
}
api(`${repo}/releases/${release.id}`, "PATCH", { body: notes });
const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || gh(["auth", "token"]).trim();
assert.ok(token && !/[\r\n"]/.test(token), "Invalid GitHub credential");
const nativeWindowsCurl = process.platform === "linux" && fs.existsSync("/mnt/c/Windows/System32/curl.exe");
const curl = nativeWindowsCurl ? "/mnt/c/Windows/System32/curl.exe" : process.platform === "win32" ? "curl.exe" : "curl";
for (const asset of assets) {
  const existing = release.assets?.find(item => item.name === asset.name);
  if (existing?.state === "uploaded") {
    assert.equal(existing.digest, `sha256:${asset.sha256}`, "Existing draft asset differs");
    continue;
  }
  if (existing) api(`${repo}/releases/assets/${existing.id}`, "DELETE");
  const inputFile = nativeWindowsCurl ? execFileSync("wslpath", ["-w", asset.file], { encoding: "utf8" }).trim() : asset.file;
  const response = execFileSync(curl, ["--config", "-", "--silent", "--show-error", "--http1.1", "--connect-timeout", "30", "--max-time", "600",
    "--request", "POST", "--header", "Content-Type: application/octet-stream", "--data-binary", `@${inputFile}`, "--write-out", "\n%{http_code}",
    `https://uploads.github.com/${repo}/releases/${release.id}/assets?name=${encodeURIComponent(asset.name)}`],
  { input: `header = "Authorization: Bearer ${token}"\n`, encoding: "utf8", maxBuffer: 1024 * 1024 });
  const split = response.lastIndexOf("\n");
  assert.equal(response.slice(split + 1), "201", `Upload failed for ${asset.name}`);
  const uploaded = JSON.parse(response.slice(0, split));
  assert.equal(uploaded.digest, `sha256:${asset.sha256}`, `Uploaded checksum differs: ${asset.name}`);
  assert.equal(uploaded.size, asset.bytes);
  console.log(`Uploaded and verified ${asset.name}`);
}
const ready = api(`${repo}/releases/${release.id}`);
assert.equal(ready.assets.length, assets.length, "Unexpected release assets");
for (const asset of assets) {
  const uploaded = ready.assets.find(item => item.name === asset.name);
  assert.equal(uploaded?.state, "uploaded");
  assert.equal(uploaded.digest, `sha256:${asset.sha256}`);
}
const finalBuild = api(`${repo}/actions/runs/${runId}`);
const finalCi = api(`${repo}/actions/workflows/ci.yml/runs?head_sha=${build.head_sha}&per_page=10`).workflow_runs[0];
assert.ok(finalCi, "CI result disappeared before publication");
validateBuildRuns(finalBuild, finalCi, workflow.id);
api(`${repo}/releases/${release.id}`, "PATCH", { draft: false, make_latest: "true" });
const published = api(`${repo}/releases/latest`);
assert.equal(published.id, release.id, "Release did not become latest");
assert.equal(published.draft, false);
console.log(JSON.stringify({ published: published.html_url, sourceCommit: manifest.sourceCommit, installer: manifest.installer }, null, 2));

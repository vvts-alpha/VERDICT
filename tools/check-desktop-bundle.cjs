const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync, execFileSync } = require("node:child_process");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");
const os = require("node:os");
const { crc32 } = require("node:zlib");
const { sha256, MAX_INSTALLER_BYTES, MAX_UNPACKED_BYTES } = require("./release-validation.cjs");

const directory = path.resolve(process.argv[2]);
const app = path.join(directory, "resources/app");
const scope = path.join(app, "node_modules/@anthropic-ai");
assert.deepEqual(fs.readdirSync(scope).filter(name => name.startsWith("claude-agent-sdk-")), ["claude-agent-sdk-win32-x64"]);
const env = { ...process.env, ELECTRON_RUN_AS_NODE: "1" };
delete env.NODE_TEST_CONTEXT;
const cli = spawnSync(path.join(directory, "VERDICT.exe"), [path.join(app, "node_modules/@veritas/cli/dist/main.js"), "--help"],
  { env, cwd: app, encoding: "utf8", timeout: 30_000 });
assert.equal(cli.status, 0, cli.error?.message ?? cli.stderr);
assert.match(cli.stdout, /pilot/);
const native = spawnSync(path.join(scope, "claude-agent-sdk-win32-x64/claude.exe"), ["--version"], { encoding: "utf8", timeout: 30_000 });
assert.equal(native.status, 0, native.error?.message ?? native.stderr);
assert.match(native.stdout, /Claude Code/);
const liveArgument = process.argv.indexOf("--live-settings");
const settings = liveArgument < 0 ? null : JSON.parse(fs.readFileSync(process.argv[liveArgument + 1], "utf8"));
const secrets = settings ? Object.entries(settings).filter(([key, value]) => /key|token|password/i.test(key) && typeof value === "string").map(([, value]) => value).filter(Boolean) : [];

async function check() {
  const output = path.dirname(directory);
  const manifestFile = path.join(output, "artifact-manifest.json");
  const prior = fs.existsSync(manifestFile) ? JSON.parse(fs.readFileSync(manifestFile, "utf8")) : null;
  const sourceCommit = process.env.GITHUB_SHA || prior?.sourceCommit;
  assert.match(sourceCommit ?? "", /^[a-f0-9]{40}$/, "A source commit is required");
  const pkg = JSON.parse(fs.readFileSync(path.join(app, "package.json"), "utf8"));
  const installerName = `VERDICT.Setup.${pkg.version}.exe`;
  const installerFile = path.join(output, installerName);
  const builderFile = path.join(output, `VERDICT Setup ${pkg.version}.exe`);
  if (!fs.existsSync(installerFile)) fs.renameSync(builderFile, installerFile);
  const installer = { name: installerName, bytes: fs.statSync(installerFile).size, sha256: sha256(installerFile) };
  if (prior) assert.equal(installer.sha256, prior.installer.sha256, "Installer changed since CI");
  assert.ok(installer.bytes < MAX_INSTALLER_BYTES, "Installer exceeds size budget");
  const privateFiles = [];
  const foreignPackages = [];
  let unpackedBytes = 0;
  const files = new Map();
  function inspect(folder) {
    for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
      const file = path.join(folder, entry.name);
      const relative = path.relative(directory, file).split(path.sep).join("/");
      if (/^(?:\.env(?:\..*)?|settings\.json|vault\.json|.*\.sqlite(?:-wal|-shm)?|.*\.cookies(?:\..*)?)$/i.test(entry.name) || entry.name === ".git") privateFiles.push(relative);
      if (relative.includes("node_modules/@anthropic-ai/claude-agent-sdk-") && !relative.includes("node_modules/@anthropic-ai/claude-agent-sdk-win32-x64")) foreignPackages.push(relative);
      if (entry.isDirectory()) inspect(file);
      else {
        const bytes = fs.statSync(file).size;
        unpackedBytes += bytes;
        files.set(relative, { file, bytes });
      }
    }
  }
  inspect(directory);
  assert.deepEqual(privateFiles, [], "Private files found in artifact");
  assert.deepEqual(foreignPackages, [], "Foreign SDK files found in artifact");
  assert.ok(unpackedBytes < MAX_UNPACKED_BYTES, "Unpacked application exceeds size budget");
  // Bind the tested directory to every file actually stored in the installer, including additions and omissions.
  {
    const sevenZip = process.env.VERDICT_7ZIP || (process.platform === "win32" ? "7z.exe" : "7z");
    const listing = execFileSync(sevenZip, ["l", "-slt", "-t7z", installerFile], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
    let matched = 0;
    for (const block of listing.replaceAll("\r\n", "\n").split("\n\n")) {
      const data = Object.fromEntries(block.split("\n").filter(line => line.includes(" = ")).map(line => { const split = line.indexOf(" = "); return [line.slice(0, split), line.slice(split + 3)]; }));
      if (!data.CRC) continue;
      const relative = data.Path.replaceAll("\\", "/");
      const entry = files.get(relative);
      assert.ok(entry, `Installer contains an untested file: ${relative}`);
      assert.equal(entry.bytes, Number(data.Size), `Installer file size differs: ${relative}`);
      const descriptor = fs.openSync(entry.file, "r");
      let checksum = 0;
      try {
        const buffer = Buffer.alloc(1024 * 1024);
        let length;
        while ((length = fs.readSync(descriptor, buffer)) > 0) checksum = crc32(buffer.subarray(0, length), checksum);
      } finally { fs.closeSync(descriptor); }
      assert.equal(checksum.toString(16).padStart(8, "0").toUpperCase(), data.CRC.toUpperCase(), `Installer file differs from tested directory: ${relative}`);
      matched++;
    }
    assert.equal(matched, files.size, "Installer is missing files from the tested application");
  }
  const requireApp = createRequire(path.join(app, "package.json"));
  const { _electron } = requireApp("playwright-core");
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "verdict-package-check-"));
  const guiEnv = { ...process.env };
  for (const key of ["NODE_TEST_CONTEXT", "ELECTRON_RUN_AS_NODE", "VERDICT_SHOT", "VERDICT_SHOT_QUERY", "VERDICT_ATTB_URL"]) delete guiEnv[key];
  let electron;
  const checks = { installerContents: "pass", cli: "pass", nativeSdk: "pass", gui: "not-run", localApiAuth: "not-run", models: "not-run", browser: "not-run", modelToolRoundtrip: "not-run" };
  try {
    electron = await _electron.launch({ executablePath: path.join(directory, "VERDICT.exe"), args: [`--user-data-dir=${profile}`], env: guiEnv, timeout: 60_000 });
    const actualProfile = await electron.evaluate(({ app }) => app.getPath("userData"));
    assert.equal(path.resolve(actualProfile), path.resolve(profile), "Smoke test must use an isolated profile");
    const page = await electron.firstWindow();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.waitForFunction(() => !!window.verdictDesktop);
    const runtime = await page.evaluate(() => window.verdictDesktop.app.info());
    assert.equal(runtime.version, pkg.version);
    const authenticated = await page.evaluate(async () => (await fetch("/api/assessments")).status);
    assert.equal(authenticated, 200);
    assert.equal((await fetch(new URL("/api/assessments", page.url()))).status, 401);
    checks.localApiAuth = "pass";
    if (settings) {
      await page.evaluate(draft => window.verdictDesktop.settings.set(draft), settings);
      const stored = await page.evaluate(() => window.verdictDesktop.settings.get());
      assert.ok(stored.apiKey === settings.apiKey?.trim(), "Saved credential differs");
      const results = await page.evaluate(() => window.verdictDesktop.settings.check());
      for (const name of ["Deep model", "Light model", "Automation browser"]) {
        assert.equal(results.find(result => result.name === name)?.status, "ok", `${name} connection failed`);
      }
      checks.models = "pass";
      checks.browser = "pass";
      assert.ok(stored.baseURL && stored.provider !== "claude-cli", "Live tool roundtrip requires an OpenAI-compatible provider");
      const { runOpenAiAgentLoop } = await import(pathToFileURL(path.join(app, "node_modules/@veritas/pilot/dist/agent-loop.js")).href);
      let calls = 0;
      const result = await runOpenAiAgentLoop({ baseURL: stored.baseURL, apiKey: stored.apiKey, model: stored.deepModel,
        system: "Client connection test only. Call connection_test once, then reply OK. No external actions.", goal: "Call connection_test, read its result, then reply OK.",
        tools: [{ name: "connection_test", description: "Local no-op; returns OK.", inputSchema: {}, handler: async () => { calls++; return { content: [{ type: "text", text: "OK" }] }; } }],
        allowed: ["connection_test"], mode: "native", maxTurns: 3, timeoutMs: 30_000, shouldStop: () => false });
      assert.ok(calls === 1 && result.stopped === "no_tool_calls", "Model tool roundtrip failed");
      checks.modelToolRoundtrip = "pass";
    }
    await page.screenshot({ path: path.join(output, settings ? "live-smoke.png" : "smoke.png") });
    assert.deepEqual(errors, [], "Renderer errors occurred");
    checks.gui = "pass";
    const report = { schemaVersion: 1, sourceCommit, version: pkg.version, platform: process.platform, arch: process.arch,
      runtime, installer, unpackedBytes, privateFiles, foreignPackages, checks, checkedAt: new Date().toISOString() };
    fs.writeFileSync(path.join(output, settings ? "live-validation.json" : "artifact-manifest.json"), JSON.stringify(report, null, 2) + "\n");
    fs.writeFileSync(path.join(output, "SHA256SUMS.txt"), `${installer.sha256}  ${installer.name}\n`);
    console.log(JSON.stringify({ version: pkg.version, installerBytes: installer.bytes, checks }));
  } finally {
    await electron?.close();
    fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
  }
}

check().catch(error => {
  let message = String(error.message ?? error);
  for (const secret of secrets) message = message.split(secret).join("[redacted]");
  console.error(message);
  process.exitCode = 1;
});

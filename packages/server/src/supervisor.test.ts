// Verify resume() restores the run's start-time options into the child CLI args.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Supervisor } from "./supervisor.js";

const waitForFile = async (p: string, ms = 8000): Promise<string> => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (existsSync(p)) return readFileSync(p, "utf8");
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${p}`);
};

test("resume restores start-time run options into CLI args", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "verdict-supervisor-resume-"));
  try {
    const id = "a-resume-args";
    const dir = join(runsDir, id);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ target: "http://localhost:3000/" }));
    writeFileSync(join(dir, "run.json"), JSON.stringify({
      command: "pilot",
      options: {
        model: "deep", fastModel: "light", rate: 1, maxTurns: 5, exhaustive: true,
        loginUrl: "http://localhost:3000/#/login", maxScreens: 300,
        focus: "audit the checkout", context: "tenant=acme", keepAliveMin: 2, parallel: 4,
      },
    }));
    const argvOut = join(runsDir, "argv.json");
    // Fixture CLI: dump argv so the test can assert the exact flags resume forwarded.
    writeFileSync(join(runsDir, "cli.mjs"),
      'import { writeFileSync } from "node:fs";\n' +
      'writeFileSync(process.env.ARGV_OUT, JSON.stringify(process.argv.slice(2)));\n');
    const supervisor = new Supervisor({
      runsDir, cliPath: join(runsDir, "cli.mjs"), nodePath: process.execPath,
      childEnv: () => ({ ...process.env, ARGV_OUT: argvOut }),
    });
    supervisor.resume(id);
    const argv = JSON.parse(await waitForFile(argvOut)) as string[];
    for (const flag of [
      "pilot", "--resume", "--id", id,
      "--model", "deep", "--fast-model", "light",
      "--rate", "1", "--max-turns", "5", "--exhaustive",
      "--login-url", "http://localhost:3000/#/login",
      "--max-screens", "300", "--focus", "audit the checkout",
      "--context", "tenant=acme", "--keepalive-min", "2", "--parallel", "4",
    ]) assert.ok(argv.includes(flag), `missing ${flag} in ${argv.join(" ")}`);

    // Burp-side launches restore the run's model too — the AI re-verify must not fall back to the env default.
    // spawnChild refuses while a child is still "running" — wait for the fixture to exit before each launch.
    const waitExit = async (): Promise<void> => {
      const deadline = Date.now() + 8000;
      while (supervisor.isRunning(id) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
    };
    await waitExit();
    rmSync(argvOut, { force: true });
    supervisor.burpScan(id);
    const burpArgv = JSON.parse(await waitForFile(argvOut)) as string[];
    for (const flag of ["burp-scan", "--id", id, "--model", "deep"])
      assert.ok(burpArgv.includes(flag), `missing ${flag} in ${burpArgv.join(" ")}`);
    await waitExit();
    rmSync(argvOut, { force: true });
    supervisor.burpImport(id, join(runsDir, "report.xml"));
    const impArgv = JSON.parse(await waitForFile(argvOut)) as string[];
    for (const flag of ["burp-import", "--id", id, "--model", "deep"])
      assert.ok(impArgv.includes(flag), `missing ${flag} in ${impArgv.join(" ")}`);
  } finally {
    rmSync(runsDir, { recursive: true, force: true });
  }
});

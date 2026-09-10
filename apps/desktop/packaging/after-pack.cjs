const fs = require("node:fs/promises");
const path = require("node:path");

// Remove foreign native SDK packages from the output, never from the source bundle.
module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== "win32") return;
  const architecture = { 1: "x64", 3: "arm64" }[context.arch];
  if (!architecture) throw new Error(`Unsupported Windows architecture: ${context.arch}`);
  const expected = `claude-agent-sdk-win32-${architecture}`;
  const modules = path.join(context.appOutDir, "resources", "app", "node_modules");
  const binary = path.join(modules, "@anthropic-ai", expected, "claude.exe");
  const handle = await fs.open(binary, "r");
  try {
    const header = Buffer.alloc(2);
    await handle.read(header, 0, 2, 0);
    if (header.toString("ascii") !== "MZ") {
      throw new Error(`Invalid Windows SDK executable: ${binary}`);
    }
  } finally {
    await handle.close();
  }

  const removed = [];
  async function prune(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (path.basename(directory) === "@anthropic-ai" &&
          entry.name.startsWith("claude-agent-sdk-") && entry.name !== expected) {
        await fs.rm(target, { recursive: true, force: true });
        removed.push(path.relative(modules, target));
      } else if (entry.isDirectory()) {
        await prune(target);
      }
    }
  }
  await prune(modules);
  console.log(`Windows SDK verified (${architecture}); removed ${removed.length} foreign SDK packages${removed.length ? `: ${removed.join(", ")}` : ""}.`);
};

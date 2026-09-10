const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const [mode, stageArgument, bundleArgument] = process.argv.slice(2);
if (!["prepare", "materialize"].includes(mode) || !stageArgument || !bundleArgument) {
  throw new Error("Usage: node tools/package-desktop.cjs prepare|materialize <staging-workspace> <bundle>");
}
const stage = path.resolve(stageArgument);
const bundle = path.resolve(bundleArgument);
if (stage === root || bundle === root || stage === bundle) throw new Error("Use separate staging and bundle directories.");

function copy(from, to) {
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.cpSync(from, to, { recursive: true, dereference: true });
}
const workspaces = ["apps/desktop", ...fs.readdirSync(path.join(root, "packages"))
  .filter(name => fs.existsSync(path.join(root, "packages", name, "package.json")))
  .map(name => `packages/${name}`)];

if (mode === "prepare") {
  if (fs.existsSync(stage)) throw new Error("Staging directory already exists; use a fresh directory.");
  for (const file of ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc"]) {
    if (fs.existsSync(path.join(root, file))) copy(path.join(root, file), path.join(stage, file));
  }
  for (const workspace of workspaces) {
    const source = path.join(root, workspace);
    const manifest = JSON.parse(fs.readFileSync(path.join(source, "package.json"), "utf8"));
    for (const file of ["package.json", ...(manifest.files ?? ["dist"])]) {
      copy(path.join(source, file), path.join(stage, workspace, file));
    }
  }
  console.log("Staged built workspace and unchanged dependency lockfile.");
} else {
  if (fs.existsSync(bundle)) throw new Error("Bundle directory already exists; use a fresh directory.");
  const desktop = path.join(stage, "apps/desktop");
  const manifest = JSON.parse(fs.readFileSync(path.join(desktop, "package.json"), "utf8"));
  for (const file of ["package.json", ...manifest.files]) copy(path.join(desktop, file), path.join(bundle, file));
  // A frozen, production-only hoisted install contains native optional dependencies for THIS platform.
  // Copy the actual files so electron-builder never has to traverse pnpm links or guess its dependency graph.
  copy(path.join(stage, "node_modules"), path.join(bundle, "node_modules"));
  const manifests = new Map(workspaces.map(workspace => {
    const source = path.join(stage, workspace);
    const pkg = JSON.parse(fs.readFileSync(path.join(source, "package.json"), "utf8"));
    return [pkg.name, { source, pkg }];
  }));
  const included = new Set();
  function include(name) {
    if (included.has(name)) return;
    const entry = manifests.get(name);
    if (!entry) return;
    included.add(name);
    const { source, pkg } = entry;
    const destination = path.join(bundle, "node_modules", name);
    for (const file of pkg.files ?? ["dist"]) copy(path.join(source, file), path.join(destination, file));
    const clean = { ...pkg };
    delete clean.devDependencies;
    for (const key of ["dependencies", "optionalDependencies"]) {
      if (!clean[key]) continue;
      clean[key] = { ...clean[key] };
      for (const dependency of Object.keys(clean[key])) {
        if (manifests.has(dependency)) {
          clean[key][dependency] = manifests.get(dependency).pkg.version;
          include(dependency);
        }
      }
    }
    fs.mkdirSync(destination, { recursive: true });
    fs.writeFileSync(path.join(destination, "package.json"), JSON.stringify(clean, null, 2) + "\n");
  }
  for (const name of Object.keys(manifest.dependencies)) include(name);
  for (const name of Object.keys(manifest.dependencies)) {
    if (manifests.has(name)) manifest.dependencies[name] = manifests.get(name).pkg.version;
  }
  // Keep only the pinned Electron version as build metadata; no development dependencies are shipped.
  manifest.devDependencies = { electron: manifest.devDependencies.electron };
  fs.writeFileSync(path.join(bundle, "package.json"), JSON.stringify(manifest, null, 2) + "\n");
  console.log(`Materialized ${included.size} runtime workspace packages and production dependencies.`);
}

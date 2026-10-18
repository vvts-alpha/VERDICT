#!/usr/bin/env node
// Scheduled-workflow helper: pick the newest stable Electron released at least
// MIN_AGE_DAYS ago and update the devDependencies.electron pin in
// apps/desktop/package.json. Key=value pairs are printed on stdout — the
// workflow redirects them into $GITHUB_OUTPUT.
import { readFileSync, writeFileSync } from "node:fs";

const MIN_AGE_DAYS = 7;
const pkgPath = "apps/desktop/package.json";

const cmp = (a, b) => {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
};

const meta = await (await fetch("https://registry.npmjs.org/electron")).json();
const cutoff = Date.now() - MIN_AGE_DAYS * 86_400_000;
const [version, released] = Object.entries(meta.time)
  .filter(([v, t]) => /^\d+\.\d+\.\d+$/.test(v) && new Date(t).getTime() <= cutoff)
  .sort((a, b) => cmp(b[0], a[0]))[0] ?? [];
if (!version) throw new Error(`no stable Electron release older than ${MIN_AGE_DAYS} days`);

const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
const current = pkg.devDependencies?.electron;
if (!current) throw new Error("apps/desktop/package.json has no devDependencies.electron");

if (version === current) {
  console.log(`changed=false\ncurrent=${current}\nversion=${version}`);
  process.exit(0);
}

const kind = Number(version.split(".")[0]) > Number(current.split(".")[0]) ? "major" : "minor-or-patch";
pkg.devDependencies.electron = version;
writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
console.log(`changed=true\ncurrent=${current}\nversion=${version}\nreleased=${released}\nkind=${kind}`);

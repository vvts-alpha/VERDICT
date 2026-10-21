// Collect all t("...") / t('...') canonical keys from the webui + desktop renderer sources.
// Usage: node tools/i18n-collect.cjs  → prints sorted keys, writes i18n-keys.json
const fs = require("fs");
const path = require("path");
const roots = ["packages/webui/src", "apps/desktop/renderer"];
const re = /\bt\(\s*"((?:[^"\\]|\\.)*)"|(?<!\w)t\(\s*'((?:[^'\\]|\\.)*)'/g;
const keys = new Set();
function walk(d) {
  for (const f of fs.readdirSync(d)) {
    const p = path.join(d, f);
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p);
    else if (/\.tsx?$/.test(f)) {
      const s = fs.readFileSync(p, "utf8");
      let m;
      while ((m = re.exec(s))) {
        const raw = m[1] !== undefined ? m[1] : m[2].replace(/\\'/g, "'").replace(/"/g, '\\"');
        keys.add(JSON.parse(`"${raw}"`));
      }
    }
  }
}
roots.forEach((r) => walk(path.join(__dirname, "..", r)));
const list = [...keys].sort();
fs.writeFileSync(path.join(__dirname, "..", "i18n-keys.json"), JSON.stringify(list, null, 2));
console.log(`${list.length} keys`);

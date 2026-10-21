// Verify every collected t() key is present as a JA entry in i18n.tsx.
const fs = require("fs");
const path = require("path");
const keys = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "i18n-keys.json"), "utf8"));
const src = fs.readFileSync(path.join(__dirname, "..", "packages/webui/src/i18n.tsx"), "utf8");
const missing = keys.filter((k) => {
  const ident = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k);
  const needle = ident ? `${k}:` : `${JSON.stringify(k)}:`;
  if (src.includes(needle)) return false;
  // also allow `  Key :` spacing variants
  const re = new RegExp("(^|[,{\\n\\r])\\s*" + (ident ? k.replace(/[$]/g, "\\$") : JSON.stringify(k).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")) + "\\s*:", "m");
  return !re.test(src);
});
console.log(`keys: ${keys.length}  missing in JA: ${missing.length}`);
missing.forEach((k) => console.log("MISSING:", JSON.stringify(k)));

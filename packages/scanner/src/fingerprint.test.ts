// fingerprintTech: test of the pure function that structurally extracts the tech stack from the response's headers/Cookie/meta/script-src.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { fingerprintTech, formatTechInventory, stackAttackHints } from "./fingerprint.js";

test("stackAttackHints maps detected stack to attack classes (Flask/Jinja → SSTI, PHP → LFI/deser)", () => {
  const flask = stackAttackHints([
    { kind: "framework", name: "Werkzeug", version: "2.0.1", source: "server", evidence: "" },
    { kind: "framework", name: "Flask (Jinja2)", version: null, source: "cookie", evidence: "" },
  ]);
  assert.ok(flask.some((h) => /SSTI/i.test(h)), "Flask/Jinja should imply SSTI");
  const php = stackAttackHints([{ kind: "language", name: "PHP", version: "7.4.3", source: "x-powered-by", evidence: "" }]);
  assert.ok(php.some((h) => /LFI|php:\/\/filter|deserial/i.test(h)), "PHP should imply LFI/deserialization");
  // An unrelated stack yields no hints (keeps the structure-based plan).
  assert.deepEqual(stackAttackHints([{ kind: "server", name: "nginx", version: "1.20", source: "server", evidence: "" }]), []);
});

test("extracts server / language / framework from headers and cookies", () => {
  const c = fingerprintTech([
    {
      url: "https://app.test/",
      headers: { server: "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3", "set-cookie": "PHPSESSID=abc; path=/" },
      body: "",
    },
  ]);
  const find = (name: string) => c.find((x) => x.name === name);
  assert.equal(find("Apache")?.version, "2.4.41");
  assert.equal(find("Apache")?.kind, "server");
  assert.equal(find("PHP")?.version, "7.4.3"); // X-Powered-By PHP/7.4.3
  assert.ok(c.some((x) => x.source === "cookie" && /PHP/.test(x.name))); // PHPSESSID → PHP language
});

test("extracts version-value headers and meta generator (CMS)", () => {
  const c = fingerprintTech([
    {
      url: "https://cms.test/",
      headers: { "x-aspnet-version": "4.0.30319" },
      body: `<meta name="generator" content="WordPress 6.4.2">`,
    },
  ]);
  assert.equal(c.find((x) => x.name === "ASP.NET")?.version, "4.0.30319");
  const wp = c.find((x) => x.kind === "cms");
  assert.equal(wp?.name, "WordPress");
  assert.equal(wp?.version, "6.4.2");
});

test("flags vulnerable JS libraries from script src via the catalog", () => {
  const c = fingerprintTech([
    {
      url: "https://app.test/",
      headers: {},
      body: `<script src="/assets/jquery-1.12.4.min.js"></script><script src="/assets/lodash-4.17.21.min.js"></script>`,
    },
  ]);
  const jq = c.find((x) => x.name === "jQuery");
  assert.equal(jq?.version, "1.12.4");
  assert.equal(jq?.kind, "frontend-lib");
  assert.match(jq?.knownVuln ?? "", /CVE-2020-11022/); // 1.12.4 <= 3.4.1 → known-vuln annotated
  const lodash = c.find((x) => x.name === "Lodash");
  assert.equal(lodash?.version, "4.17.21");
  assert.equal(lodash?.knownVuln, undefined); // 4.17.21 > 4.17.11 → not flagged
});

test("dedups identical components across samples", () => {
  const sample = { url: "https://app.test/", headers: { server: "nginx/1.18.0" }, body: "" };
  const c = fingerprintTech([sample, sample, { ...sample, url: "https://app.test/x" }]);
  assert.equal(c.filter((x) => x.name === "nginx").length, 1);
  assert.equal(c.find((x) => x.name === "nginx")?.version, "1.18.0");
});

test("formatTechInventory renders one line per component, marking known vulns", () => {
  const lines = formatTechInventory(fingerprintTech([{ url: "https://app.test/", headers: { server: "nginx/1.18.0" }, body: `<script src="/jquery-1.12.4.min.js"></script>` }]));
  assert.ok(lines.some((l) => /\[server\] nginx 1\.18\.0/.test(l)));
  assert.ok(lines.some((l) => /jQuery 1\.12\.4.*⚠ KNOWN/.test(l)));
});

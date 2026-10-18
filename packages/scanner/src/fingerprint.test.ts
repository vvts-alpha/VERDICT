// fingerprintTech: test of the pure function that structurally extracts the tech stack from the response's headers/Cookie/meta/script-src.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { fingerprintTech, formatTechInventory, stackAttackHints, hasVersionedComponent, isVersionlessComponentLead, extractBackendLibs } from "./fingerprint.js";

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

test("hasVersionedComponent: Apache/nginx banners count; BigIP-without-version does not", () => {
  assert.equal(hasVersionedComponent({ server: "Apache/2.4.41 (Ubuntu)" }, ""), true);
  assert.equal(hasVersionedComponent({ server: "nginx/1.18.0" }, ""), true);
  assert.equal(hasVersionedComponent({ server: "BigIP" }, ""), false);
  assert.equal(hasVersionedComponent({ Server: "BigIP", "set-cookie": "MRHSHint=x; MRHSession=y" }, ""), false);
  assert.equal(hasVersionedComponent({}, `<script src="/jquery-1.12.4.min.js"></script>`), true);
});

test("isVersionlessComponentLead: undisclosed-version writeup is A06 noise even with a banner", () => {
  const bigip = { server: "BigIP" };
  assert.equal(isVersionlessComponentLead("F5 BIG-IP internet-exposed with undisclosed version", bigip, ""), true);
  assert.equal(isVersionlessComponentLead("product family has Critical RCE CVE history", bigip, ""), true);
  assert.equal(
    isVersionlessComponentLead("Outdated Apache httpd 2.4.49 — CVE-2021-41773 path traversal/RCE", { server: "Apache/2.4.49" }, ""),
    false,
  );
});

const SP2013_HIVE = `<link href="/_layouts/15/1033/styles/Themable/corev15.css" rel="stylesheet"/>
<script src="/_layouts/15/init.js"></script>
<link href="/_catalogs/masterpage/_valero/img/logos/favicon.ico"/>`;

test("SharePoint /_layouts/15/ hive is a product, not SharePoint 2013 — no version", () => {
  const c = fingerprintTech([{ url: "https://sp.test/", headers: {}, body: SP2013_HIVE }]);
  const sp = c.find((x) => /SharePoint/i.test(x.name));
  assert.ok(sp);
  assert.equal(sp!.version, null);
  assert.equal(hasVersionedComponent({}, SP2013_HIVE), false);
  const writeup =
    "Outdated Microsoft SharePoint Server (2013 / v15 hive) — CVE-2019-0604. Corresponds to version 15.0. Patch level could not be confirmed.";
  assert.equal(isVersionlessComponentLead(writeup, {}, SP2013_HIVE), true);
});

test("SharePoint MicrosoftSharePointTeamServices build is a real version; hive+unrelated jQuery does not justify 15.0", () => {
  assert.equal(
    isVersionlessComponentLead(
      "Outdated Microsoft SharePoint 15.0.0.4557 — CVE-2019-0604",
      { microsoftsharepointteamservices: "15.0.0.4557" },
      SP2013_HIVE,
    ),
    false,
  );
  const mixed = `${SP2013_HIVE}<script src="/jquery-1.12.4.min.js"></script>`;
  assert.equal(
    isVersionlessComponentLead("Outdated Microsoft SharePoint Server 2013 (version 15.0) — CVE-2019-0604", {}, mixed),
    true,
  );
});

test("writeup may cite major.minor of a longer banner (PHP 7.4 vs 7.4.3)", () => {
  assert.equal(
    isVersionlessComponentLead("Outdated PHP 7.4 — CVE-2022-31629", { "x-powered-by": "PHP/7.4.3" }, ""),
    false,
  );
});

test("formatTechInventory renders one line per component, marking known vulns", () => {
  const lines = formatTechInventory(fingerprintTech([{ url: "https://app.test/", headers: { server: "nginx/1.18.0" }, body: `<script src="/jquery-1.12.4.min.js"></script>` }]));
  assert.ok(lines.some((l) => /\[server\] nginx 1\.18\.0/.test(l)));
  assert.ok(lines.some((l) => /jQuery 1\.12\.4.*⚠ KNOWN/.test(l)));
});

test("extractBackendLibs names backend libraries from stack traces and error pages", () => {
  // Node stack trace leaks the image library path (both / and \ separators).
  const sharp = extractBackendLibs(
    `Error: Input file is missing
    at Sharp.metadata (C:/app/node_modules/sharp/lib/input.js:42:11)
    at Sharp.input (${"C:\\app\\node_modules\\sharp\\lib\\sharp.js"}:9:3)`,
  );
  assert.ok(sharp.some((c) => c.kind === "backend-lib" && c.name === "sharp"), `expected sharp, got ${sharp.map((c) => c.name)}`);
  // Python error names the parser explicitly.
  const pil = extractBackendLibs(`{"detail":"PIL.UnidentifiedImageError: cannot identify image file 'upload.jpg'"}`);
  assert.ok(pil.some((c) => c.name === "Pillow (PIL)"), `expected Pillow, got ${pil.map((c) => c.name)}`);
  // Java stack names the PDF parser.
  const pdfbox = extractBackendLibs(`java.io.IOException: Error: End-of-File
    at org.apache.pdfbox.pdmodel.PDDocument.load(PDDocument.java:1045)`);
  assert.ok(pdfbox.some((c) => c.name === "Apache PDFBox"), `expected PDFBox, got ${pdfbox.map((c) => c.name)}`);
  // Django debug page → framework + exact version (error-page is the strong signal).
  const django = extractBackendLibs(`<html><head><title>ImportError at /upload</title></head><body><div id="summary"><h1>ImportError at /upload</h1><pre>No module named 'pymagic'</pre></div><footer>Django Version: 4.2.11</footer></body></html>`);
  const dj = django.find((c) => c.name === "Django");
  assert.equal(dj?.version, "4.2.11", `expected Django 4.2.11, got ${JSON.stringify(dj)}`);
});

test("extractBackendLibs pulls versions from jar paths and lockfile fragments", () => {
  const jar = extractBackendLibs(`Caused by: org.yaml.snakeyaml.error.YAMLException
    at org.yaml.snakeyaml-1.33.jar!/org/yaml/snakeyaml/constructor/SafeConstructor.java:321`);
  assert.ok(jar.some((c) => c.name.toLowerCase() === "snakeyaml" && c.version === "1.33"), `expected snakeyaml 1.33, got ${jar.map((c) => `${c.name}@${c.version}`)}`);
  // Leaked package-lock gives exact versions — the OSV-matchable form.
  const lock = extractBackendLibs(`{"name":"app","lockfileVersion":3,"packages":{"":{"version":"1.0.0"},"node_modules/sharp":{"version":"0.32.1"},"node_modules/multer":{"version":"1.4.5"}}}`);
  assert.ok(lock.some((c) => c.name === "sharp" && c.version === "0.32.1"), `expected sharp@0.32.1, got ${lock.map((c) => `${c.name}@${c.version}`)}`);
  // requirements.txt fragment.
  const reqs = extractBackendLibs(`flask==3.0.0\ngunicorn==21.2.0\npillow==10.1.0\nrequests==2.31.0\n`);
  assert.ok(reqs.some((c) => c.name.toLowerCase() === "pillow" && c.version === "10.1.0"), `expected pillow==10.1.0, got ${reqs.map((c) => `${c.name}@${c.version}`)}`);
});

test("extractBackendLibs is a guess feed — empty on unremarkable bodies, no flood of deps", () => {
  assert.deepEqual(extractBackendLibs(`<html><body><h1>OK</h1></body></html>`), []);
  // A plain npm stack only surfaces allow-listed names, not every transitive dep.
  const trace = extractBackendLibs(`Error: x
    at h (/app/node_modules/lodash/index.js:1:1)
    at h (/app/node_modules/multer/lib/multer.js:1:1)
    at h (/app/node_modules/bluebird/js/release/util.js:1:1)`);
  const names = trace.map((c) => c.name);
  assert.ok(names.includes("multer"), `multer expected, got ${names}`);
  assert.ok(!names.includes("lodash") && !names.includes("bluebird"), `dep flood: ${names}`);
});

test("stackAttackHints maps backend-lib guesses to n-day attack classes", () => {
  const hints = stackAttackHints([
    { kind: "backend-lib", name: "ImageMagick", version: null, source: "error-message", evidence: "" },
    { kind: "backend-lib", name: "SnakeYAML", version: "1.33", source: "stack-trace", evidence: "" },
    { kind: "backend-lib", name: "Log4j", version: null, source: "stack-trace", evidence: "" },
  ]);
  assert.ok(hints.some((h) => /polyglot|MVG/i.test(h)), "ImageMagick → polyglot/MVG hint");
  assert.ok(hints.some((h) => /YAML|yaml\.load/i.test(h)), "SnakeYAML → unsafe-load hint");
  assert.ok(hints.some((h) => /JNDI|Log4Shell/i.test(h)), "Log4j → JNDI hint");
  // Backend-lib kind flows through the inventory formatter for the LLM prompt.
  const inv = formatTechInventory([{ kind: "backend-lib", name: "SnakeYAML", version: "1.33", source: "stack-trace", evidence: "" }]);
  assert.ok(inv[0]?.includes("[backend-lib] SnakeYAML 1.33"), inv[0]);
});

// fingerprintTech: test of the pure function that structurally extracts the tech stack from the response's headers/Cookie/meta/script-src.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { fingerprintTech, formatTechInventory, stackAttackHints, hasVersionedComponent, isVersionlessComponentLead } from "./fingerprint.js";

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

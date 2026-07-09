import { test } from "node:test";
import assert from "node:assert/strict";

import { reconFindings, topSeverity } from "./index.js";
import type { Asset } from "@veritas/core";

const mk = (o: Partial<Asset>): Asset => ({
    host: "x.example.com",
    source: "crt.sh",
    resolved: ["1.2.3.4"],
    alive: true,
    scheme: "https",
    status: 200,
    title: null,
    tech: [],
    screenshot: null,
    inScope: true,
    ...o,
});

test("reconFindings: takeover → subdomain-takeover finding (severity by confidence)", () => {
    const f = reconFindings(mk({ takeover: { service: "AWS/S3", vulnerable: true, confidence: "likely", cname: "b.s3.amazonaws.com", note: "claim it" } }));
    assert.equal(f[0]?.category, "subdomain-takeover");
    assert.equal(f[0]?.severity, "critical");
});

test("reconFindings: exposed .git = critical; swagger = medium; listing = high", () => {
    const f = reconFindings(mk({
        notablePaths: [
            { path: "/.git/HEAD", status: 200, note: "readable .git (HEAD)", escalate: true },
            { path: "/swagger.json", status: 200, note: "OpenAPI/Swagger spec", escalate: false },
        ],
        listing: [{ name: "backup", type: "dir", path: "/backup/", children: [{ name: "db.sql", type: "file", path: "/backup/db.sql" }] }],
    }));
    const bySev = Object.fromEntries(f.map((x) => [x.category, x.severity]));
    assert.equal(bySev["exposed-source-secret"], "critical");
    assert.equal(bySev["exposed-path"], "medium");
    assert.equal(bySev["directory-listing"], "high");
});

test("reconFindings: default page (low), version disclosure (info), plaintext http (low)", () => {
    const f = reconFindings(mk({ scheme: "http", title: "Welcome to nginx!", tech: ["nginx/1.25.0"] }));
    const cats = f.map((x) => x.category);
    assert.ok(cats.includes("default-install-page"));
    assert.ok(cats.includes("version-disclosure"));
    assert.ok(cats.includes("plaintext-http"));
});

test("topSeverity: returns the maximum severity", () => {
    const f = reconFindings(mk({
        takeover: { service: "GitHub Pages", vulnerable: true, confidence: "likely", note: "x" },
        tech: ["nginx/1.2"],
    }));
    assert.equal(topSeverity(f), "critical");
    assert.equal(topSeverity([]), null);
});

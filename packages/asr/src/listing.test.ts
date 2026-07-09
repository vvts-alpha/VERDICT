import { test } from "node:test";
import assert from "node:assert/strict";

import { isDirectoryListing, parseListing, enumerateListing, type HttpProbe } from "./index.js";

const APACHE = `<html><head><title>Index of /</title></head><body><h1>Index of /</h1><pre>
<a href="?C=N;O=D">Name</a>  <a href="?C=M;O=A">Last modified</a>
<a href="../">Parent Directory</a>
<a href="backup/">backup/</a>   2020-01-01
<a href="readme.txt">readme.txt</a>  1.2K
<a href="uploads/">uploads/</a></pre></body></html>`;

test("parseListing: direct-child dirs+files; skips parent + sort links", () => {
    const e = parseListing(APACHE, "/");
    assert.deepEqual(e.map((x) => `${x.type}:${x.name}`), ["dir:backup", "file:readme.txt", "dir:uploads"]);
    assert.equal(e[0]?.path, "/backup/");
    assert.equal(e[1]?.path, "/readme.txt");
});

test("isDirectoryListing: true on an autoindex, false on a normal page", () => {
    assert.equal(isDirectoryListing(APACHE), true);
    assert.equal(isDirectoryListing("<html><title>Home</title><body>welcome</body></html>"), false);
});

test("enumerateListing: recurses into subdirs, depth-bounded", async () => {
    const pages: Record<string, string> = {
        "/": `<title>Index of /</title><pre><a href="../">Parent Directory</a><a href="backup/">backup/</a><a href="app.js">app.js</a></pre>`,
        "/backup/": `<title>Index of /backup/</title><pre><a href="../">Parent Directory</a><a href="db.sql">db.sql</a><a href="old/">old/</a></pre>`,
        "/backup/old/": `<title>Index of /backup/old/</title><pre><a href="conf.bak">conf.bak</a></pre>`,
    };
    const http: HttpProbe = async (url) => {
        const path = new URL(url).pathname;
        const body = pages[path];
        if (body === undefined) throw new Error("404");
        return { status: 200, headers: {}, body, finalUrl: url };
    };
    const tree = await enumerateListing("https://x.example.com", "/", http, { maxDepth: 2, maxEntries: 100 });
    assert.deepEqual(tree.map((e) => e.name), ["backup", "app.js"]);
    const backup = tree.find((e) => e.name === "backup");
    assert.deepEqual(backup?.children?.map((e) => e.name), ["db.sql", "old"]);
    // "old" sits at depth 1; recursing it would be depth 2 (== maxDepth) → not expanded
    assert.equal(backup?.children?.find((e) => e.name === "old")?.children, undefined);
});

test("enumerateListing: [] when the start URL is not an autoindex", async () => {
    const http: HttpProbe = async (url) => ({ status: 200, headers: {}, body: "<html>not a listing</html>", finalUrl: url });
    assert.deepEqual(await enumerateListing("https://x", "/", http), []);
});

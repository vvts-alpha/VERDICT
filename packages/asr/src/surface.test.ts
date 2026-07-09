import { test } from "node:test";
import assert from "node:assert/strict";

import { probeSurface, type HttpProbe, type ProbeResponse } from "./index.js";

const respond = (map: Record<string, ProbeResponse>): HttpProbe => async (url) => {
    const path = new URL(url).pathname;
    const r = map[path];
    if (!r) throw new Error("ECONNREFUSED"); // path not present on this host
    return r;
};
const R = (status: number, ctype: string, body: string): ProbeResponse => ({
    status,
    headers: { "content-type": ctype },
    body,
    finalUrl: "",
});

test("probeSurface: content-signature hits (.git/.env escalate, swagger/robots don't); missing paths skipped", async () => {
    const http = respond({
        "/.git/HEAD": R(200, "text/plain", "ref: refs/heads/main\n"),
        "/.env": R(200, "text/plain", "APP_KEY=base64:abcd\nDB_PASSWORD=hunter2\n"),
        "/swagger.json": R(200, "application/json", '{"swagger":"2.0","paths":{}}'),
        "/robots.txt": R(200, "text/plain", "User-agent: *\nDisallow: /admin\n"),
    });
    const hits = await probeSurface("x.example.com", "https", http);
    const byPath = Object.fromEntries(hits.map((h) => [h.path, h]));
    assert.equal(byPath["/.git/HEAD"]?.escalate, true);
    assert.equal(byPath["/.env"]?.escalate, true);
    assert.equal(byPath["/swagger.json"]?.escalate, false);
    assert.equal(byPath["/robots.txt"]?.escalate, false);
    assert.ok(byPath["/.env"]?.note.includes(".env"));
    // paths not in the map threw ECONNREFUSED and were skipped, not surfaced
    assert.equal(hits.length, 4);
});

test("probeSurface: a catch-all 200 (SPA HTML for every path) yields ZERO hits — no soft-404 false positives", async () => {
    const spa: HttpProbe = async () => R(200, "text/html", "<!doctype html><html><div id=app></div></html>");
    const hits = await probeSurface("spa.example.com", "https", spa);
    assert.deepEqual(hits, []);
});

test("probeSurface: a 200 .git/HEAD that returns HTML (soft 404) is not a hit", async () => {
    const http = respond({ "/.git/HEAD": R(200, "text/html", "<html><body>Not Found</body></html>") });
    const hits = await probeSurface("x.example.com", "https", http);
    assert.deepEqual(hits, []);
});

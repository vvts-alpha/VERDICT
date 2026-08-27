// Spike: prove node:sqlite (flag-free) + @veritas/core's AssessmentStore open inside the REAL Electron main process.
// This decides the architecture: if the store opens in main, the server can run in-process; if not, it must be
// pushed to a utilityProcess. Runs without a window (whenReady → test → quit). Run: pnpm --filter @veritas/desktop spike
import { app } from "electron";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";

const log = (...a) => console.log("[spike]", ...a);

async function run() {
    const results = {};
    // 1) raw node:sqlite, flag-free (Electron 38 = Node 22.18 ≥ 22.13 where the flag was dropped)
    try {
        const { DatabaseSync } = await import("node:sqlite");
        const db = new DatabaseSync(":memory:");
        db.exec("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (42);");
        const row = db.prepare("SELECT x FROM t").get();
        db.close();
        results.nodeSqlite = row?.x === 42 ? "OK (flag-free)" : `WRONG (${JSON.stringify(row)})`;
    } catch (e) {
        results.nodeSqlite = `FAIL: ${String(e).slice(0, 200)}`;
    }
    // 2) @veritas/core AssessmentStore (the real store the server uses) opening a file DB in main
    try {
        const core = await import("@veritas/core");
        const dir = mkdtempSync(join(tmpdir(), "verdict-spike-"));
        const store = core.AssessmentStore.open(join(dir, "state.sqlite"));
        const st = store.createAssessment({
            target: { kind: "single_url", url: "https://example.com/", followLinks: true, maxDepth: 2 },
            scope: core.deriveScopeFromSingleUrl("https://example.com/"),
        });
        const loaded = store.loadAssessment(st.id);
        store.close();
        results.assessmentStore = loaded && loaded.events.length >= 1 ? `OK (id=${st.id}, phase=${loaded.phase})` : "WRONG (no assessment back)";
    } catch (e) {
        results.assessmentStore = `FAIL: ${String(e).slice(0, 300)}`;
    }
    results.electron = process.versions.electron;
    results.node = process.versions.node;
    results.esmMain = "OK (this file loaded as ESM main)";
    log("RESULTS:", JSON.stringify(results, null, 2));
    // exit code reflects success so the shell can assert
    const ok = String(results.nodeSqlite).startsWith("OK") && String(results.assessmentStore).startsWith("OK");
    app.exit(ok ? 0 : 1);
}

app.disableHardwareAcceleration();
app.whenReady().then(run).catch((e) => {
    console.error("[spike] fatal:", e);
    app.exit(1);
});

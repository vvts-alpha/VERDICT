import { test } from "node:test";
import assert from "node:assert/strict";
import type { Screen } from "@veritas/core";
import { buildTools, dedupKey } from "./tools.js";
import type { PilotSession } from "./tools.js";

// Both tools read the same live projections; requesting a screen never harvests the global evidence bodies.
test("screen detail stays local and paginated shared context sees newly captured state without a stale copy", async () => {
    const url = "https://app.test/account";
    const screen = { screenId: "s-0001", urlTemplate: url, observedUrls: [url], authState: "unauth", screenType: "detail",
        description: "Account", params: [], apis: [{ method: "GET", urlTemplate: "https://app.test/api/account" }], labels: [],
    } as unknown as Screen;
    const findingsByKey = new Map<string, never>();
    const related = dedupKey("idor", "https://app.test/api/account", "id", url);
    const appWide = "app:security-headers";
    const unrelated = Array.from({ length: 45 }, (_, i) => dedupKey("sqli", `https://app.test/other${i}`, "q", url));
    for (const key of [related, appWide, ...unrelated]) findingsByKey.set(key, undefined as never);
    let evidenceReads = 0;
    const records = [{ response: { body: '{"userId":1023}' } }];
    const session = {
        inv: { screens: () => [screen] }, store: { checks: () => [] }, plans: new Map(), currentScreenId: screen.screenId,
        targetUrl: url, currentRole: "", roleCreds: new Map(), roleCookieFiles: new Map(), roleDescriptions: new Map(),
        findingsByKey, evidence: { get records() { evidenceReads++; return records; } },
    } as unknown as PilotSession;
    const defs = buildTools(session);
    const call = async (name: string, args: Record<string, unknown> = {}) => {
        const result = await defs.find((t) => t.name === name)!.handler(args as never, {});
        return JSON.parse((result.content[0] as { text: string }).text);
    };
    const detail = await call("get_screen");
    assert.deepEqual(detail.alreadyConfirmed, [related, appWide]);
    assert.equal(detail.knownObjectIds, undefined);
    assert.equal(detail.sharedContextTool, "get_shared_context");
    assert.equal(evidenceReads, 0, "ordinary screen reads do not scan global HTTP bodies");
    const keys: string[] = [];
    let offset: number | null = 0;
    while (offset !== null) {
        const page = await call("get_shared_context", { offset, limit: 20 });
        assert.ok(page.alreadyConfirmed.length <= 20);
        assert.ok(page.knownObjectIds.includes("userId=1023"), "cross-user IDs remain retrievable");
        keys.push(...page.alreadyConfirmed);
        offset = page.nextOffset;
    }
    assert.deepEqual(keys, [...findingsByKey.keys()]);
    const later = dedupKey("sqli", "https://app.test/new", "q", url);
    findingsByKey.set(later, undefined as never);
    records.push({ response: { body: '{"userId":1024}' } });
    const fresh = await call("get_shared_context", { offset: 47 });
    assert.deepEqual(fresh.alreadyConfirmed, [later]);
    assert.ok(fresh.knownObjectIds.includes("userId=1024"), "read-through sees another worker's new evidence");
});

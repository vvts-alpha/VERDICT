import { test } from "node:test";
import assert from "node:assert/strict";
import { checkReadiness } from "./preflight.js";

const env = { VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1", VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light" };

test("readiness tests both selected models and browser; Burp off makes no API calls", async () => {
  const models: string[] = [];
  let browser = 0;
  const result = await checkReadiness(env, false, {
    model: async (cfg) => { models.push(cfg.model!); }, browser: async () => { browser++; }, fetch: async () => { throw new Error("unexpected request"); },
  });
  assert.deepEqual(models, ["deep", "light"]);
  assert.equal(browser, 1);
  assert.equal(result.filter((c) => c.status === "ok").length, 3);
  assert.equal(result.at(-1)?.status, "skipped");
});

test("failures remain separate, never expose credentials, and do not prevent other checks", async () => {
  const result = await checkReadiness(env, false, {
    model: async () => { throw new Error("provider echoed secret-token"); }, browser: async () => { throw new Error("bad path"); }, fetch,
  });
  assert.equal(result.filter((c) => c.status === "error").length, 3);
  assert.ok(!JSON.stringify(result).includes("secret-token"));
});

test("same model is checked once; serial Burp compatibility is read-only and authenticated", async () => {
  let models = 0;
  const paths: string[] = [];
  const result = await checkReadiness({ ...env, VERDICT_LLM_FAST_MODEL: "deep", BURP_AUDIT_API: "http://burp.test", BURP_AUDIT_TOKEN: "test" }, true, {
    model: async () => { models++; }, browser: async () => {},
    fetch: async (url, init) => {
      paths.push(String(url));
      assert.equal(init?.method, undefined);
      assert.equal((init?.headers as Record<string, string>)["X-Scan-Token"], "test");
      return String(url).endsWith("yaml") ? new Response("paths:\n  /scan/serial:") : Response.json({ hosts: [] });
    },
  });
  assert.equal(models, 1);
  assert.deepEqual(paths, ["http://burp.test/openapi.yaml", "http://burp.test/status"]);
  assert.ok(result.every((r) => r.status === "ok"));
});

test("old extension fails readiness without submitting or resetting audits", async () => {
  const result = await checkReadiness({ ...env, BURP_AUDIT_API: "http://burp.test" }, true, {
    model: async () => {}, browser: async () => {}, fetch: async () => new Response("paths:\n  /scan:"),
  });
  assert.equal(result.at(-1)?.status, "error");
});

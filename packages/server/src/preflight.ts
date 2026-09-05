import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PlaywrightDriver } from "@veritas/crawler";
import { makeLlmClient, resolveLlmConfig } from "@veritas/llm";
import type { LlmProviderConfig } from "@veritas/llm";
import type { ReadinessCheck } from "@veritas/core";

interface PreflightDependencies {
  model(config: LlmProviderConfig): Promise<void>;
  browser(env: NodeJS.ProcessEnv): Promise<void>;
  fetch: typeof fetch;
}
const defaults: PreflightDependencies = {
  model: async (config) => {
    const reply = await makeLlmClient({ ...config, timeoutMs: 20_000 }).complete({ prompt: "Connection test. Reply only OK.", timeoutMs: 20_000 });
    if (!reply.text.trim()) throw new Error("empty response");
  },
  browser: async (env) => {
    const dir = mkdtempSync(join(tmpdir(), "verdict-browser-check-"));
    try {
      const browser = await PlaywrightDriver.launch({
        userDataDir: dir, headless: true,
        ...(env.VERDICT_BROWSER_PATH ? { executablePath: env.VERDICT_BROWSER_PATH } : {}),
        ...(env.VERDICT_BROWSER_CHANNEL ? { channel: env.VERDICT_BROWSER_CHANNEL } : {}),
      });
      await browser.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  },
  fetch: (...args) => fetch(...args),
};

/** Check the selected provider and local tools. Never submit a scan or send target data. */
export async function checkReadiness(env: NodeJS.ProcessEnv, burpScan: boolean, deps: PreflightDependencies = defaults): Promise<ReadinessCheck[]> {
  const checks: ReadinessCheck[] = [];
  const check = async (name: string, action: () => Promise<string>, failure: string): Promise<void> => {
    try { checks.push({ name, status: "ok", message: await action() }); }
    catch { checks.push({ name, status: "error", message: failure }); }
  };
  const checkedModels = new Set<string>();
  for (const [tier, model] of [["Deep model", env.VERDICT_LLM_MODEL], ["Light model", env.VERDICT_LLM_FAST_MODEL]] as const) {
    const cfg = resolveLlmConfig(env, { ...(model ? { explicitModel: model } : {}), claudeDefaultModel: tier === "Deep model" ? "claude-opus-4-8" : "claude-sonnet-5" });
    if (cfg.model && checkedModels.has(cfg.model)) {
      checks.push({ name: tier, status: "ok", message: "Uses the model already checked above" });
      continue;
    }
    await check(tier, async () => {
      if (cfg.provider === "openai" && (!cfg.baseURL || !cfg.model)) throw new Error("missing configuration");
      await deps.model(cfg);
      if (cfg.model) checkedModels.add(cfg.model);
      return "Test request succeeded";
    }, "Test request failed. Check the provider, model name, credentials, quota, and connectivity.");
  }
  await check("Automation browser", async () => { await deps.browser(env); return "Browser launched and closed successfully"; }, "Could not launch the browser. Install Chrome/Edge or correct the Chromium path in Network settings.");
  const read = async (path: string, token?: string): Promise<Response> => {
    const u = new URL(path);
    if (!["http:", "https:"].includes(u.protocol)) throw new Error("invalid URL");
    const res = await deps.fetch(u.href, { redirect: "error", signal: AbortSignal.timeout(10_000), ...(token ? { headers: { "X-Scan-Token": token } } : {}) });
    if (!res.ok) throw new Error("API unavailable");
    return res;
  };
  if (burpScan) {
    await check("Burp scanner", async () => {
      if (env.BURP_AUDIT_API) {
        const base = env.BURP_AUDIT_API.replace(/\/+$/, "");
        const res = await read(`${base}/openapi.yaml`, env.BURP_AUDIT_TOKEN);
        if (!(await res.text()).includes("/scan/serial:")) throw new Error("old extension");
        const status = await (await read(`${base}/status`, env.BURP_AUDIT_TOKEN)).json() as { hosts?: unknown[] };
        if (!Array.isArray(status.hosts)) throw new Error("invalid API");
        return "Audit API connected; sequential scanning supported";
      }
      // Burp serves its authenticated API documentation at [service URL]/[API key].
      const base = (env.BURP_API || "http://127.0.0.1:1337").replace(/\/+$/, "");
      const doc = await (await read(`${base}/${env.BURP_API_KEY ? encodeURIComponent(env.BURP_API_KEY) : ""}`)).text();
      if (!/burp/i.test(doc)) throw new Error("not Burp");
      return "REST API connected; scan policy and resource pool are checked when the scan starts";
    }, "Burp check failed. Start the API, check its URL/key/token, and reload the updated Audit extension if used.");
  } else checks.push({ name: "Burp scanner", status: "skipped", message: "Optional post-diagnosis scan is off" });
  return checks;
}

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
    catch (error) { checks.push({ name, status: "error", message: readinessFailure(error, failure, name === "Burp scanner") }); }
  };
  const checkedModels = new Map<string, ReadinessCheck>();
  for (const [tier, model] of [["Deep model", env.VERDICT_LLM_MODEL], ["Light model", env.VERDICT_LLM_FAST_MODEL]] as const) {
    const cfg = resolveLlmConfig(env, { ...(model ? { explicitModel: model } : {}), claudeDefaultModel: tier === "Deep model" ? "claude-opus-4-8" : "claude-sonnet-5" });
    if (cfg.model && checkedModels.has(cfg.model)) {
      const previous = checkedModels.get(cfg.model)!;
      checks.push({ ...previous, name: tier });
      continue;
    }
    await check(tier, async () => {
      if (cfg.provider === "openai" && (!cfg.baseURL || !cfg.model)) throw new Error("missing configuration");
      await deps.model(cfg);
      return "Test request succeeded";
    }, "Test request failed. Check the provider, model name, credentials, quota, and connectivity.");
    if (cfg.model) checkedModels.set(cfg.model, checks.at(-1)!);
  }
  await check("Automation browser", async () => { await deps.browser(env); return "Browser launched and closed successfully"; }, "Could not launch the browser. Install Chrome/Edge or correct the Chromium path in Network settings.");
  const read = async (path: string, token?: string): Promise<Response> => {
    const u = new URL(path);
    if (!["http:", "https:"].includes(u.protocol)) throw new Error("invalid URL");
    const res = await deps.fetch(u.href, { redirect: "error", signal: AbortSignal.timeout(10_000), ...(token ? { headers: { "X-Scan-Token": token } } : {}) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
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

/** Return only known diagnostic categories; providers may echo credentials in arbitrary response bodies. */
export function readinessFailure(error: unknown, fallback: string, burp = false): string {
  const message = error instanceof Error ? error.message : "";
  const code = (error as { cause?: { code?: string } } | null)?.cause?.code;
  if (/x-opencode-session/i.test(message)) return "Provider rejected missing session metadata. Update VERDICT to the latest version.";
  if (/HTTP (401|403)\b/.test(message)) return burp
    ? "Burp authentication failed (HTTP 401/403). Check the Audit extension X-Scan-Token or the REST API key for the selected API."
    : "Provider authentication failed (HTTP 401/403). Check API key permissions and subscription access.";
  if (/HTTP 429\b/.test(message)) return "Provider rate or usage limit reached (HTTP 429). Check quota and retry later.";
  if (/HTTP 404\b/.test(message)) return "Endpoint or model was not found (HTTP 404). Check the Base URL and model ID.";
  if (/HTTP 5\d\d\b/.test(message)) return "The service returned a server error (HTTP 5xx). Retry shortly.";
  if (/HTTP 400\b/.test(message)) return "The service rejected the request (HTTP 400). Check model compatibility and update VERDICT.";
  if (/timed out|timeout/i.test(message)) return "The connection test timed out. Check connectivity and retry.";
  if (code === "ECONNREFUSED") return "Connection refused. Start the service and check its host and port.";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") return "Could not resolve the service hostname. Check DNS and the Base URL.";
  if (code && /CERT|TLS|SSL/.test(code)) return "TLS certificate validation failed. Check the service certificate and trusted proxy settings.";
  if (message === "old extension") return "The Burp Audit extension does not support sequential scans. Load the updated extension.";
  return fallback;
}

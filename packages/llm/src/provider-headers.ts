import { randomUUID } from "node:crypto";

/** One stable identifier per conversation, shared by turns, retries, and context summaries. */
export function createProviderHeaders(baseURL: string): Record<string, string> {
    const headers: Record<string, string> = { "user-agent": "VERDICT/1.0" };
    const url = new URL(baseURL);
    // OpenCode Go requires session routing metadata from third-party clients.
    // https://opencode.ai/docs/go/#where-can-i-use-it
    if (url.hostname === "opencode.ai" && url.pathname.startsWith("/zen/")) headers["x-opencode-session"] = randomUUID();
    return headers;
}

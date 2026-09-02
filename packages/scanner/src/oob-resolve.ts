// Resolve the OOB provider from env. Off unless the operator opted in.
//
//   VERDICT_OOB=none|off          → disabled (even if BURP_AUDIT_API is set for --burp-scan)
//   VERDICT_OOB=interactsh        → Interactsh (INTERACTSH_SERVER default oast.pro; INTERACTSH_TOKEN optional)
//   VERDICT_OOB=burp              → Burp Collaborator via BURP_AUDIT_API
//   unset:
//     INTERACTSH_SERVER set       → Interactsh (server-set is itself opt-in)
//     BURP_AUDIT_API set          → Burp (byte-identical to the previous Collaborator-only path)
//     else                        → none
//
// Public Interactsh is third-party egress (callbacks from the target land on that server) — never default-on.

import { BurpOobProvider } from "./burp-oob.js";
import { DEFAULT_INTERACTSH_SERVER, InteractshOobProvider, type FetchLike } from "./oob-interactsh.js";
import type { OobProvider } from "./oob.js";

export interface ResolveOobOverrides {
    /** --oob flag (interactsh | burp | none). Wins over VERDICT_OOB. */
    mode?: string;
    fetchImpl?: FetchLike;
}

function parseMode(raw: string | undefined): "interactsh" | "burp" | "none" | "auto" {
    const s = (raw ?? "").trim().toLowerCase();
    if (s === "none" || s === "off" || s === "false") return "none";
    if (s === "interactsh" || s === "oast" || s === "interact") return "interactsh";
    if (s === "burp" || s === "collaborator") return "burp";
    return "auto";
}

export async function resolveOobProvider(
    env: Record<string, string | undefined> = process.env,
    ov: ResolveOobOverrides = {},
): Promise<OobProvider | null> {
    const mode = parseMode(ov.mode ?? env.VERDICT_OOB);
    if (mode === "none") return null;

    const wantInteractsh = mode === "interactsh" || (mode === "auto" && !!env.INTERACTSH_SERVER?.trim());
    if (wantInteractsh) {
        const server = env.INTERACTSH_SERVER?.trim() || DEFAULT_INTERACTSH_SERVER;
        return InteractshOobProvider.register({
            server,
            ...(env.INTERACTSH_TOKEN?.trim() ? { token: env.INTERACTSH_TOKEN.trim() } : {}),
            ...(ov.fetchImpl ? { fetchImpl: ov.fetchImpl } : {}),
        });
    }

    const wantBurp = mode === "burp" || (mode === "auto" && !!env.BURP_AUDIT_API?.trim());
    if (wantBurp) {
        const base = env.BURP_AUDIT_API?.trim();
        if (!base) return null;
        const token = env.BURP_AUDIT_TOKEN?.trim();
        return new BurpOobProvider({ base, ...(token ? { token } : {}) });
    }
    return null;
}

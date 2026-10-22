// Mutation ledger detection — runs on every recorded evidence request (EvidenceStore.onRecord).
// Mechanical, never model-reported: any in-scope request that plausibly changed target state and
// returned <400 is appended as a `mutation_recorded` event so operators can ask
// "what did VERDICT change?" (e.g. which account's password now holds which value).

import type { Mutation, MutationAction, StateEvent } from "@veritas/core";
import { mutationLedger } from "@veritas/core";
import { sessionRefOf } from "./checks.js";
import type { PilotSession } from "./tools.js";
import type { EvidenceRecord } from "@veritas/scanner";
import type { LoginCreds } from "@veritas/crawler";

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** Path segments that imply a state change even on GET (Juice Shop's change-password is one). */
const MUTATING_PATH =
  /change-?password|reset-?password|forgot-?password|register|sign-?up|create|update|edit|delete|remove|apply|checkout|order|subscribe|upgrade|invite|assign/i;

/** Body/query keys that carry a credential/identity value worth keeping verbatim. */
const CRED_FIELD = /^(new|repeat|password|pass|pwd|current|confirm|answer|email|username|user|login|token|secret|role|id|userId|name)$/i;

/** Keys worth recording for generic writes (top-level scalars only). */
const FIELD_KEY =
  /^(email|username|user(name)?|login|name|firstName|lastName|password|pwd|new|repeat|current|answer|role|id|userId|email|phone|mobileNum|address|city|zipCode|country|balance|quantity|qty|price|status|comment|review|rating|title|description|deluxe|isAdmin|isActive|amount|securityAnswer)$/i;

const MAX_FIELD_LEN = 200;

function classify(u: URL, method: string, fields: Record<string, string>): MutationAction {
  const p = u.pathname + u.search;
  if (/reset-?password|forgot-?password/i.test(p)) return "password-reset";
  if (/change-?password/i.test(p) || ("new" in fields && /pass|pwd/i.test(p))) return "password-change";
  if (method === "DELETE") return "delete";
  if (/register|sign-?up|\/api\/Users\/?$/i.test(p) && method === "POST") return "register";
  if (method === "POST" || method === "PUT" || method === "PATCH") return "update";
  return "write";
}

function scalarFields(raw: string | null | undefined, u: URL): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of u.searchParams) if (FIELD_KEY.test(k) && v.length <= MAX_FIELD_LEN) out[k] = v;
  if (raw) {
    try {
      const j = JSON.parse(raw) as Record<string, unknown>;
      for (const [k, v] of Object.entries(j)) {
        if (typeof v === "string" && FIELD_KEY.test(k) && v.length <= MAX_FIELD_LEN) out[k] = v;
        else if (typeof v === "number" || typeof v === "boolean") out[k] = String(v);
      }
    } catch {
      // urlencoded form bodies
      for (const pair of raw.split("&")) {
        const eq = pair.indexOf("=");
        if (eq <= 0) continue;
        const k = decodeURIComponent(pair.slice(0, eq));
        const v = decodeURIComponent(pair.slice(eq + 1));
        if (FIELD_KEY.test(k) && v.length <= MAX_FIELD_LEN) out[k] = v;
      }
    }
  }
  return out;
}

/** Whether a recorded request plausibly mutated target state. */
export function isMutating(rec: Pick<EvidenceRecord, "request" | "response">): boolean {
  if (rec.response.status >= 400 || rec.response.status === 0) return false;
  const method = rec.request.method.toUpperCase();
  if (WRITE_METHODS.has(method)) return true;
  // GET mutations exist (change-password via query params) — require a mutation-looking path AND a value-bearing param.
  if (method === "GET") {
    try {
      const u = new URL(rec.request.url);
      if (!MUTATING_PATH.test(u.pathname)) return false;
      return [...u.searchParams.keys()].some((k) => CRED_FIELD.test(k));
    } catch {
      return false;
    }
  }
  return false;
}

/** Build the Mutation for a recorded write, or null when it isn't one. */
export function mutationFromRecord(s: PilotSession, rec: EvidenceRecord): Mutation | null {
  if (!isMutating(rec)) return null;
  let u: URL;
  try {
    u = new URL(rec.request.url);
  } catch {
    return null;
  }
  const method = rec.request.method.toUpperCase();
  const fields = scalarFields(rec.request.body, u);
  if (!Object.keys(fields).length && method === "GET") return null;
  const action = classify(u, method, fields);
  const subject = fields.email ?? fields.username ?? fields.user ?? undefined;
  const sessionRef = sessionRefOf(rec.request.headers ?? {});
  return {
    screenId: rec.screenId !== "pilot" ? rec.screenId : (s.currentScreenId ?? null),
    role: s.currentRole || null,
    sessionRef,
    action,
    ...(subject ? { subject } : {}),
    fields,
    method,
    url: rec.request.url,
    status: rec.response.status,
    evidenceId: rec.id,
  };
}

/** EvidenceStore.onRecord hook: append mutation events for recorded state-changing requests. */
export function detectMutation(s: PilotSession, rec: EvidenceRecord): void {
  const m = mutationFromRecord(s, rec);
  if (!m) return;
  s.store.appendEvent(s.assessmentId, { type: "mutation_recorded", payload: { mutation: m } });
}

/** The manifest creds are stale the moment VERDICT itself changes the account's password (a reset/change probe
 *  that succeeded). Re-login must use the ledger's latest (subject, password) value — the exact case that left
 *  a run unable to log back in after rotating the account's password. Returns creds unchanged when the ledger
 *  has no password row for the username. */
export function effectiveCreds(events: ReadonlyArray<StateEvent>, creds: LoginCreds): LoginCreds {
  const rows = mutationLedger(events).filter(
    (r) => r.field === "password" && r.subject.toLowerCase() === creds.username.toLowerCase(),
  );
  const latest = rows[rows.length - 1]?.value;
  return latest && latest !== creds.password ? { ...creds, password: latest } : creds;
}

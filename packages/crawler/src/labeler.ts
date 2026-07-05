// DESIGN §6.5 — M1 is rule-based provisional labeling (replaced by the LLM in M2).
// Assigns screen_type / param guessedType / labels (attack hints for later phases) by rule.

import type { ApiCall, GuessedType, Param, ParamLoc, ScreenType } from "@veritas/core";
import type { FormObservation } from "./types.js";

const PII_HINTS = [
  "email",
  "e-mail",
  "password",
  "phone",
  "address",
  "ssn",
  "first name",
  "last name",
  "birth",
  "credit card",
  "card number",
];

const URLISH_RE = /(url|uri|redirect|return|next|callback|dest|destination|target|continue)/i;

export function guessParamType(name: string, loc: ParamLoc): GuessedType {
  const n = name.toLowerCase();
  if (loc === "path") return "object_ref"; // an id segment in the path is an object reference
  if (/^(id|.*_id)$/i.test(name) || /id$/.test(name)) return "object_ref";
  if (/(price|amount|cost|total|fee|balance)/.test(n)) return "price";
  if (/(qty|quantity|count|num|stock)/.test(n)) return "qty";
  if (/(file|upload|attachment|document|avatar|photo|image)/.test(n)) return "file";
  if (/(sort|order|filter|status|category|lang|locale|type|role)/.test(n)) return "enum";
  if (URLISH_RE.test(n)) return "free_text"; // SSRF/open-redirect candidates are picked up on the labels side
  return "unknown";
}

export function classifyScreenType(o: {
  urlTemplate: string;
  finalUrl: string;
  forms: FormObservation[];
  title: string;
  visibleText: string;
}): ScreenType {
  const url = `${o.urlTemplate} ${o.finalUrl} ${o.title}`.toLowerCase();
  const fields = o.forms.flatMap((f) => f.fields);
  const hasPassword = fields.some((f) => f.type === "password");
  const hasFile = fields.some((f) => f.type === "file");
  const hasSearch = fields.some(
    (f) => f.type === "search" || /^(q|query|search|keyword|s)$/i.test(f.name),
  );

  if (hasPassword || /\b(login|signin|sign-in|signup|sign-up|register|auth|sso|oauth|logon|forgot|reset|recover|password|passwd|otp|2fa|mfa|magic-?link|passwordless|email-verif|verify-email)\b/.test(url)) {
    return "auth"; // incl. password-reset / account-recovery / email-verify — these are auth-critical, not generic forms
  }
  if (/\b(admin|administrator|manage|backoffice|wp-admin)\b/.test(url)) return "admin";
  if (/\b(checkout|payment|billing|cart|pay|purchase|subscribe|invoice)\b/.test(url)) return "payment";
  if (hasFile || /\b(upload|import)\b/.test(url)) return "upload";
  if (hasSearch || /\b(search|results)\b/.test(url)) return "search";
  if (/\b(dashboard|account|profile|settings|overview)\b/.test(url)) return "dashboard";
  if (/\{id\d*\}$/.test(o.urlTemplate)) return "detail";
  if (o.forms.length > 0) return "form";
  if (o.urlTemplate === "/") return "dashboard";
  return "other";
}

export function deriveLabels(
  screenType: ScreenType,
  params: Param[],
  apis: ApiCall[],
  visibleText: string,
): string[] {
  const labels = new Set<string>();
  if (params.some((p) => p.guessedType === "object_ref")) labels.add("idor-candidate");
  if (screenType === "auth") labels.add("auth");
  if (screenType === "payment") labels.add("payment");
  if (params.some((p) => p.guessedType === "price" || p.guessedType === "qty")) {
    labels.add("price-tampering-candidate");
  }
  if (params.some((p) => URLISH_RE.test(p.name))) labels.add("ssrf-candidate");
  if (PII_HINTS.some((h) => visibleText.toLowerCase().includes(h))) labels.add("pii");
  if (apis.some((a) => a.auth !== "none")) labels.add("authenticated-api");
  return [...labels];
}

export function describeScreen(
  screenType: ScreenType,
  urlTemplate: string,
  params: Param[],
  apis: ApiCall[],
): string {
  const ps = params.length
    ? ` params: ${params.map((p) => `${p.name}(${p.guessedType})`).join(", ")}`
    : "";
  const as = apis.length
    ? ` apis: ${apis.slice(0, 5).map((a) => `${a.method} ${a.urlTemplate}`).join(", ")}`
    : "";
  return `[rule] ${screenType} ${urlTemplate}.${ps}${as}`.trimEnd();
}

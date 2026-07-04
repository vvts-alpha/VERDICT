// DESIGN §6.3 — "stuck detection" heuristics for auth handoff (pure).
// Detects CAPTCHA (Arkose/hCaptcha/reCAPTCHA/Turnstile) / challenge redirect / MFA / 429.
// No cookie injection. On detection, raise a HumanHandoff so a human logs in via a real browser.

import type { HandoffReason } from "@veritas/core";
import type { Observation } from "./types.js";

export interface StuckSignal {
  reason: HandoffReason;
  detail: string;
}

const CAPTCHA_RE =
  /(recaptcha|hcaptcha|arkose|funcaptcha|turnstile|px-captcha|i['’ ]?m not a robot|verify you are human|are you a robot|complete the captcha|security check|checking your browser)/i;
const MFA_RE = /(two[-\s]?factor|\b2fa\b|\bmfa\b|one[-\s]?time|verification code|authenticator app|\botp\b)/i;

export function detectStuck(o: Observation): StuckSignal | null {
  if (CAPTCHA_RE.test(o.domSkeleton) || CAPTCHA_RE.test(o.visibleText)) {
    return { reason: "captcha", detail: "CAPTCHA widget detected (Arkose/hCaptcha/reCAPTCHA/Turnstile)" };
  }
  try {
    const path = new URL(o.finalUrl).pathname.toLowerCase();
    if (/\/(challenge|captcha|verify|cdn-cgi\/challenge)/.test(path)) {
      return { reason: "captcha", detail: `challenge redirect: ${path}` };
    }
  } catch {
    /* ignore */
  }
  if (MFA_RE.test(o.visibleText)) {
    return { reason: "auth", detail: "MFA / verification step detected" };
  }
  if (o.status === 429) {
    return { reason: "rate_limit", detail: "HTTP 429 (rate limited)" };
  }
  return null;
}

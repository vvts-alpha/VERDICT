// DESIGN §6.3 — 認証ハンドオフの「詰まり検出」ヒューリスティクス(純粋)。
// CAPTCHA(Arkose/hCaptcha/reCAPTCHA/Turnstile)/ challenge リダイレクト / MFA / 429 を検出。
// Cookie 注入はしない。検出したら HumanHandoff を起票し、人間が生ブラウザでログインする想定。

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

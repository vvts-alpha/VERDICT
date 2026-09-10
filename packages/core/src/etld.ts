import { parse } from "tldts";

/** Return a PSL registrable domain, including private hosting boundaries; unknown suffixes fail closed. */
export function knownRegistrableDomain(hostname: string): string | null {
  const result = parse(hostname.toLowerCase().replace(/\.$/, ""), { allowPrivateDomains: true });
  return result.isIcann || result.isPrivate ? result.domain : null;
}

/** IPs, public suffixes, and unknown names remain exact hosts. */
export function registrableDomain(hostname: string): string {
  return knownRegistrableDomain(hostname) ?? hostname.toLowerCase().replace(/\.$/, "");
}

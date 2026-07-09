// ASR — subdomain-takeover detection. A dangling CNAME to a de-provisioned third-party service (S3, GitHub Pages,
// Heroku, Azure, …) that an attacker can claim to serve content on the victim's subdomain — a classic bug-bounty
// finding. Signal = the service's "unclaimed" response fingerprint, and/or a CNAME to a takeover-able service with
// nothing serving. Fingerprints curated from can-i-take-over-xyz. Pure; the CNAME chain + body come from the probe.

import type { AssetTakeover } from "@veritas/core";

interface Fingerprint {
    service: string;
    /** CNAME target patterns for the service. */
    cname: RegExp[];
    /** The response body signature of an *unclaimed* instance. */
    fingerprint?: RegExp;
    /** Generally takeover-able (per can-i-take-over-xyz); false = edge-case, verify manually. */
    vulnerable: boolean;
    note: string;
}

export const TAKEOVER_FINGERPRINTS: Fingerprint[] = [
    { service: "AWS/S3", cname: [/s3[.-][a-z0-9-]*\.amazonaws\.com$/i, /\.s3\.amazonaws\.com$/i], fingerprint: /<Code>NoSuchBucket<\/Code>|The specified bucket does not exist/i, vulnerable: true, note: "Create the S3 bucket named by the CNAME and serve content." },
    { service: "GitHub Pages", cname: [/\.github\.io$/i], fingerprint: /There isn't a GitHub Pages site here|For root URLs \(like http/i, vulnerable: true, note: "Create a GitHub Pages repo with a CNAME file for this host." },
    { service: "Heroku", cname: [/\.herokudns\.com$/i, /\.herokuapp\.com$/i, /\.herokussl\.com$/i], fingerprint: /No such app|no-such-app\.html/i, vulnerable: true, note: "Register the Heroku app name in the CNAME." },
    { service: "Fastly", cname: [/\.fastly\.net$/i], fingerprint: /Fastly error: unknown domain/i, vulnerable: true, note: "Add the domain to a Fastly service." },
    { service: "Azure", cname: [/\.azurewebsites\.net$/i, /\.cloudapp\.net$/i, /\.cloudapp\.azure\.com$/i, /\.trafficmanager\.net$/i, /\.blob\.core\.windows\.net$/i, /\.azureedge\.net$/i], fingerprint: /404 Web Site not found|The specified blob does not exist/i, vulnerable: true, note: "Claim the Azure resource named by the CNAME." },
    { service: "Surge.sh", cname: [/\.surge\.sh$/i], fingerprint: /project not found/i, vulnerable: true, note: "Deploy to surge.sh with this domain." },
    { service: "Bitbucket", cname: [/\.bitbucket\.io$/i], fingerprint: /Repository not found/i, vulnerable: true, note: "Create a Bitbucket Cloud site for this host." },
    { service: "Ghost", cname: [/\.ghost\.io$/i], fingerprint: /The thing you were looking for is no longer here/i, vulnerable: true, note: "Register the Ghost.io subdomain." },
    { service: "Pantheon", cname: [/\.pantheonsite\.io$/i], fingerprint: /The gods are wise|404 error unknown site/i, vulnerable: true, note: "Claim the Pantheon site." },
    { service: "Tumblr", cname: [/\.domains\.tumblr\.com$/i], fingerprint: /doesn't currently exist at this address/i, vulnerable: true, note: "Register the Tumblr blog + map the domain." },
    { service: "Webflow", cname: [/\.proxy\.webflow\.com$/i, /\.webflow\.io$/i], fingerprint: /The page you are looking for doesn't exist or has been moved/i, vulnerable: true, note: "Add this custom domain in a Webflow project." },
    { service: "WordPress.com", cname: [/\.wordpress\.com$/i], fingerprint: /Do you want to register/i, vulnerable: true, note: "Register the WordPress.com subdomain." },
    { service: "Shopify", cname: [/\.myshopify\.com$/i], fingerprint: /Sorry, this shop is currently unavailable/i, vulnerable: false, note: "Shopify — usually NOT takeover-able; verify (the exact myshopify name must be free)." },
    { service: "Zendesk", cname: [/\.zendesk\.com$/i], fingerprint: /Help Center Closed|no longer exists/i, vulnerable: false, note: "Zendesk host mapping — edge-case, verify manually." },
    { service: "Cloudfront", cname: [/\.cloudfront\.net$/i], fingerprint: /ERROR: The request could not be satisfied/i, vulnerable: false, note: "CloudFront — usually NOT directly takeover-able; verify the distribution is unclaimed." },
];

/** Detect a subdomain takeover from a host's CNAME chain + HTTP response. Returns null if there's no signal. */
export function detectTakeover(input: { cnames: string[]; status: number | null; body: string }): AssetTakeover | null {
    // Strongest signal: the service is serving its "unclaimed" page.
    for (const fp of TAKEOVER_FINGERPRINTS) {
        if (!fp.fingerprint || !fp.fingerprint.test(input.body)) continue;
        const cname = input.cnames.find((c) => fp.cname.some((re) => re.test(c)));
        return {
            service: fp.service,
            vulnerable: fp.vulnerable,
            confidence: cname ? "likely" : "potential",
            ...(cname ? { cname } : {}),
            note: fp.note,
        };
    }
    // Dangling CNAME: points to a takeover-able service, but nothing resolved/served.
    if (input.status === null) {
        for (const fp of TAKEOVER_FINGERPRINTS) {
            if (!fp.vulnerable) continue;
            const cname = input.cnames.find((c) => fp.cname.some((re) => re.test(c)));
            if (cname) {
                return { service: fp.service, vulnerable: true, confidence: "potential", cname, note: `Dangling CNAME to ${fp.service} (nothing resolves). ${fp.note}` };
            }
        }
    }
    return null;
}

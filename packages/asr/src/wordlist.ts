// ASR S3 — the bundled default subdomain wordlist for `--brute` (dnsx or the native fallback). A small ~100-word list
// of the highest-hit-rate subdomain labels (à la T3MP3ST's subdomain_enum), so `--brute` is self-contained with zero
// external files. Override with `--wordlist <file>`. Kept as a TS array (not a data file) so it bundles cleanly with
// no import-assertion / read-path concerns.

export const DEFAULT_SUBDOMAIN_WORDLIST: string[] = [
    // web / edge
    "www", "www2", "web", "portal", "app", "apps", "m", "mobile", "cdn", "static", "assets", "img", "images", "media", "files", "download", "downloads",
    // api / services
    "api", "api2", "apis", "gateway", "gw", "service", "services", "rest", "graphql", "grpc", "ws", "socket", "rpc",
    // auth / identity
    "auth", "sso", "login", "account", "accounts", "id", "identity", "oauth", "idp", "secure",
    // environments
    "dev", "development", "test", "testing", "qa", "uat", "stage", "staging", "stg", "preprod", "prod", "production", "sandbox", "demo", "beta", "alpha", "canary",
    // ops / infra
    "admin", "administrator", "internal", "intranet", "corp", "vpn", "remote", "ssh", "bastion", "jump", "proxy", "lb", "ns", "ns1", "ns2", "mx", "smtp", "mail", "email", "webmail", "imap", "pop",
    // data / storage
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "cache", "storage", "s3", "backup", "backups", "ftp", "sftp",
    // tooling / ci
    "git", "gitlab", "github", "jenkins", "ci", "build", "deploy", "registry", "docker", "k8s", "kube", "argocd", "grafana", "kibana", "prometheus", "monitor", "monitoring", "status", "metrics", "logs", "log",
    // content / collab
    "blog", "news", "docs", "doc", "wiki", "support", "help", "helpdesk", "jira", "confluence", "crm", "erp", "shop", "store", "cart", "checkout", "pay", "payment", "billing", "dashboard", "console", "manage", "panel", "cpanel",
];

/** Parse a `--wordlist` file's text → sanitized DNS labels (lowercase alnum/hyphen/underscore, deduped; `#` comments + blanks dropped). */
export function parseWordlist(text: string): string[] {
    const seen = new Set<string>();
    for (const raw of text.split(/\r?\n/)) {
        const w = raw.trim().toLowerCase();
        if (!w || w.startsWith("#")) continue;
        if (/^[a-z0-9_-]+$/.test(w)) seen.add(w);
    }
    return [...seen];
}

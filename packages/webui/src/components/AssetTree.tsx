import { useMemo, useState, type CSSProperties, type ReactNode } from "react";
import type { Asset, AssetInventory, AssetFinding, FindingSeverity, ListingEntry } from "@veritas/core";

// ASR asset rendering — the LEFT host tree (AssetTree, uses the same .tree/.node CSS as the web SITE TREE), the Host
// detail pane (HostDetail, "Host" tab) and the Findings list (AssetFindings, "Findings" tab). Same viewer shape and
// same design system as the web/API viewer. Read-only projection of the asset inventory.

const SEV_RANK: Record<FindingSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Discovery-source provenance (S5): a compact label + tooltip per AssetSource. `active` = an ACTIVE DNS brute (--brute),
// the only source that sends resolution packets; the rest are passive/offline. Exported so the statusbar can summarize.
export const SOURCE_META: Record<string, { label: string; title: string; active?: boolean }> = {
    "crt.sh": { label: "CT", title: "crt.sh — passive certificate-transparency logs" },
    import: { label: "import", title: "imported (subfinder / recon.sh httpx / hosts list)" },
    active: { label: "brute", title: "active DNS brute (--brute: dnsx / native node:dns)", active: true },
    seed: { label: "seed", title: "operator-seeded" },
};
const sourceLabel = (s: string): string => SOURCE_META[s]?.label ?? s;
const sourceTitle = (s: string): string => SOURCE_META[s]?.title ?? s;

function topSev(fs: AssetFinding[] | undefined): FindingSeverity | null {
    let top: FindingSeverity | null = null;
    for (const f of fs ?? []) if (top === null || SEV_RANK[f.severity] > SEV_RANK[top]) top = f.severity;
    return top;
}
function bandRank(b: string | undefined): number {
    return b === "critical" ? 3 : b === "high" ? 2 : b === "medium" ? 1 : 0;
}
function statusColor(s: number | null | undefined): string {
    if (s == null) return "var(--muted)";
    if (s >= 200 && s < 300) return "var(--ok)";
    if (s >= 300 && s < 400) return "var(--accent)";
    if (s === 401 || s === 403) return "var(--warn)";
    if (s >= 500) return "var(--err)";
    return "var(--muted)";
}
// Map an asset to a web SITE-TREE status class (drives the .dot colour): finding / suspected / clean / queued.
function hostStatus(a: Asset): string {
    if (!a.alive) return "queued";
    const sev = topSev(a.findings);
    if (sev === "critical" || sev === "high") return "finding";
    if (sev) return "suspected";
    return "clean";
}

type NodeKind = "domain" | "ip" | "port" | "path" | "listing";
interface TNode {
    kind: NodeKind;
    label: string;
    key: string;
    asset?: Asset;
    escalate?: boolean;
    note?: string;
    status?: number | null;
    children: TNode[];
}

function listingNodes(entries: ListingEntry[], parentKey: string): TNode[] {
    return entries.map((e) => ({
        kind: "listing" as const,
        label: e.type === "dir" ? `${e.name}/` : e.name,
        key: `${parentKey}|${e.path}`,
        children: e.children ? listingNodes(e.children, `${parentKey}|${e.path}`) : [],
    }));
}

// Flat host list — each host is a top node labelled with its full FQDN (sorted by score), expandable to its
// IP → port, curated-path hits and directory listing. Flatter + more readable than a subdomain-label trie.
function buildAssetTree(assets: Asset[]): TNode {
    const root: TNode = { kind: "domain", label: "", key: "root", children: [] };
    for (const a of assets) {
        const host: TNode = { kind: "domain", label: a.host, key: a.host, asset: a, children: [] };
        const port = a.scheme === "http" ? 80 : 443;
        for (const ip of a.resolved) {
            host.children.push({
                kind: "ip",
                label: ip,
                key: `${a.host}|ip|${ip}`,
                children: a.alive ? [{ kind: "port", label: `:${port}`, key: `${a.host}|ip|${ip}|${port}`, status: a.status, children: [] }] : [],
            });
        }
        for (const h of a.notablePaths ?? []) {
            host.children.push({ kind: "path", label: h.path, key: `${a.host}|path|${h.path}`, escalate: h.escalate, note: h.note, status: h.status, children: [] });
        }
        if (a.listing?.length) {
            host.children.push({ kind: "listing", label: "listing", key: `${a.host}|listing`, children: listingNodes(a.listing, `${a.host}|listing`) });
        }
        root.children.push(host);
    }
    sortTree(root);
    return root;
}

function sortTree(node: TNode): void {
    node.children.sort((a, b) => {
        const ko = (k: NodeKind): number => (k === "domain" ? 0 : k === "ip" ? 1 : k === "path" ? 2 : 3);
        if (ko(a.kind) !== ko(b.kind)) return ko(a.kind) - ko(b.kind);
        if (a.kind === "domain" && b.kind === "domain") {
            const r = bandRank(b.asset?.score?.band) - bandRank(a.asset?.score?.band);
            if (r !== 0) return r;
            const s = (b.asset?.score?.total ?? -1) - (a.asset?.score?.total ?? -1);
            if (s !== 0) return s;
            return a.label.localeCompare(b.label);
        }
        if (a.kind === "path" && b.kind === "path") return Number(!!b.escalate) - Number(!!a.escalate);
        return 0;
    });
    for (const c of node.children) sortTree(c);
}

function segStyle(node: TNode): CSSProperties {
    if (node.kind === "ip" || node.kind === "port") return { color: "#7aa2f7", fontFamily: "ui-monospace, monospace" };
    if (node.kind === "path") return { color: node.escalate ? "var(--err)" : "var(--muted)", fontFamily: "ui-monospace, monospace" };
    if (node.kind === "listing") return { color: node.label.endsWith("/") ? "#d4b483" : "var(--muted)", fontFamily: "ui-monospace, monospace" };
    return {};
}

// One tree row — reuses the web SITE TREE markup/classes (li > .node > .twist/.dot/.seg …).
function Node({ node, collapsed, toggle, selected, onSelect }: {
    node: TNode; collapsed: Set<string>; toggle: (k: string) => void; selected: string | null; onSelect: (asset: Asset, key: string) => void;
}) {
    const hasKids = node.children.length > 0;
    const open = !collapsed.has(node.key);
    const isHost = node.kind === "domain" && !!node.asset;
    const isSel = isHost && selected === node.key;
    const findings = node.asset?.findings?.length ?? 0;
    return (
        <li>
            <div
                className={`node ${isSel ? "sel" : ""} ${isHost ? hostStatus(node.asset!) : ""}`}
                onClick={() => (isHost ? onSelect(node.asset!, node.key) : hasKids ? toggle(node.key) : undefined)}
            >
                {hasKids ? (
                    <button type="button" className={`twist ${open ? "open" : ""}`} onClick={(e) => { e.stopPropagation(); toggle(node.key); }} aria-label={open ? "collapse" : "expand"}>
                        ▸
                    </button>
                ) : (
                    <span className="twist-spacer" />
                )}
                {isHost ? <span className="dot" /> : <span className="twist-spacer" style={{ width: 8 }} />}
                <span className="seg" style={segStyle(node)}>{node.label}</span>
                {node.kind === "port" ? <span className="stype" style={{ color: statusColor(node.status) }}>{node.status ?? ""}</span> : null}
                {isHost && node.asset?.score ? <span className="stype" title={`score ${node.asset.score.total}`}>{node.asset.score.band}</span> : null}
                {isHost && node.asset && node.asset.source !== "crt.sh" ? (
                    <span className="asr-src" data-src={node.asset.source} title={sourceTitle(node.asset.source)}>{sourceLabel(node.asset.source)}</span>
                ) : null}
                {isHost && node.asset?.promoted ? <span className="asr-piloted-chip" title="promoted to a pilot run">piloted</span> : null}
                {isHost && findings > 0 ? <span className="roll" title={`${findings} finding(s)`}>{findings}</span> : null}
            </div>
            {hasKids && open ? (
                <ul>
                    {node.children.map((c) => (
                        <Node key={c.key} node={c} collapsed={collapsed} toggle={toggle} selected={selected} onSelect={onSelect} />
                    ))}
                </ul>
            ) : null}
        </li>
    );
}

/** The LEFT host tree (same .tree markup as the web SITE TREE). */
export function AssetTree({ inv, selected, onSelect }: { inv: AssetInventory; selected: string | null; onSelect: (asset: Asset, key: string) => void }) {
    const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
    const tree = useMemo(() => buildAssetTree(inv.assets), [inv]);
    const toggle = (k: string): void => setCollapsed((prev) => { const n = new Set(prev); if (n.has(k)) n.delete(k); else n.add(k); return n; });
    return (
        <nav className="tree">
            <div className="pane-title">HOSTS</div>
            {tree.children.length === 0 ? (
                <p className="muted" style={{ padding: 12 }}>no hosts yet</p>
            ) : (
                <ul className="root">
                    {tree.children.map((c) => (
                        <Node key={c.key} node={c} collapsed={collapsed} toggle={toggle} selected={selected} onSelect={onSelect} />
                    ))}
                </ul>
            )}
        </nav>
    );
}

// A recon finding card — uses the same .finding / .sevpill / .finding-head/-title/-desc markup as the web Findings tab.
function Finding({ f, host, onJump }: { f: AssetFinding; host?: string; onJump?: (h: string) => void }) {
    return (
        <div className={`finding sev-${f.severity}`}>
            <div className="finding-head">
                <span className={`sevpill sev-${f.severity}`}>{f.severity}</span>
                <span className="finding-title">{f.title}</span>
                {host ? (
                    <span className="finding-id">
                        {onJump ? (
                            <button type="button" className="screenlink" onClick={() => onJump(host)}>{host}</button>
                        ) : (
                            host
                        )}
                    </span>
                ) : null}
            </div>
            <p className="finding-desc">{f.detail}</p>
        </div>
    );
}

/** The Host tab — one host's full detail. */
export function HostDetail({ id, asset }: { id: string; asset: Asset | null }) {
    if (!asset) return <p className="muted">Select a host from the tree.</p>;
    const thumb = asset.screenshot ? `/api/assessments/${encodeURIComponent(id)}/hosts/${encodeURIComponent(asset.host)}/screenshot` : null;
    const scheme = asset.scheme ?? "https";
    const findings = [...(asset.findings ?? [])].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
    const meta = (label: string, value: ReactNode) => (
        <div className="asr-meta">
            <span className="asr-meta-k">{label}</span>
            <span className="asr-meta-v">{value}</span>
        </div>
    );
    return (
        <div className="asr-host">
            <div className="asr-host-h">
                <a href={`${scheme}://${asset.host}/`} target="_blank" rel="noreferrer">{asset.host} ↗</a>
                {asset.score ? <span className="stype">{asset.score.band} · {asset.score.total}</span> : null}
                {asset.promoted ? (
                    <a className="asr-piloted-link" href={`?id=${encodeURIComponent(asset.promoted)}`} title="open the pilot run promoted from this host">→ piloted</a>
                ) : null}
            </div>
            {thumb ? <img className="asr-shot" src={thumb} alt={asset.host} /> : null}
            {findings.length > 0 ? (
                <>
                    <div className="pane-subtitle">Recon findings ({findings.length})</div>
                    <div className="findings">{findings.map((f, i) => <Finding key={i} f={f} />)}</div>
                </>
            ) : null}
            <div className="asr-metabox">
                {meta("status", <span style={{ color: statusColor(asset.status) }}>{asset.status ?? "—"}</span>)}
                {meta("source", <span title={sourceTitle(asset.source)}>{sourceLabel(asset.source)}</span>)}
                {meta("scheme", asset.scheme ?? "—")}
                {asset.title ? meta("title", asset.title) : null}
                {meta("resolved", asset.resolved.length ? asset.resolved.join(", ") : "no DNS")}
                {asset.tech.length ? meta("tech", asset.tech.join(" · ")) : null}
                {asset.score ? meta("score", `${asset.score.total} · ` + Object.entries(asset.score.components).map(([k, v]) => `${k[0]}${v}`).join(" ")) : null}
            </div>
            {asset.ai ? (
                <div className="asr-ai">
                    <div className="asr-ai-h">AI triage — {asset.ai.category} ({asset.ai.band})</div>
                    {asset.ai.rationale ? <div className="asr-ai-r">{asset.ai.rationale}</div> : null}
                    {asset.ai.angle ? <div className="asr-ai-a"><b>angle:</b> {asset.ai.angle}</div> : null}
                </div>
            ) : null}
        </div>
    );
}

/** The Findings tab — every recon finding across hosts, with the same section/filterbar/cards as the web Findings tab. */
export function AssetFindings({ assets, onJump }: { assets: Asset[]; onJump: (host: string) => void }) {
    const [sev, setSev] = useState<FindingSeverity | null>(null);
    const all = assets
        .flatMap((a) => (a.findings ?? []).map((f) => ({ host: a.host, f })))
        .sort((x, y) => SEV_RANK[y.f.severity] - SEV_RANK[x.f.severity]);
    if (all.length === 0)
        return (
            <section className="findings-tab">
                <h2>Findings (0)</h2>
                <p className="muted">No recon findings yet.</p>
            </section>
        );
    const counts: Record<string, number> = {};
    for (const r of all) counts[r.f.severity] = (counts[r.f.severity] ?? 0) + 1;
    const shown = sev ? all.filter((r) => r.f.severity === sev) : all;
    return (
        <section className="findings-tab">
            <h2>Findings ({all.length})</h2>
            <div className="filterbar">
                <button type="button" className={sev === null ? "active" : ""} onClick={() => setSev(null)}>all ({all.length})</button>
                {(["critical", "high", "medium", "low", "info"] as const)
                    .filter((s) => counts[s])
                    .map((s) => (
                        <button type="button" key={s} className={`sevf sevf-${s}${sev === s ? " active" : ""}`} onClick={() => setSev(sev === s ? null : s)}>
                            {s} ({counts[s]})
                        </button>
                    ))}
            </div>
            <div className="findings">
                {shown.map((r, i) => <Finding key={i} f={r.f} host={r.host} onJump={onJump} />)}
            </div>
        </section>
    );
}

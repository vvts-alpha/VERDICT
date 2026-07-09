import { useEffect, useMemo, useState, type ReactNode } from "react";
import type { Asset, AssetInventory, AssetFinding, FindingSeverity, ListingEntry } from "@veritas/core";

// ASR viewer — a DOMAIN-rooted tree (its own assessment type, distinct from the web/API viewer): apex → subdomains
// (score + top-finding next to the host) → resolved IP → port, plus curated-path hits and an open directory listing.
// Click a host for its full detail + recon findings on the right. Read-only projection of asset_inventory.json.

const SEV_COLOR: Record<FindingSeverity, string> = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280" };
const SEV_RANK: Record<FindingSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

function topSev(fs: AssetFinding[] | undefined): FindingSeverity | null {
    let top: FindingSeverity | null = null;
    for (const f of fs ?? []) if (top === null || SEV_RANK[f.severity] > SEV_RANK[top]) top = f.severity;
    return top;
}
function bandColor(b: string | undefined): string {
    return b === "critical" ? "#ef4444" : b === "high" ? "#f97316" : b === "medium" ? "#eab308" : "#4b5563";
}
function bandRank(b: string | undefined): number {
    return b === "critical" ? 3 : b === "high" ? 2 : b === "medium" ? 1 : 0;
}
function statusColor(s: number | null | undefined): string {
    if (s == null) return "#8b93a7";
    if (s >= 200 && s < 300) return "#22c55e";
    if (s >= 300 && s < 400) return "#3b82f6";
    if (s === 401 || s === 403) return "#eab308";
    if (s >= 500) return "#ef4444";
    return "#8b93a7";
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

function buildDomainTree(apex: string, assets: Asset[]): TNode {
    const root: TNode = { kind: "domain", label: apex, key: apex, children: [] };
    for (const a of assets) {
        const sub = a.host === apex ? "" : a.host.endsWith(`.${apex}`) ? a.host.slice(0, a.host.length - apex.length - 1) : a.host;
        const labels = sub ? sub.split(".").reverse() : [];
        let node = root;
        let path = apex;
        for (const label of labels) {
            path = `${label}.${path}`;
            let child = node.children.find((c) => c.kind === "domain" && c.label === label);
            if (!child) {
                child = { kind: "domain", label, key: path, children: [] };
                node.children.push(child);
            }
            node = child;
        }
        node.asset = a;
        const port = a.scheme === "http" ? 80 : 443;
        for (const ip of a.resolved) {
            node.children.push({
                kind: "ip",
                label: ip,
                key: `${node.key}|ip|${ip}`,
                children: a.alive ? [{ kind: "port", label: `:${port}`, key: `${node.key}|ip|${ip}|${port}`, status: a.status, children: [] }] : [],
            });
        }
        for (const h of a.notablePaths ?? []) {
            node.children.push({ kind: "path", label: h.path, key: `${node.key}|path|${h.path}`, escalate: h.escalate, note: h.note, status: h.status, children: [] });
        }
        if (a.listing?.length) {
            node.children.push({ kind: "listing", label: "listing", key: `${node.key}|listing`, children: listingNodes(a.listing, `${node.key}|listing`) });
        }
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

function Chip({ color, children, title }: { color: string; children: ReactNode; title?: string }) {
    return (
        <span title={title} style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10.5, fontWeight: 700, letterSpacing: 0.2, color, background: `${color}22`, border: `1px solid ${color}55`, borderRadius: 999, padding: "1px 7px", whiteSpace: "nowrap" }}>
            {children}
        </span>
    );
}
function SevDot({ sev }: { sev: FindingSeverity }) {
    return <span style={{ width: 7, height: 7, borderRadius: 999, background: SEV_COLOR[sev], display: "inline-block", flex: "0 0 auto" }} />;
}

function Row({ node, depth, collapsed, toggle, selected, onSelect }: {
    node: TNode; depth: number; collapsed: Set<string>; toggle: (k: string) => void; selected: string | null; onSelect: (n: TNode) => void;
}) {
    const hasKids = node.children.length > 0;
    const open = !collapsed.has(node.key);
    const isHost = node.kind === "domain" && !!node.asset;
    const sel = selected === node.key;
    const isDir = node.kind === "listing" && (node.label.endsWith("/") || node.children.length > 0);
    const icon = node.kind === "ip" ? "↳" : node.kind === "path" ? (node.escalate ? "!" : "·") : "";
    const color = node.kind === "path" ? (node.escalate ? "#f87171" : "#8b93a7") : node.kind === "ip" || node.kind === "port" ? "#7aa2f7" : node.kind === "listing" ? (isDir ? "#d4b483" : "#8b93a7") : "#e6e9ef";
    const sev = isHost ? topSev(node.asset?.findings) : null;
    return (
        <div>
            <div
                onClick={() => (isHost ? onSelect(node) : hasKids ? toggle(node.key) : undefined)}
                style={{ display: "flex", alignItems: "center", gap: 5, padding: "3px 8px", paddingLeft: 8 + depth * 15, cursor: isHost || hasKids ? "pointer" : "default", background: sel ? "#1d2637" : "transparent", borderLeft: sel ? "2px solid #3b82f6" : "2px solid transparent", fontFamily: node.kind === "ip" || node.kind === "port" ? "ui-monospace, monospace" : "inherit", fontSize: 12.5, lineHeight: 1.6 }}
                onMouseEnter={(e) => { if (!sel) e.currentTarget.style.background = "#161c28"; }}
                onMouseLeave={(e) => { if (!sel) e.currentTarget.style.background = "transparent"; }}
            >
                <span onClick={(e) => { if (hasKids) { e.stopPropagation(); toggle(node.key); } }} style={{ width: 12, color: "#5b6478", cursor: hasKids ? "pointer" : "default", flex: "0 0 auto" }}>
                    {hasKids ? (open ? "▾" : "▸") : ""}
                </span>
                {icon ? <span style={{ color, width: 13, flex: "0 0 auto" }}>{icon}</span> : null}
                <span style={{ color, fontWeight: isHost ? 600 : 400 }}>{node.label}</span>
                {node.kind === "port" ? <span style={{ marginLeft: 4, color: statusColor(node.status), fontSize: 11.5 }}>{node.status ?? ""}</span> : null}
                {isHost && node.asset?.score ? <Chip color={bandColor(node.asset.score.band)} title={Object.entries(node.asset.score.components).map(([k, v]) => `${k}: ${v}`).join("  ")}>{node.asset.score.band.toUpperCase()} {node.asset.score.total}</Chip> : null}
                {sev ? <span title={`${node.asset?.findings?.length} recon finding(s)`} style={{ display: "inline-flex", alignItems: "center", gap: 3 }}><SevDot sev={sev} /><span style={{ fontSize: 10.5, color: SEV_COLOR[sev] }}>{node.asset?.findings?.length}</span></span> : null}
                {isHost && node.asset?.ai ? <span style={{ marginLeft: 2, fontSize: 11, color: "#a78bfa" }}>· {node.asset.ai.category}</span> : null}
            </div>
            {open && hasKids ? node.children.map((c) => <Row key={c.key} node={c} depth={depth + 1} collapsed={collapsed} toggle={toggle} selected={selected} onSelect={onSelect} />) : null}
        </div>
    );
}

function Detail({ id, asset }: { id: string; asset: Asset | null }) {
    if (!asset) return <div style={{ color: "#5b6478", padding: 24, fontSize: 13 }}>Select a host to see its detail.</div>;
    const thumb = asset.screenshot ? `/api/assessments/${encodeURIComponent(id)}/hosts/${encodeURIComponent(asset.host)}/screenshot` : null;
    const scheme = asset.scheme ?? "https";
    const findings = [...(asset.findings ?? [])].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
    const meta = (label: string, value: ReactNode) => (
        <div style={{ display: "flex", gap: 10, fontSize: 12.5, padding: "3px 0" }}>
            <span style={{ color: "#5b6478", minWidth: 84 }}>{label}</span>
            <span style={{ color: "#c9cfdb", wordBreak: "break-all", fontFamily: "ui-monospace, monospace" }}>{value}</span>
        </div>
    );
    return (
        <div style={{ padding: 18, overflowY: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
                <a href={`${scheme}://${asset.host}/`} target="_blank" rel="noreferrer" style={{ fontWeight: 700, fontSize: 15.5, color: "#e6e9ef", textDecoration: "none" }}>{asset.host} ↗</a>
                {asset.score ? <Chip color={bandColor(asset.score.band)}>{asset.score.band.toUpperCase()} · {asset.score.total}</Chip> : null}
            </div>
            {thumb ? <img src={thumb} alt={asset.host} style={{ width: "100%", maxHeight: 190, objectFit: "cover", objectPosition: "top", borderRadius: 8, border: "1px solid #232a38", marginBottom: 14 }} /> : null}

            {findings.length > 0 ? (
                <div style={{ marginBottom: 14 }}>
                    <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6, color: "#5b6478", marginBottom: 6 }}>Recon findings ({findings.length})</div>
                    {findings.map((f, i) => (
                        <div key={i} style={{ display: "flex", gap: 9, padding: "8px 10px", background: "#12161f", border: `1px solid ${SEV_COLOR[f.severity]}33`, borderLeft: `3px solid ${SEV_COLOR[f.severity]}`, borderRadius: 7, marginBottom: 6 }}>
                            <div style={{ flex: 1 }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 2 }}>
                                    <Chip color={SEV_COLOR[f.severity]}>{f.severity.toUpperCase()}</Chip>
                                    <span style={{ fontSize: 13, fontWeight: 600, color: "#e6e9ef" }}>{f.title}</span>
                                </div>
                                <div style={{ fontSize: 12, color: "#9aa3b5", fontFamily: "ui-monospace, monospace" }}>{f.detail}</div>
                            </div>
                        </div>
                    ))}
                </div>
            ) : null}

            <div style={{ padding: "10px 12px", background: "#12161f", border: "1px solid #232a38", borderRadius: 8, marginBottom: 12 }}>
                {meta("status", <span style={{ color: statusColor(asset.status) }}>{asset.status ?? "—"}</span>)}
                {meta("scheme", asset.scheme ?? "—")}
                {asset.title ? meta("title", asset.title) : null}
                {meta("resolved", asset.resolved.length ? asset.resolved.join(", ") : "no DNS")}
                {asset.tech.length ? meta("tech", asset.tech.join(" · ")) : null}
                {asset.score ? meta("score", `${asset.score.total} · ` + Object.entries(asset.score.components).map(([k, v]) => `${k[0]}${v}`).join(" ")) : null}
            </div>

            {asset.ai ? (
                <div style={{ padding: "10px 12px", background: "#171326", border: "1px solid #2e2350", borderRadius: 8 }}>
                    <div style={{ fontSize: 12, color: "#a78bfa", fontWeight: 700, marginBottom: 5 }}>AI triage — {asset.ai.category} ({asset.ai.band})</div>
                    {asset.ai.rationale ? <div style={{ fontSize: 12.5, color: "#9aa3b5", marginBottom: 5 }}>{asset.ai.rationale}</div> : null}
                    {asset.ai.angle ? <div style={{ fontSize: 12.5, color: "#d4d9e3" }}><b style={{ color: "#a78bfa" }}>angle:</b> {asset.ai.angle}</div> : null}
                </div>
            ) : null}
        </div>
    );
}

export function AssetTree({ id }: { id: string }) {
    const [inv, setInv] = useState<AssetInventory | null>(null);
    const [err, setErr] = useState(false);
    const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
    const [selected, setSelected] = useState<string | null>(null);
    const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

    useEffect(() => {
        let alive = true;
        const load = (): void => {
            fetch(`/api/assessments/${encodeURIComponent(id)}/assets`)
                .then((r) => r.json())
                .then((v: AssetInventory) => { if (alive) { setInv(v); setErr(false); } })
                .catch(() => { if (alive) setErr(true); });
        };
        load();
        const t = window.setInterval(load, 5000);
        return () => { alive = false; window.clearInterval(t); };
    }, [id]);

    const tree = useMemo(() => (inv ? buildDomainTree(inv.apex || "assets", inv.assets) : null), [inv]);
    const tally = useMemo(() => {
        const t: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        let takeovers = 0;
        for (const a of inv?.assets ?? []) {
            if (a.takeover) takeovers += 1;
            const s = topSev(a.findings);
            if (s) t[s] += 1;
        }
        return { t, takeovers };
    }, [inv]);
    const toggle = (k: string): void => setCollapsed((prev) => { const n = new Set(prev); if (n.has(k)) n.delete(k); else n.add(k); return n; });
    const onSelect = (node: TNode): void => { setSelected(node.key); setSelectedAsset(node.asset ?? null); };

    if (err) return <div className="empty">Could not load ASR assets.</div>;
    if (!inv || !tree) return <div className="empty">Loading assets…</div>;
    if (inv.assets.length === 0) {
        return <div className="empty">Scanning… no hosts yet. (crt.sh → DNS → liveness)</div>;
    }
    const live = inv.assets.filter((a) => a.alive).length;

    return (
        <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", borderBottom: "1px solid #232a38", flexWrap: "wrap" }}>
                <span style={{ fontWeight: 700, fontSize: 14, color: "#e6e9ef" }}>{inv.apex}</span>
                <span style={{ color: "#5b6478", fontSize: 12.5 }}>{inv.assets.length} hosts · {live} live</span>
                <span style={{ flex: 1 }} />
                {tally.takeovers > 0 ? <Chip color="#ef4444" title="possible subdomain takeover(s)">{tally.takeovers} takeover</Chip> : null}
                {SEV_ORDER.filter((s) => tally.t[s] > 0).map((s) => <Chip key={s} color={SEV_COLOR[s]}>{s} {tally.t[s]}</Chip>)}
            </div>
            <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
                <div style={{ flex: "1 1 54%", overflowY: "auto", borderRight: "1px solid #232a38", padding: "6px 2px" }}>
                    {tree.children.map((c) => <Row key={c.key} node={c} depth={0} collapsed={collapsed} toggle={toggle} selected={selected} onSelect={onSelect} />)}
                </div>
                <div style={{ flex: "1 1 46%", overflowY: "auto" }}>
                    <Detail id={id} asset={selectedAsset} />
                </div>
            </div>
        </div>
    );
}

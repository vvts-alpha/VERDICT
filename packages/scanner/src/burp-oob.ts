// AMRAAM Audit REST 拡張(同 1338)の OOB(Burp Collaborator)ルートのクライアント。
// ブラインド SSRF/XXE/SQLi/OS コマンドインジェクション等を out-of-band で確証するために使う:
//   ① oobPayload() で一意ドメインを発行 → AMRAAM が標的の注入点に埋める
//   ② oobPoll() で interaction(DNS/HTTP/SMTP コールバック)を回収 → 来れば確証
// conn は Audit REST と同じ(同一拡張・同一ポート)。

import type { BurpAuditConn } from "./burp-audit.js";

function url(conn: BurpAuditConn, path: string): string {
  return `${conn.base.replace(/\/+$/, "")}${path}`;
}
function headers(conn: BurpAuditConn): Record<string, string> {
  return conn.token ? { "X-Scan-Token": conn.token } : {};
}

export interface OobInteraction {
  /** 発行ペイロードの id と一致する相関キー。 */
  id: string;
  /** "DNS" | "HTTP" | "SMTP" */
  type: string;
  /** epoch ms。 */
  time: number;
  /** 標的(コールバック元)の IP。 */
  clientIp?: string;
}

/** Collaborator が Burp 側で有効かを返す。available=false なら OOB は使えない。 */
export async function oobStatus(conn: BurpAuditConn): Promise<{ available: boolean; server: string; error?: string }> {
  const res = await fetch(url(conn, "/oob/status"), { headers: headers(conn) });
  if (!res.ok) throw new Error(`oob /status failed: ${res.status}`);
  const j = (await res.json()) as { available?: boolean; server?: string; error?: string };
  return { available: !!j.available, server: j.server ?? "", ...(j.error ? { error: j.error } : {}) };
}

/** 一意 OOB ペイロードを発行。host=注入用の完全ドメイン, id=interaction との相関キー。 */
export async function oobPayload(conn: BurpAuditConn): Promise<{ host: string; id: string }> {
  const res = await fetch(url(conn, "/oob/payload"), { method: "POST", headers: headers(conn) });
  if (!res.ok) throw new Error(`oob /payload failed: ${res.status} ${(await res.text().catch(() => "")).slice(0, 200)}`);
  const j = (await res.json()) as { host?: string; id?: string };
  if (!j.host || !j.id) throw new Error("oob /payload returned no host/id");
  return { host: j.host, id: j.id };
}

/** Collaborator から interaction を回収(since=epoch ms 以降 / id 一致で絞る)。 */
export async function oobPoll(conn: BurpAuditConn, opts: { since?: number; id?: string } = {}): Promise<OobInteraction[]> {
  const qs = new URLSearchParams();
  if (opts.since != null) qs.set("since", String(opts.since));
  if (opts.id) qs.set("id", opts.id);
  const res = await fetch(url(conn, `/oob/interactions${qs.toString() ? `?${qs}` : ""}`), { headers: headers(conn) });
  if (!res.ok) throw new Error(`oob /interactions failed: ${res.status}`);
  const j = (await res.json()) as { interactions?: Array<{ id?: string; type?: string; time?: number; client_ip?: string }> };
  return (j.interactions ?? []).map((i) => ({ id: i.id ?? "", type: i.type ?? "?", time: i.time ?? 0, ...(i.client_ip ? { clientIp: i.client_ip } : {}) }));
}

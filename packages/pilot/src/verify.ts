// Burp 取り込み後の検証フェーズ: Burp 能動スキャンの High+ finding を AI が能動再テストして確証/反証する。
// Burp スキャナは FP(特に SSTI/XSS/desync/reflected 系)を出すので、取り込んだ High 以上を 1 件ずつ
// AI が自分の http_request で再現(negative control + >=2 stable positive = 証拠規律)し、効果で判定する。
// 反証してもレポートからは消さない(severity 据え置き + 注記のみ)。確証は [burp✓]、反証は [burp?] に印を付ける。
//
// 自己完結: 診断ステージの重い PilotSession(driver/inventory…)に依存せず、http クライアントと evidence だけで回す。
// runBurpScanOnRun / burp-import(REST/XML どちらの取り込み経路)からも呼べる。

import { createSdkMcpServer, query, tool } from "@anthropic-ai/claude-agent-sdk";
import type { HookCallback } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import { isInScope } from "@veritas/core";
import type { AssessmentStore, Finding, ScopePolicy, Severity } from "@veritas/core";
import { readEvidenceArtifact, classifyBurpName } from "@veritas/scanner";
import type { EvidenceStore, FetchHttpClient, HttpRequest, HttpResponse } from "@veritas/scanner";

export interface VerifyBurpDeps {
  store: AssessmentStore;
  assessmentId: string;
  scope: ScopePolicy;
  /** スコープゲート済み http クライアント(必要なら認証ヘッダを内包)。 */
  http: FetchHttpClient;
  /** runs/<id>/artifacts に紐づく EvidenceStore(再テストの req/resp を記録)。 */
  evidence: EvidenceStore;
  /** Burp finding が引用する元 req/resp を読むための artifacts ディレクトリ。 */
  artifactsDir: string;
  /** 認証下 finding を再現するための Cookie ヘッダ(任意。無ければ未認証で検証)。 */
  cookie?: string;
  /** Bearer JWT(任意)。Juice Shop 等は /profile を Bearer で検証するので、これが無いと再テストが 401/「Blocked」で
   *  弾かれ「再現できず」と誤判定する(SSTI/XSS 再検証が失敗していた根因)。cookie と併せて Authorization に載せる。 */
  bearer?: string;
  model?: string;
  maxTurnsPerFinding?: number;
  onText?: (t: string) => void;
  onTool?: (n: string, i: unknown) => void;
}

export interface VerifyBurpResult {
  checked: number;
  confirmed: number;
  refuted: number;
}

const HIGH_PLUS = new Set<Severity>(["high", "critical"]);
// onlyVeritasToolsHook が真の境界。だが preset が提示する組み込み系をここで隠さないとモデルが ToolSearch 等を
// 叩いて拒否され続ける(ターン浪費)。run.ts の DISALLOWED と揃える。
const DISALLOWED = [
  "Bash", "BashOutput", "KillShell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "WebFetch", "WebSearch",
  "Task", "Agent", "ToolSearch", "TodoWrite", "Skill", "Monitor", "Workflow", "EnterPlanMode", "ExitPlanMode", "SendMessage",
  "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "TaskStop", "TaskOutput", "CronCreate", "CronList", "CronDelete",
];

const onlyVeritasToolsHook: HookCallback = async (input) => {
  const name = (input as { tool_name?: string }).tool_name ?? "";
  if (name.startsWith("mcp__veritas__")) return { continue: true };
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `burp-verify only permits veritas tools. '${name}' is denied.`,
    },
  };
};

const VERIFY_SYSTEM = `You are independently RE-VERIFYING a vulnerability that Burp Suite's automated active scanner reported. Automated scanners produce false positives, so you must REPRODUCE the issue with your own HTTP requests before confirming — never trust Burp's verdict alone.

Procedure:
1. Call burp_evidence to read Burp's original request/response.
2. Use http_request to send a NEGATIVE CONTROL (the payload absent / a benign value) — it must NOT show the vulnerable behaviour.
3. Use http_request to send the attack request at least TWICE — both must reproduce the SAME vulnerable behaviour (stable).
Judge by the EFFECT, not by Burp's say-so:
- SSTI: an arithmetic payload (e.g. 7*7) must render its result (49) in the response, and the control must not.
- Reflected/stored XSS: the exact injected markup must come back UNENCODED (executable), control encoded/absent.
- SQLi: a boolean/UNION/error difference vs the control that proves query control.
- Open redirect/SSRF/desync: the concrete side effect (Location to attacker host, fetched marker, smuggled response).
Then call verdict EXACTLY ONCE:
- confirmed: you reproduced it (control clean + >=2 stable positives). Pass the evidenceIds you used.
- refuted: you could NOT reproduce it (control == positive, behaviour absent, or unstable). The finding is KEPT for manual review; you are only flagging that automated re-test failed.
Be skeptical: when uncertain, choose refuted. Keep it to a handful of requests.`;

/** Burp finding の説明末尾 "@ <url>" から対象エンドポイントを抽出。無ければ null。 */
export function endpointOf(f: Finding): string | null {
  const m = /@\s+(https?:\/\/\S+)\s*$/.exec(f.description.trim());
  return m?.[1] ?? null;
}

const txt = (s: string): { content: { type: "text"; text: string }[] } => ({ content: [{ type: "text", text: s }] });

function pick(h: Record<string, string>, keys: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of keys) if (h[k] !== undefined) o[k] = h[k];
  return o;
}

/**
 * Burp 由来の High+ finding を AI が能動再テストして確証/反証する。冪等(既に印の付いた finding は飛ばす)。
 * 反証しても severity は据え置き(注記のみ)。確証=[burp✓] / 反証=[burp?] に印を付け、AI の再テスト証拠を添える。
 */
export async function verifyBurpFindings(deps: VerifyBurpDeps): Promise<VerifyBurpResult> {
  const all = deps.store.loadAssessment(deps.assessmentId)?.findings ?? [];
  const targets = all.filter(
    (f) =>
      HIGH_PLUS.has(f.severity) &&
      f.source.kind === "validator" &&
      f.source.validatorName === "burp" &&
      !/\[burp[✓?]\]/.test(f.title), // 既に検証済みは飛ばす(冪等)
  );
  const result: VerifyBurpResult = { checked: 0, confirmed: 0, refuted: 0 };
  if (targets.length === 0) return result;

  const maxTurns = deps.maxTurnsPerFinding ?? 12;
  for (const f of targets) {
    result.checked += 1;
    const o = await deepDiveOne(deps, f, maxTurns);
    if (o === "confirmed") result.confirmed += 1;
    else result.refuted += 1;
  }
  return result;
}

/**
 * Burp finding 1 件を AI が能動再テストして確証/反証する共通本体(High+ 検証と sub-High 深堀の両方が使う)。
 * confirmSeverity を渡すと、確証時に severity をそこへ **引き上げる**(info で取り込んだ反射点が実 XSS だった等)。
 */
async function deepDiveOne(
  deps: VerifyBurpDeps,
  f: Finding,
  maxTurns: number,
  opts: { confirmSeverity?: Severity } = {},
): Promise<"confirmed" | "refuted"> {
    const endpoint = endpointOf(f);
    // verdict ツールが書き込むこのフィンディング 1 件分の結果。
    // ※ クロージャ越しに書き換わるので holder オブジェクトにする(TS の flow-narrowing 回避)。
    const box: { outcome: "confirmed" | "refuted" | null; note: string; ev: string[] } = { outcome: null, note: "", ev: [] };

    const burpEvidence = tool(
      "burp_evidence",
      "Return Burp's original request/response for the finding under verification (so you can craft your own re-test).",
      {},
      async () => {
        const evId = f.evidenceIds[0];
        const art = evId ? readEvidenceArtifact(deps.artifactsDir, evId, 6000) : null;
        return txt(
          JSON.stringify({
            finding: f.title,
            endpoint,
            burpRequest: art?.request ?? "(no stored request)",
            burpResponse: art?.response ?? "(no stored response)",
          }),
        );
      },
    );

    const httpRequest = tool(
      "http_request",
      "Send a scoped raw HTTP request to reproduce (or refute) the finding. Records evidence; returns an evidenceId to cite in the verdict.",
      {
        method: z.string(),
        url: z.string(),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        note: z.string().optional(),
      },
      async ({ method, url, headers, body, note }) => {
        if (!isInScope(url, deps.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const req: HttpRequest = {
          method: method.toUpperCase(),
          url,
          // 認証下 finding(/profile の JWT none・SSTI 等)を再現できるよう、cookie + Bearer をデフォルトで載せる
          // (モデルが headers で上書きすれば優先)。これが無いと Juice Shop は 401/「Blocked illegal activity」を返す。
          headers: {
            ...(deps.cookie ? { cookie: deps.cookie } : {}),
            ...(deps.bearer ? { authorization: `Bearer ${deps.bearer}` } : {}),
            ...(headers ?? {}),
          },
          body: body ?? null,
        };
        let res: HttpResponse;
        try {
          res = await deps.http.send(req);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 200)}`);
        }
        const ev = deps.evidence.record({
          screenId: "burp-verify",
          validator: "burp-verify",
          kind: "positive_replay",
          request: { ...req, headers: deps.http.effectiveHeaders(req.headers) },
          response: res,
          note: note ?? `verify ${f.id}: ${req.method} ${url}`,
        });
        return txt(
          JSON.stringify({
            evidenceId: ev.id,
            status: res.status,
            headers: pick(res.headers, ["content-type", "location", "set-cookie", "www-authenticate", "access-control-allow-origin"]),
            bodyLength: res.body.length,
            body: res.body.slice(0, 1800),
          }),
        );
      },
    );

    const verdict = tool(
      "verdict",
      "Record the re-verification verdict for this Burp finding EXACTLY ONCE. confirmed = you reproduced it (control clean + >=2 stable positives); refuted = automated re-test could not reproduce it.",
      {
        verdict: z.enum(["confirmed", "refuted"]),
        note: z.string().describe("one-sentence justification grounded in the EFFECT you observed (e.g. 'control returned {{7*7}} literally, payload rendered 49 twice')"),
        evidenceIds: z.array(z.string()).optional().describe("the http_request evidenceIds that justify the verdict"),
      },
      async ({ verdict: v, note, evidenceIds }) => {
        box.outcome = v;
        box.note = note;
        if (evidenceIds) box.ev.push(...evidenceIds);
        return txt(`recorded ${v} for ${f.id}.`);
      },
    );

    const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: [burpEvidence, httpRequest, verdict] });
    const goal = `Re-verify Burp finding ${f.id}: [${f.severity}] ${f.title.replace(/^\[burp\]\s*/, "")}${endpoint ? ` at ${endpoint}` : ""}. Start with burp_evidence, reproduce it with http_request (control + >=2 positives), then call verdict.`;

    const q = query({
      prompt: goal,
      options: {
        mcpServers: { veritas: server },
        allowedTools: ["burp_evidence", "http_request", "verdict"].map((n) => `mcp__veritas__${n}`),
        disallowedTools: DISALLOWED,
        permissionMode: "bypassPermissions",
        hooks: { PreToolUse: [{ hooks: [onlyVeritasToolsHook] }] },
        ...(deps.model ? { model: deps.model } : {}),
        systemPrompt: { type: "preset", preset: "claude_code", append: VERIFY_SYSTEM },
        maxTurns,
      },
    });
    try {
      for await (const msg of q) {
        if (msg.type === "assistant") {
          for (const block of msg.message.content) {
            if (block.type === "text" && block.text.trim()) deps.onText?.(block.text.trim());
            else if (block.type === "tool_use") deps.onTool?.(block.name, block.input);
          }
        }
        if (box.outcome) break; // verdict が出たら即終了(1 件 1 判定)
      }
    } catch (e) {
      deps.onText?.(`⚠ verify ${f.id} ended early: ${String(e instanceof Error ? e.message : e).slice(0, 140)}`);
    }
    try {
      await q.return?.(undefined as never);
    } catch {
      /* generator already done */
    }

    // verdict が出ないまま終わった(maxTurns 等)→ 反証扱い(再現できなかった=注記のみ)。
    const finalOutcome: "confirmed" | "refuted" = box.outcome ?? "refuted";
    const note = box.note || (box.outcome ? "" : "no verdict reached within the re-test budget");
    annotate(deps, f, finalOutcome, note, box.ev, finalOutcome === "confirmed" ? opts.confirmSeverity : undefined);
    return finalOutcome;
}

export interface TriageDeepDiveResult {
  /** sub-High の Burp リード総数(モデルに提示した一覧の件数) */
  listed: number;
  /** モデルが深堀を選んだ件数 */
  selected: number;
  confirmed: number;
  refuted: number;
}

const SELECT_SYSTEM = `You are triaging a list of LOWER-severity issues Burp's scanner reported. Most are noise (hygiene, low-value disclosures), but some are ENTRY POINTS to real vulnerabilities the scanner under-rated:
- "Input returned in response (reflected/stored)" / "Cross-site scripting" → reflected/stored XSS, IF the input returns unescaped in an executable context.
- "External service interaction (DNS/HTTP)" → SSRF / OOB.
- "Cross-origin resource sharing: arbitrary origin trusted" → cross-site data theft, IF the response is credentialed and sensitive.
- "Cross-site request forgery", "Open redirection", "File upload", weak CSP, exposed API spec → their respective classes.
Each row carries a heuristic hint «lead/priority» — treat it as a suggestion, not a verdict; use your own judgement on the title and endpoint.
Pick ONLY the rows genuinely worth a deep active re-test — favour those that plausibly lead to a concrete, high-impact effect; skip pure hygiene and trivial disclosures. Then call select_leads(ids, reason) EXACTLY ONCE. Be selective: a handful, not all of them.`;

/**
 * 新フェーズ「タイトル一覧 → 有望なものをモデルが選択 → 深堀」。
 * verifyBurpFindings が触らない **sub-High の Burp リード** を一覧でモデルに見せ(各行にヒューリスティック
 * ヒント付き)、選ばせた分だけ deepDiveOne で能動再テスト(証拠規律)する。確証ならヒント相当へ severity 引き上げ。
 * 全部 verify しない=操作者の方針どおり「有望そうなものだけ深堀」。
 */
export async function triageAndDeepDiveBurp(
  deps: VerifyBurpDeps,
  opts: { maxDeepDives?: number } = {},
): Promise<TriageDeepDiveResult> {
  const all = deps.store.loadAssessment(deps.assessmentId)?.findings ?? [];
  const leads = all.filter(
    (f) =>
      f.source.kind === "validator" &&
      f.source.validatorName === "burp" &&
      !HIGH_PLUS.has(f.severity) &&
      !/\[burp[✓?]\]/.test(f.title), // 既に検証済みは飛ばす(冪等)
  );
  const res: TriageDeepDiveResult = { listed: leads.length, selected: 0, confirmed: 0, refuted: 0 };
  if (leads.length === 0) return res;

  const strip = (t: string): string => t.replace(/^\[burp\]\s*/, "").replace(/\s*\(\d+ URLs?\)\s*$/, "");
  const listing = leads
    .map((f) => {
      const c = classifyBurpName(strip(f.title));
      const ep = endpointOf(f);
      return `- ${f.id} [${f.severity}] ${strip(f.title)}${ep ? ` @ ${ep}` : ""}${c ? `  «hint: ${c.lead}/${c.priority}»` : ""}`;
    })
    .join("\n");

  // ── 選択フェーズ(1 クエリ) ── モデルが一覧を見て深堀対象を選ぶ。
  const picked: { ids: string[]; reason: string } = { ids: [], reason: "" };
  const selectLeads = tool(
    "select_leads",
    "Record which lead ids are worth a deep active re-test. Call EXACTLY ONCE.",
    {
      ids: z.array(z.string()).describe("the finding ids (e.g. b-012) to deep-dive"),
      reason: z.string().describe("one sentence: why these and not the rest"),
    },
    async ({ ids, reason }) => {
      picked.ids = ids;
      picked.reason = reason;
      return txt(`selected ${ids.length} of ${leads.length}`);
    },
  );
  const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: [selectLeads] });
  const q = query({
    prompt: `${leads.length} lower-severity Burp issues (format: id [severity] title @ endpoint «heuristic hint»):\n${listing}\n\nReview the titles and pick the ones worth deep-diving, then call select_leads.`,
    options: {
      mcpServers: { veritas: server },
      allowedTools: ["select_leads"].map((n) => `mcp__veritas__${n}`),
      disallowedTools: DISALLOWED,
      permissionMode: "bypassPermissions",
      hooks: { PreToolUse: [{ hooks: [onlyVeritasToolsHook] }] },
      ...(deps.model ? { model: deps.model } : {}),
      systemPrompt: { type: "preset", preset: "claude_code", append: SELECT_SYSTEM },
      maxTurns: 4,
    },
  });
  try {
    for await (const msg of q) {
      if (msg.type === "assistant") {
        for (const block of msg.message.content) {
          if (block.type === "text" && block.text.trim()) deps.onText?.(block.text.trim());
          else if (block.type === "tool_use") deps.onTool?.(block.name, block.input);
        }
      }
      if (picked.ids.length) break;
    }
  } catch (e) {
    deps.onText?.(`⚠ burp triage selection ended early: ${String(e instanceof Error ? e.message : e).slice(0, 140)}`);
  }
  try {
    await q.return?.(undefined as never);
  } catch {
    /* generator already done */
  }

  const cap = opts.maxDeepDives ?? 12;
  const chosen = leads.filter((f) => picked.ids.includes(f.id)).slice(0, cap);
  res.selected = chosen.length;
  if (chosen.length === 0) {
    deps.onText?.(`burp triage: model selected nothing to deep-dive of ${leads.length} lead(s)`);
    return res;
  }
  deps.store.appendEvent(deps.assessmentId, {
    type: "note",
    payload: { message: `🔬 burp triage: deep-diving ${chosen.length}/${leads.length} model-flagged lead(s) — ${picked.reason.slice(0, 160)}` },
  });

  const maxTurns = deps.maxTurnsPerFinding ?? 12;
  for (const f of chosen) {
    const c = classifyBurpName(strip(f.title));
    const confirmSeverity: Severity | undefined = c?.priority === "high" ? "high" : c?.priority === "medium" ? "medium" : undefined;
    const outcome = await deepDiveOne(deps, f, maxTurns, confirmSeverity ? { confirmSeverity } : {});
    if (outcome === "confirmed") res.confirmed += 1;
    else res.refuted += 1;
  }
  return res;
}

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** finding に検証結果の印と注記を付ける。confirmed=[burp✓] / refuted=[burp?]。
 *  newSeverity 指定時は確証された sub-High リードの severity を **上方向にだけ** 引き上げる(info→high 等)。 */
function annotate(
  deps: VerifyBurpDeps,
  f: Finding,
  outcome: "confirmed" | "refuted",
  note: string,
  evidenceIds: string[],
  newSeverity?: Severity,
): void {
  const cur = deps.store.loadAssessment(deps.assessmentId)?.findings.find((x) => x.id === f.id) ?? f;
  const mark = outcome === "confirmed" ? "[burp✓]" : "[burp?]";
  const title = cur.title.replace(/^\[burp\]/, mark);
  // 確証され、かつヒント severity が現状より高ければ引き上げる(過小評価された info 取り込みを是正)。下げはしない。
  const bumped = outcome === "confirmed" && newSeverity && SEV_RANK[newSeverity] > SEV_RANK[cur.severity] ? newSeverity : cur.severity;
  const head =
    outcome === "confirmed"
      ? `✅ AI-verified by active re-test: ${note}${bumped !== cur.severity ? ` (severity raised ${cur.severity}→${bumped}: confirmed real, not info-only)` : ""}`
      : `⚠ AI re-test could not reproduce (severity kept, manual confirmation advised): ${note}`;
  const ev = [...new Set([...cur.evidenceIds, ...evidenceIds])];
  deps.store.upsertFinding(deps.assessmentId, { ...cur, title, severity: bumped, description: `${head}\n\n${cur.description}`, evidenceIds: ev });
  deps.store.appendEvent(deps.assessmentId, {
    type: "note",
    payload: { message: `${outcome === "confirmed" ? "✅" : "⚠"} burp-verify ${f.id}: ${outcome} — ${note.slice(0, 200)}` },
  });
}

// 画面インベントリ(Screen.apis = XHR/fetch ∪ HTMLフォームPOST)→ OpenAPI 3.0 定義への純粋な projection。
// 目的: AMRAAM が ground truth として持つ「全エンドポイント × 全パラメータ」を Burp の API scanning へ明示的に渡す。
// (Burp の site map は URL 集約でパラメータが落ちるので、AMRAAM が定義として宣言する方が完全)。

import type { JsonShape, Screen } from "./types/index.js";

export interface BuildOpenApiOptions {
  /** servers[].url の基底(例 https://app.example.com)。末尾スラッシュは除去される。 */
  baseUrl: string;
  title?: string;
  version?: string;
}

type OASchema = Record<string, unknown>;

/** JsonShape → OpenAPI schema(再帰)。unknown は型無し({})にする。 */
export function jsonShapeToSchema(shape: JsonShape): OASchema {
  switch (shape.type) {
    case "object": {
      const properties: Record<string, OASchema> = {};
      for (const [k, v] of Object.entries(shape.fields)) properties[k] = jsonShapeToSchema(v);
      return { type: "object", properties };
    }
    case "array":
      return { type: "array", items: jsonShapeToSchema(shape.items) };
    case "unknown":
      return {};
    default:
      return { type: shape.type };
  }
}

/** urlTemplate の {name} → path parameter 名の配列。 */
function pathParamsOf(template: string): string[] {
  return [...template.matchAll(/\{([^}]+)\}/g)].map((m) => m[1] ?? "").filter(Boolean);
}

/**
 * Screen[] → OpenAPI 3.0.3 ドキュメント。url×method ごとに 1 operation。
 * - path params は urlTemplate の {name} から(always)
 * - requestBody は ApiCall.reqSchema(XHR の JSON / フォームの合成スキーマ)から
 * - query params は「その path を自前ページに持つ画面」の in:query を GET 系に載せる
 * - responses は resSchema があれば 200 のスキーマに
 */
export function buildOpenApi(screens: ReadonlyArray<Screen>, opts: BuildOpenApiOptions): Record<string, unknown> {
  // urlTemplate → query param 名(画面が自前ページに持つもの)。
  const queryByPath = new Map<string, Set<string>>();
  for (const sc of screens) {
    const q = sc.params.filter((p) => p.in === "query").map((p) => p.name);
    if (q.length === 0) continue;
    const set = queryByPath.get(sc.urlTemplate) ?? new Set<string>();
    for (const n of q) set.add(n);
    queryByPath.set(sc.urlTemplate, set);
  }

  const paths: Record<string, Record<string, unknown>> = {};
  const seen = new Set<string>();
  let opCount = 0;
  for (const sc of screens) {
    for (const api of sc.apis) {
      const key = `${api.method} ${api.urlTemplate}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const method = api.method.toLowerCase();
      const op: Record<string, unknown> = { summary: `${api.method} ${api.urlTemplate}` };
      const parameters: OASchema[] = [];
      for (const name of pathParamsOf(api.urlTemplate)) {
        parameters.push({ name, in: "path", required: true, schema: { type: "string" } });
      }
      const qnames = queryByPath.get(api.urlTemplate);
      if (qnames && (method === "get" || method === "head")) {
        for (const name of qnames) parameters.push({ name, in: "query", required: false, schema: { type: "string" } });
      }
      if (parameters.length > 0) op.parameters = parameters;
      if (api.reqSchema) {
        // NOTE: フォーム由来は本来 application/x-www-form-urlencoded だが、ApiCall は content-type を保持しない。
        //       Burp の API scanner はスキーマの properties から fuzz 対象パラメータを読むので json で十分(精緻化は後段)。
        op.requestBody = { content: { "application/json": { schema: jsonShapeToSchema(api.reqSchema) } } };
      }
      op.responses = api.resSchema
        ? { "200": { description: "observed", content: { "application/json": { schema: jsonShapeToSchema(api.resSchema) } } } }
        : { "200": { description: "observed" } };
      (paths[api.urlTemplate] ??= {})[method] = op;
      opCount += 1;
    }
  }

  return {
    openapi: "3.0.3",
    info: {
      title: opts.title ?? `AMRAAM discovered API — ${opts.baseUrl}`,
      version: opts.version ?? "1.0.0",
      description: `${opCount} operation(s) across ${Object.keys(paths).length} path(s), discovered by AMRAAM (XHR/fetch + HTML form POSTs).`,
    },
    servers: [{ url: opts.baseUrl.replace(/\/+$/, "") }],
    paths,
  };
}

// DESIGN §6.4 / §6.6 — 観測 → Screen 素材化 と dedup(画面インベントリ構築)。

import type { ApiCall, AuthState, JsonShape, Param, Screen } from "@veritas/core";
import type { FormObservation, Observation } from "./types.js";
import { extractQueryParams, normalizePath } from "./url.js";
import { apiKey, extractApiRefs, inferApiCall, isApiExchange } from "./api.js";
import { hashDomSkeleton } from "./dom.js";
import { classifyScreenType, deriveLabels, describeScreen, guessParamType } from "./labeler.js";

function screenIdFor(n: number): string {
  return `s-${String(n).padStart(4, "0")}`;
}

/** HTML フォームの fields → そのフォーム送信先(POST 等)の reqSchema(合成オブジェクト形状)。
 *  これで「フォーム POST のエンドポイント + ボディ項目」が第一級 API として OpenAPI に出せる(XHR と同列)。
 *  input type を JSON プリミティブにマップ(number/range→number, checkbox→boolean, それ以外→string)。 */
function formFieldsToShape(fields: FormObservation["fields"]): JsonShape | null {
  const named = fields.filter((f) => f.name);
  if (named.length === 0) return null;
  const shapeFields: Record<string, JsonShape> = {};
  for (const f of named) {
    const t = f.type;
    const kind: "string" | "number" | "boolean" = /number|range/.test(t) ? "number" : /checkbox/.test(t) ? "boolean" : "string";
    shapeFields[f.name] = { type: kind };
  }
  return { type: "object", fields: shapeFields };
}

/** Cap-grouping key. The per-template cap (see DEFAULT_MAX_SCREENS_PER_TEMPLATE) folds the DOM-skeleton churn of ONE
 *  page (same URL, mutating markup) into <=maxPerTemplate screens. But SPA hash routes (#/basket, #/wallet, …) are
 *  DISTINCT pages that all share pathname "/", so a cap keyed on the pathname template alone collapsed a whole
 *  hash-routed app (Angular / OWASP Juice Shop) into 3 screens — every route past the 3rd silently merged into "/".
 *  Fold the SPA hash route into the cap key so each route caps independently. Non-hash URLs return `urlTemplate`
 *  unchanged → byte-identical behaviour for non-SPA apps. */
export function capTemplateOf(urlTemplate: string, url: string): string {
  let hash = "";
  try {
    hash = new URL(url).hash;
  } catch {
    const i = url.indexOf("#");
    hash = i >= 0 ? url.slice(i) : "";
  }
  if (!/^#!?\/.+/.test(hash)) return urlTemplate;
  const hashPath = hash.replace(/^#!?/, "").split(/[?&]/)[0] ?? "";
  return `${urlTemplate === "/" ? "" : urlTemplate}#${normalizePath(hashPath).template}`;
}

/** Internal route identity includes the origin and SPA route; urlTemplate remains display-friendly. */
export function screenRouteKey(urlTemplate: string, url: string): string {
  let origin = "";
  try { origin = new URL(url).origin; } catch { /* Legacy screens may lack an observed URL. */ }
  return `${origin}\0${capTemplateOf(urlTemplate, url)}`;
}

export interface BuiltScreen {
  dedupKey: string;
  observedUrl: string;
  /** Origin and route grouping key (see screenRouteKey). */
  capTemplate: string;
  /** screenId 未割当の Screen 素材 */
  screen: Omit<Screen, "screenId">;
}

/** route + the screen's functional attack surface (param locations+names, API endpoint signatures).
 *  Two observations with the same surface are the same logical screen even if the DOM skeleton differs. */
function surfaceKeyOf(route: string, screen: Pick<Screen, "params" | "apis">): string {
  const params = screen.params.map((p) => `${p.in}:${p.name}`).sort().join(",");
  const apis = screen.apis.map(apiKey).sort().join(",");
  return `${route}${params}${apis}`;
}

/** Merge a re-observed ApiCall into the kept one: fill null schemas, and for GraphQL union the variable
 *  name→kind shape + refresh the replay example (newest values are the most likely to still resolve). */
function mergeApiCall(cur: ApiCall | undefined, next: ApiCall): void {
  if (!cur) return;
  if (!cur.reqSchema && next.reqSchema) cur.reqSchema = next.reqSchema;
  if (!cur.resSchema && next.resSchema) cur.resSchema = next.resSchema;
  if (next.graphql) {
    if (cur.graphql) {
      cur.graphql.variablesShape = { ...cur.graphql.variablesShape, ...next.graphql.variablesShape };
      if (next.graphql.variablesExample) cur.graphql.variablesExample = next.graphql.variablesExample;
      // Backfill metadata a stored/older observation may lack. Fill-only, never union: responseKeys must match
      // the STORED document (`first:user` vs `second:user` are now different operationKeys, so a merge always
      // carries the same alias set — but a legacy entry may simply lack the field).
      if (!cur.graphql.responseKeys && next.graphql.responseKeys) cur.graphql.responseKeys = next.graphql.responseKeys;
      if (cur.graphql.rootFields.length === 0 && next.graphql.rootFields.length) cur.graphql.rootFields = next.graphql.rootFields;
      if (!cur.graphql.operationName && next.graphql.operationName) cur.graphql.operationName = next.graphql.operationName;
      if (!cur.graphql.document && next.graphql.document) cur.graphql.document = next.graphql.document;
    } else {
      cur.graphql = next.graphql;
    }
  }
}

/** 観測 1 件 → dedup_key と (id 未割当の) Screen 素材。 */
export function buildScreenFromObservation(o: Observation, authState: AuthState = "unauth"): BuiltScreen {
  const u = new URL(o.finalUrl);
  const { template, params: pathParams } = normalizePath(u.pathname);

  const params: Param[] = [
    ...pathParams.map(
      (p): Param => ({ name: p.name, in: "path", example: p.example, guessedType: guessParamType(p.name, "path") }),
    ),
    ...extractQueryParams(u.search).map(
      (p): Param => ({ name: p.name, in: "query", example: p.example, guessedType: guessParamType(p.name, "query") }),
    ),
  ];
  for (const form of o.forms) {
    for (const f of form.fields) {
      if (f.name && !params.some((p) => p.name === f.name)) {
        params.push({ name: f.name, in: "body", example: "", guessedType: guessParamType(f.name, "body") });
      }
    }
  }

  const apis: ApiCall[] = [];
  const seen = new Set<string>();
  const addApi = (api: ApiCall): void => {
    const k = apiKey(api);
    if (!seen.has(k)) {
      seen.add(k);
      apis.push(api);
      return;
    }
    mergeApiCall(apis.find((x) => apiKey(x) === k), api);
  };
  // 1) 傍受した XHR/fetch
  for (const ex of o.apiCalls) {
    if (isApiExchange(ex)) addApi(inferApiCall(ex));
  }
  // 2) フォーム送信先(検索/ログイン/作成 等のエンドポイント)。ボディを持つメソッド(POST/PUT/...)は
  //    フォームの fields から reqSchema を合成して紐付ける(GET フォームの項目は query なのでボディ無し)。
  for (const form of o.forms) {
    if (!form.action) continue;
    try {
      const urlTemplate = normalizePath(new URL(form.action, o.finalUrl).pathname).template;
      const method = form.method.toUpperCase();
      const bodyMethod = method !== "GET" && method !== "HEAD";
      addApi({ method, urlTemplate, auth: "none", reqSchema: bodyMethod ? formFieldsToShape(form.fields) : null, resSchema: null });
    } catch {
      /* 解析不能な action は無視 */
    }
  }
  // 3) JS から静的抽出した API 参照(受動クロールで発火しないものも拾う)
  for (const api of extractApiRefs(o.scripts ?? [], o.finalUrl)) addApi(api);

  const domSkeletonHash = hashDomSkeleton(o.domSkeleton);
  const screenType = classifyScreenType({
    urlTemplate: template,
    finalUrl: o.finalUrl,
    forms: o.forms,
    title: o.title,
    visibleText: o.visibleText,
  });
  const labels = deriveLabels(screenType, params, apis, o.visibleText);

  return {
    dedupKey: `${screenRouteKey(template, o.finalUrl)}\0${domSkeletonHash}`,
    observedUrl: o.finalUrl,
    capTemplate: screenRouteKey(template, o.finalUrl),
    screen: {
      urlTemplate: template,
      observedUrls: [o.finalUrl],
      authState,
      screenType,
      description: describeScreen(screenType, template, params, apis),
      params,
      apis,
      screenshot: "",
      domSkeletonHash,
      labels,
    },
  };
}

/** Cap on how many distinct screens may share one urlTemplate. A page whose DOM skeleton keeps changing on
 *  re-visit — dynamic content, or (notably) the agent's OWN injected XSS/markup mutating the page — would
 *  otherwise inflate one logical URL into a fresh screen every visit (observed: /post exploding to 15 screens
 *  on a reflected-XSS lab). hashDomSkeleton already folds benign count differences (see the /post?id=N test);
 *  this is the backstop for the *structural* churn it can't fold. Past the cap, further variants merge into the
 *  template's representative screen. Keep it >= 2 so a genuine same-URL/different-skeleton split (SPA) still works. */
const DEFAULT_MAX_SCREENS_PER_TEMPLATE = 3;

/**
 * dedup_key = (正規化ルート, DOM骨格hash) で画面を集約(§6.4)。
 * 同一キーは observedUrls / apis / params / labels をマージし 1 画面に束ねる。
 */
export class InventoryBuilder {
  private readonly byKey = new Map<string, Screen>();
  private readonly byTemplate = new Map<string, Screen>();
  /** route + identical attack surface (params + API endpoints) → screen. The DOM skeleton shifts with auth
   *  chrome (a logged-in nav bar re-hashes the page), so per-role re-maps of ONE route landed as 2-3 screens
   *  when only the skeleton differed. Same route + same functional surface = same logical screen. */
  private readonly bySurface = new Map<string, Screen>();
  /** Origin + HTTP/SPA route representatives and counts bound DOM churn independently per route. */
  private readonly byCap = new Map<string, Screen>();
  private readonly capCount = new Map<string, number>();
  /** seed() で渡された(前パスで観測済みの)urlTemplate。2 パス目はこれを優先キーにする。 */
  private readonly seededTemplates = new Set<string>();
  private counter = 0;

  constructor(private readonly maxPerTemplate: number = DEFAULT_MAX_SCREENS_PER_TEMPLATE) {}

  ingest(o: Observation, authState: AuthState = "unauth"): { screen: Screen; isNew: boolean } {
    return this.ingestBuilt(buildScreenFromObservation(o, authState));
  }

  /** Ingest a PRE-BUILT screen (e.g. synthesized from an OpenAPI/Swagger spec) through the SAME dedup / merge /
   *  seed path as ingest() — so spec-derived endpoints overlay a crawl (fill empty req/res schemas, union params)
   *  instead of duplicating, and get a continuous screenId. */
  ingestBuilt(built: BuiltScreen): { screen: Screen; isNew: boolean } {
    const route = screenRouteKey(built.screen.urlTemplate, built.observedUrl);
    built = { ...built, capTemplate: route, dedupKey: `${route}\0${built.screen.domSkeletonHash}` };
    // 2 パス目(認証済み再クロール): 既知 urlTemplate はログイン後にナビバー等で DOM 骨格が
    // 変わっても同一画面とみなしマージ(公開ページの二重計上を防ぐ)。新規 urlTemplate だけが auth-only。
    if (this.seededTemplates.has(route)) {
      const sameTemplate = this.byTemplate.get(route);
      if (sameTemplate) {
        this.merge(sameTemplate, built);
        return { screen: sameTemplate, isNew: false };
      }
    }
    const existing = this.byKey.get(built.dedupKey);
    if (existing) {
      this.merge(existing, built);
      return { screen: existing, isNew: false };
    }
    // Surface dedup: DOM-skeleton differs (auth chrome, per-role re-map) but the ATTACK surface is identical —
    // same params, same API endpoints on the same route. Diagnosis would probe the same inputs 2-3×.
    const surfaceKey = surfaceKeyOf(route, built.screen);
    const twin = this.bySurface.get(surfaceKey);
    if (twin) {
      this.merge(twin, built);
      return { screen: twin, isNew: false };
    }
    // Per-template cap (backstop against DOM-skeleton churn, e.g. self-injected XSS mutating the page): once a
    // capTemplate already has maxPerTemplate distinct screens, treat a further skeleton variant as the same logical
    // page re-hashing and merge into its representative instead of spawning yet another screen. Keyed on capTemplate
    // (hash-aware) so distinct SPA hash routes are NOT collapsed into pathname "/"'s cap.
    const rep = this.byCap.get(built.capTemplate);
    if (rep && (this.capCount.get(built.capTemplate) ?? 0) >= this.maxPerTemplate) {
      this.merge(rep, built);
      return { screen: rep, isNew: false };
    }
    this.counter += 1;
    const screen: Screen = { screenId: screenIdFor(this.counter), ...built.screen };
    this.byKey.set(built.dedupKey, screen);
    if (!this.bySurface.has(surfaceKey)) this.bySurface.set(surfaceKey, screen);
    this.capCount.set(built.capTemplate, (this.capCount.get(built.capTemplate) ?? 0) + 1);
    if (!this.byCap.has(built.capTemplate)) this.byCap.set(built.capTemplate, screen);
    if (!this.byTemplate.has(route)) this.byTemplate.set(route, screen);
    return { screen, isNew: true };
  }

  private merge(existing: Screen, built: BuiltScreen): void {
    if (!existing.observedUrls.includes(built.observedUrl)) {
      existing.observedUrls.push(built.observedUrl);
    }
    const haveApis = new Set(existing.apis.map(apiKey));
    for (const a of built.screen.apis) {
      const k = apiKey(a);
      if (!haveApis.has(k)) {
        existing.apis.push(a);
        haveApis.add(k);
      } else {
        // 同一エンドポイントを後から観測してスキーマが付いたら、空だった方を埋める(情報を捨てない)。
        mergeApiCall(existing.apis.find((x) => apiKey(x) === k), a);
      }
    }
    const paramKey = (p: Param): string => `${p.in}:${p.name}`;
    const haveParams = new Set(existing.params.map(paramKey));
    for (const p of built.screen.params) {
      if (!haveParams.has(paramKey(p))) {
        existing.params.push(p);
        haveParams.add(paramKey(p));
      }
    }
    if (built.screen.labels.length > 0) {
      existing.labels = [...new Set([...existing.labels, ...built.screen.labels])];
    }
  }

  screens(): Screen[] {
    return [...this.byKey.values()];
  }

  /** 既存の画面で初期化(2 パス目のクロールが dedup と screenId 採番を継続できるように)。 */
  seed(screens: Screen[]): void {
    for (const screen of screens) {
      const cap = screenRouteKey(screen.urlTemplate, screen.observedUrls[0] ?? "");
      this.byKey.set(`${cap}\0${screen.domSkeletonHash}`, screen);
      const sKey = surfaceKeyOf(cap, screen);
      if (!this.bySurface.has(sKey)) this.bySurface.set(sKey, screen);
      if (!this.byTemplate.has(cap)) this.byTemplate.set(cap, screen);
      this.capCount.set(cap, (this.capCount.get(cap) ?? 0) + 1);
      if (!this.byCap.has(cap)) this.byCap.set(cap, screen);
      this.seededTemplates.add(cap);
      const n = Number.parseInt(screen.screenId.replace(/^s-/, ""), 10);
      if (Number.isFinite(n)) this.counter = Math.max(this.counter, n);
    }
  }
}

// Pure projection from the screen inventory (Screen.apis = XHR/fetch ∪ HTML form POSTs) to an OpenAPI 3.0 definition.
// Purpose: hand Burp's API scanning the "every endpoint × every parameter" ground truth that VERDICT holds.
// (Burp's site map collapses by URL and drops parameters, so declaring it as an explicit definition is more complete.)

import type { JsonShape, Screen } from "./types/index.js";

export interface BuildOpenApiOptions {
  /** Base for servers[].url (e.g. https://app.example.com). A trailing slash is stripped. */
  baseUrl: string;
  title?: string;
  version?: string;
}

type OASchema = Record<string, unknown>;

/** JsonShape → OpenAPI schema (recursive). unknown becomes untyped ({}). */
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

/**
 * OpenAPI / Swagger schema → JsonShape (the inverse of jsonShapeToSchema, used to INGEST a spec).
 * - `$ref` is resolved via `deref` (components/schemas for 3.x, definitions for 2.0), cycle-guarded.
 * - `allOf` merges object fields (plus this node's own `properties`); `oneOf`/`anyOf` take the first branch.
 * - `enum` (typeless) → string; `integer` → number; OpenAPI-3.1 `type: [..,"null"]` picks the non-null member.
 * - `nullable` is ignored; anything unrecognized → `{type:"unknown"}` (renders as an untyped `{}` if re-emitted).
 */
export function schemaToJsonShape(
  schema: OASchema | undefined,
  deref: (ref: string) => OASchema | undefined,
  seen: ReadonlySet<string> = new Set(),
): JsonShape {
  if (!schema || typeof schema !== "object") return { type: "unknown" };

  const ref = schema["$ref"];
  if (typeof ref === "string") {
    if (seen.has(ref)) return { type: "unknown" }; // recursive schema — stop
    return schemaToJsonShape(deref(ref), deref, new Set(seen).add(ref));
  }

  const allOf = schema["allOf"];
  if (Array.isArray(allOf) && allOf.length > 0) {
    const fields: Record<string, JsonShape> = {};
    for (const sub of allOf) {
      const s = schemaToJsonShape(sub as OASchema, deref, seen);
      if (s.type === "object") Object.assign(fields, s.fields);
    }
    const ownProps = schema["properties"];
    if (ownProps && typeof ownProps === "object") {
      for (const [k, v] of Object.entries(ownProps as Record<string, OASchema>)) fields[k] = schemaToJsonShape(v, deref, seen);
    }
    return { type: "object", fields };
  }

  for (const key of ["oneOf", "anyOf"] as const) {
    const branch = schema[key];
    if (Array.isArray(branch) && branch.length > 0) return schemaToJsonShape(branch[0] as OASchema, deref, seen);
  }

  const props = schema["properties"];
  const t = schema["type"];
  if (t === "object" || (props && typeof props === "object")) {
    const fields: Record<string, JsonShape> = {};
    for (const [k, v] of Object.entries((props ?? {}) as Record<string, OASchema>)) fields[k] = schemaToJsonShape(v, deref, seen);
    return { type: "object", fields };
  }
  const prim = (x: unknown): JsonShape | null => {
    if (x === "string" || x === "boolean" || x === "null") return { type: x };
    if (x === "integer" || x === "number") return { type: "number" };
    if (x === "array") return { type: "array", items: schemaToJsonShape(schema["items"] as OASchema | undefined, deref, seen) };
    return null;
  };
  const p = prim(t);
  if (p) return p;
  if (Array.isArray(t)) {
    const nn = (t as unknown[]).find((x) => x !== "null");
    const q = prim(nn);
    if (q) return q;
  }
  if (Array.isArray(schema["enum"]) && (schema["enum"] as unknown[]).length > 0) return { type: "string" };
  return { type: "unknown" };
}

/** urlTemplate's {name} → array of path parameter names. */
function pathParamsOf(template: string): string[] {
  return [...template.matchAll(/\{([^}]+)\}/g)].map((m) => m[1] ?? "").filter(Boolean);
}

/**
 * Screen[] → OpenAPI 3.0.3 document. One operation per url×method.
 * - path params come from urlTemplate's {name} (always)
 * - requestBody comes from ApiCall.reqSchema (XHR JSON / synthesized form schema)
 * - query params: put the in:query params of screens that own this path as their own page onto GET-family ops
 * - responses use the resSchema as the 200 schema when present
 */
export function buildOpenApi(screens: ReadonlyArray<Screen>, opts: BuildOpenApiOptions): Record<string, unknown> {
  // urlTemplate → query param names (those a screen owns on its own page).
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
        // NOTE: form-derived bodies are really application/x-www-form-urlencoded, but ApiCall doesn't keep the content-type.
        //       Burp's API scanner reads fuzz-target parameters from the schema's properties, so json is enough (refine later).
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
      title: opts.title ?? `VERDICT discovered API — ${opts.baseUrl}`,
      version: opts.version ?? "1.0.0",
      description: `${opCount} operation(s) across ${Object.keys(paths).length} path(s), discovered by VERDICT (XHR/fetch + HTML form POSTs).`,
    },
    servers: [{ url: opts.baseUrl.replace(/\/+$/, "") }],
    paths,
  };
}

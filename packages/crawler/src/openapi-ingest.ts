// Ingest a provided OpenAPI 3.x / Swagger 2.0 spec → synthetic Screen[] (the inverse of core buildOpenApi).
// Lets an operator drive an API assessment from a swagger.json when there is no web UI to crawl (or to overlay a
// spec on a crawl and fill the endpoints the UI never calls). Pure transform — no browser, no network.

import type { ApiCall, AuthState, JsonShape, Param, ParamLoc, Screen } from "@veritas/core";
import { schemaToJsonShape } from "@veritas/core";
import { normalizePath } from "./url.js";
import { hashDomSkeleton } from "./dom.js";
import { classifyScreenType, deriveLabels, describeScreen, guessParamType } from "./labeler.js";
import { InventoryBuilder } from "./inventory.js";
import type { BuiltScreen } from "./inventory.js";

type OANode = Record<string, unknown>;
const METHODS = ["get", "post", "put", "delete", "patch", "head", "options"] as const;

const asObj = (x: unknown): OANode | undefined => (x != null && typeof x === "object" && !Array.isArray(x) ? (x as OANode) : undefined);
const asArr = (x: unknown): unknown[] => (Array.isArray(x) ? x : []);
const str = (x: unknown): string | undefined => (typeof x === "string" ? x : undefined);

const primType = (t: string | undefined): "string" | "number" | "boolean" =>
  t === "integer" || t === "number" ? "number" : t === "boolean" ? "boolean" : "string";

/** A parameter/schema's example/default rendered as a string (Param.example is a string). */
function exampleStr(p: OANode): string {
  const sch = asObj(p["schema"]);
  const ex = p["example"] ?? sch?.["example"] ?? p["default"] ?? sch?.["default"];
  if (ex == null) return "";
  return typeof ex === "string" ? ex : JSON.stringify(ex);
}

/**
 * base URL + spec path → the inventory template and a concrete probe URL. OpenAPI's `{orderId}` won't collapse under
 * normalizePath (a non-numeric segment reads as "static"), so each `{...}` is first replaced by a numeric placeholder
 * ("1","2",…) — then normalizePath rewrites them to inventory's `{id}`/`{id2}` scheme, so keys merge with a crawl.
 */
function buildEndpoint(baseUrl: string, specPath: string): { template: string; observedUrl: string } | null {
  let bu: URL;
  try {
    bu = new URL(baseUrl);
  } catch {
    return null;
  }
  const prefix = bu.pathname.replace(/\/+$/, ""); // "" or "/v2"
  const fullTemplatePath = prefix + (specPath.startsWith("/") ? specPath : `/${specPath}`);
  let n = 0;
  const concretePath = fullTemplatePath.replace(/\{[^}]+\}/g, () => String(++n));
  const { template } = normalizePath(concretePath);
  return { template, observedUrl: bu.origin + concretePath };
}

/**
 * Parse an OpenAPI 3.x / Swagger 2.0 document into Screen[]. `baseUrl` is where the API actually lives (endpoints are
 * built as baseUrl + path). Pass `existing` to overlay the spec on a crawl's screens (merges by template, fills empty
 * req/res schemas, unions params) — otherwise it returns a fresh spec-only inventory.
 */
export function parseOpenApiToScreens(rawDoc: unknown, baseUrl: string, existing: Screen[] = []): Screen[] {
  const doc = asObj(rawDoc);
  const inv = new InventoryBuilder();
  if (existing.length) inv.seed(existing);
  if (!doc) return inv.screens();

  // JSON-pointer $ref resolver — handles 3.x #/components/schemas/X and 2.0 #/definitions/X uniformly.
  const deref = (ref: string): OANode | undefined => {
    const parts = ref.replace(/^#\//, "").split("/");
    let cur: unknown = doc;
    for (const seg of parts) {
      const o = asObj(cur);
      if (!o) return undefined;
      cur = o[seg.replace(/~1/g, "/").replace(/~0/g, "~")];
    }
    return asObj(cur);
  };
  const shape = (schema: OANode | undefined): JsonShape | null => (schema ? schemaToJsonShape(schema, deref) : null);

  // securitySchemes (3.x) / securityDefinitions (2.0) → coarse auth mask.
  const schemes = asObj(asObj(doc["components"])?.["securitySchemes"]) ?? asObj(doc["securityDefinitions"]);
  const opAuth = (op: OANode): ApiCall["auth"] => {
    const reqs = asArr(op["security"] ?? doc["security"]);
    const names = reqs.flatMap((r) => Object.keys(asObj(r) ?? {}));
    if (names.length === 0) return "none"; // no security, or `security: [{}]` (anonymous allowed)
    for (const name of names) {
      const sc = asObj(schemes?.[name]);
      if (str(sc?.["type"]) === "apiKey" && str(sc?.["in"]) === "cookie") return "cookie";
    }
    return "bearer";
  };

  const opReqSchema = (op: OANode): JsonShape | null => {
    // 3.x requestBody
    const content = asObj(asObj(op["requestBody"])?.["content"]);
    if (content) {
      const mt = asObj(content["application/json"] ?? content[Object.keys(content)[0] ?? ""]);
      const s = shape(asObj(mt?.["schema"]));
      if (s) return s;
    }
    // 2.0 in:body
    for (const raw of asArr(op["parameters"])) {
      let p = asObj(raw);
      const ref = str(p?.["$ref"]);
      if (ref) p = deref(ref);
      if (p && str(p["in"]) === "body") {
        const s = shape(asObj(p["schema"]));
        if (s) return s;
      }
    }
    // 2.0 formData → synthesize an object
    const fields: Record<string, JsonShape> = {};
    for (const raw of asArr(op["parameters"])) {
      const p = asObj(raw);
      const name = str(p?.["name"]);
      if (p && str(p["in"]) === "formData" && name) fields[name] = { type: primType(str(p["type"])) };
    }
    return Object.keys(fields).length ? { type: "object", fields } : null;
  };

  const opResSchema = (op: OANode): JsonShape | null => {
    const responses = asObj(op["responses"]);
    if (!responses) return null;
    const code = Object.keys(responses).find((c) => /^2\d\d$/.test(c)) ?? (responses["default"] ? "default" : undefined);
    if (!code) return null;
    const resp = asObj(responses[code]);
    const content = asObj(resp?.["content"]);
    if (content) {
      const mt = asObj(content["application/json"] ?? content[Object.keys(content)[0] ?? ""]);
      const s = shape(asObj(mt?.["schema"]));
      if (s) return s;
    }
    return shape(asObj(resp?.["schema"])); // 2.0 response schema
  };

  const buildParams = (template: string, pathItem: OANode, op: OANode, reqSchema: JsonShape | null): Param[] => {
    const params: Param[] = [];
    const seen = new Set<string>();
    const add = (p: Param): void => {
      const k = `${p.in}:${p.name}`;
      if (!seen.has(k)) {
        seen.add(k);
        params.push(p);
      }
    };
    for (const m of template.matchAll(/\{([^}]+)\}/g)) {
      const name = m[1] ?? "";
      if (name) add({ name, in: "path", example: "1", guessedType: guessParamType(name, "path") });
    }
    for (const raw of [...asArr(pathItem["parameters"]), ...asArr(op["parameters"])]) {
      let p = asObj(raw);
      const ref = str(p?.["$ref"]);
      if (ref) p = deref(ref);
      const inLoc = str(p?.["in"]);
      const name = str(p?.["name"]);
      if (p && name && (inLoc === "query" || inLoc === "header")) {
        add({ name, in: inLoc as ParamLoc, example: exampleStr(p), guessedType: guessParamType(name, inLoc as ParamLoc, exampleStr(p)) });
      }
    }
    if (reqSchema && reqSchema.type === "object") {
      for (const fname of Object.keys(reqSchema.fields)) add({ name: fname, in: "body", example: "", guessedType: guessParamType(fname, "body") });
    }
    return params;
  };

  const paths = asObj(doc["paths"]);
  if (!paths) return inv.screens();
  for (const [specPath, rawItem] of Object.entries(paths)) {
    const pathItem = asObj(rawItem);
    if (!pathItem) continue;
    const ep = buildEndpoint(baseUrl, specPath);
    if (!ep) continue;
    for (const method of METHODS) {
      const op = asObj(pathItem[method]);
      if (!op) continue;
      const reqSchema = opReqSchema(op);
      const resSchema = opResSchema(op);
      const auth = opAuth(op);
      const api: ApiCall = { method: method.toUpperCase(), urlTemplate: ep.template, auth, reqSchema, resSchema };
      const params = buildParams(ep.template, pathItem, op, reqSchema);
      const authState: AuthState = auth === "none" ? "unauth" : "post-login";
      const screenType = classifyScreenType({ urlTemplate: ep.template, finalUrl: ep.observedUrl, forms: [], title: "", visibleText: "" });
      const labels = deriveLabels(screenType, params, [api], "");
      const domSkeletonHash = hashDomSkeleton(`api:${ep.template}`); // deterministic, DOM-less; distinct from real skeleton hashes
      const built: BuiltScreen = {
        dedupKey: `${ep.template} ${domSkeletonHash}`,
        observedUrl: ep.observedUrl,
        capTemplate: ep.template, // spec endpoints are real API paths (no SPA hash) → cap key = the template
        screen: {
          urlTemplate: ep.template,
          observedUrls: [ep.observedUrl],
          authState,
          screenType,
          description: describeScreen(screenType, ep.template, params, [api]),
          params,
          apis: [api],
          screenshot: "",
          domSkeletonHash,
          labels,
        },
      };
      inv.ingestBuilt(built); // same template → merges (unions apis/params, fills empty schemas)
    }
  }
  return inv.screens();
}

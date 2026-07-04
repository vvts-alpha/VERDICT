// DESIGN §5 — input model
//
// Two forms: single_url, which follows same-origin + descendants from an entry URL, and
// scope_manifest, which reads a structured scope (YAML/JSON).

export type TargetInput =
  | {
      kind: "single_url";
      url: string;
      followLinks: boolean;
      maxDepth: number;
    }
  | {
      kind: "scope_manifest";
      /** Path to the structured scope (YAML/JSON) */
      path: string;
    };

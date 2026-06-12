// DESIGN §5 — 入力モデル
//
// 2 系統: 起点 URL から同一オリジン + 配下を辿る single_url と、
// 構造化スコープ(YAML/JSON)を読む scope_manifest。

export type TargetInput =
  | {
      kind: "single_url";
      url: string;
      followLinks: boolean;
      maxDepth: number;
    }
  | {
      kind: "scope_manifest";
      /** 構造化スコープ(YAML/JSON)へのパス */
      path: string;
    };

// LLM 出力から JSON を頑健に取り出す。```json フェンス除去 + 最初の {/[ から括弧マッチ。

export function extractJson(text: string): unknown {
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const body = (fence?.[1] ?? text).trim();

  // まず素直にパース
  try {
    return JSON.parse(body);
  } catch {
    /* prose に埋もれている可能性 → 括弧マッチで走査 */
  }

  const start = body.search(/[{[]/);
  if (start === -1) throw new SyntaxError("no JSON value found in LLM output");
  const open = body.charAt(start);
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < body.length; i += 1) {
    const ch = body.charAt(i);
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
    } else if (ch === '"') {
      inStr = true;
    } else if (ch === open) {
      depth += 1;
    } else if (ch === close) {
      depth -= 1;
      if (depth === 0) return JSON.parse(body.slice(start, i + 1));
    }
  }
  throw new SyntaxError("unbalanced JSON in LLM output");
}

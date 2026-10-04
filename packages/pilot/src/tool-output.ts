/** Shared by paginated tools and both model transports. Counts JS characters, like the context serializer. */
export const MAX_TOOL_RESULT_CHARS = 16000;

export function boundedToolText(body: string): string {
  if (body.length <= MAX_TOOL_RESULT_CHARS) return body;
  if (/^\s*[\[{]/.test(body)) {
    let preview = body.slice(0, MAX_TOOL_RESULT_CHARS - 200);
    for (;;) {
      const result = JSON.stringify({ truncated: true, note: "Tool output exceeded the context limit. Request a smaller page or narrower detail.", preview });
      if (result.length <= MAX_TOOL_RESULT_CHARS) return result;
      preview = preview.slice(0, Math.floor(preview.length * 0.8));
    }
  }
  return `${body.slice(0, MAX_TOOL_RESULT_CHARS - 20)}\n…(truncated)`;
}

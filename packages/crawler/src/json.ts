// DESIGN §6.2 — req/res 本文から JsonShape を推定。

import type { JsonShape } from "@veritas/core";

const UNKNOWN_SHAPE: JsonShape = { type: "unknown" };

export function inferJsonShapeFromValue(value: unknown): JsonShape {
  if (value === null) return { type: "null" };
  if (Array.isArray(value)) {
    return { type: "array", items: value.length > 0 ? inferJsonShapeFromValue(value[0]) : UNKNOWN_SHAPE };
  }
  switch (typeof value) {
    case "string":
      return { type: "string" };
    case "number":
      return { type: "number" };
    case "boolean":
      return { type: "boolean" };
    case "object": {
      const fields: Record<string, JsonShape> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        fields[k] = inferJsonShapeFromValue(v);
      }
      return { type: "object", fields };
    }
    default:
      return UNKNOWN_SHAPE;
  }
}

/** JSON 文字列を JsonShape に。null/空/非 JSON は null。 */
export function inferJsonShape(sample: string | null): JsonShape | null {
  if (sample === null) return null;
  const trimmed = sample.trim();
  if (trimmed === "") return null;
  try {
    return inferJsonShapeFromValue(JSON.parse(trimmed));
  } catch {
    return null;
  }
}

import type { StateView } from "@veritas/core";

export type ScreenHonesty = StateView["screenHonesty"][string];
export type EffectiveStatus = ScreenHonesty["status"];

/** Read the core projection; the browser never reimplements screenChecks or plan matching.
 * Older servers without this field have no trustworthy verdict projection. Fail closed rather
 * than treating their raw "clean" scan status (or a coverage note) as verified execution. */
export function screenHonestyMap(view: StateView): Map<string, ScreenHonesty> {
  if (view.screenHonesty) return new Map(Object.entries(view.screenHonesty));
  return new Map(view.screenScans.map((scan) => [
    scan.screenId,
    {
      raw: scan.status,
      status: scan.status === "clean" || scan.status === "finding" || scan.status === "suspected"
        ? "unknown-records" as const : scan.status,
      legacy: false,
      gaps: 0,
      unfulfilled: 0,
    },
  ]));
}

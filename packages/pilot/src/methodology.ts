/** Restore full structured plans and migrate the historical human-readable PLAN events. */
export function restoreMethodologyPlans(events: ReadonlyArray<{ type: string; payload: unknown }>): Map<string, string> {
  const plans = new Map<string, string>();
  const structured = new Set<string>();
  for (const event of events) {
    if (!event.payload || typeof event.payload !== "object") continue;
    const payload = event.payload as Record<string, unknown>;
    if (event.type === "methodology_recorded" && typeof payload.screenId === "string" &&
        typeof payload.plan === "string" && Array.isArray(payload.vulnClasses) &&
        payload.vulnClasses.every((c) => typeof c === "string")) {
      plans.set(payload.screenId, `classes=[${payload.vulnClasses.join(",")}] ${payload.plan}`);
      structured.add(payload.screenId);
    } else if (event.type === "note" && typeof payload.message === "string") {
      const match = /^📋 PLAN (s-\d+): ((?:classes=)?\[[^\]]*\].*)$/s.exec(payload.message);
      if (match?.[1] && match[2] && !structured.has(match[1])) {
        plans.set(match[1], match[2].startsWith("classes=") ? match[2] : `classes=${match[2]}`);
      }
    }
  }
  return plans;
}

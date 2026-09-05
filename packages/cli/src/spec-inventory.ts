import { join } from "node:path";
import { isInScope } from "@veritas/core";
import type { AssessmentStore, ScopePolicy } from "@veritas/core";
import { parseOpenApiToScreens, validateOpenApiDocument, writeScreenInventory, buildInventory } from "@veritas/crawler";

/** Seed an ordinary pilot run so resume starts at methodology, preserving the operator's scope. */
export function seedSpecInventory(store: AssessmentStore, id: string, runsDir: string, doc: unknown, base: string, scope: ScopePolicy): number {
  validateOpenApiDocument(doc);
  const screens = parseOpenApiToScreens(doc, base).filter((screen) => screen.observedUrls.some((url) => isInScope(url, scope)));
  if (!screens.length) throw new Error("No API operations fall inside the configured scope");
  for (const screen of screens) store.upsertScreen(id, screen);
  writeScreenInventory(join(runsDir, id, "screen_inventory.json"), buildInventory(base, screens));
  store.setPhase(id, "phase1_label");
  store.appendEvent(id, { type: "note", payload: { message: `Imported API specification: ${screens.length} endpoint groups. Starting methodology and diagnosis from this inventory.` } });
  return screens.length;
}

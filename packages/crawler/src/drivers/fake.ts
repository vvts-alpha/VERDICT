// In-memory driver for tests/demos. Runs the whole pipeline deterministically without a browser.

import type { Driver, Observation } from "../types.js";

/** Page definitions keyed by URL (unspecified fields default to empty). */
export type FakeSite = Record<string, Partial<Observation>>;

function stripTrailingSlash(u: string): string {
  return u.length > 1 && u.endsWith("/") ? u.slice(0, -1) : u;
}

export class FakeDriver implements Driver {
  constructor(private readonly site: FakeSite) {}

  async visit(url: string): Promise<Observation> {
    const def = this.site[url] ?? this.site[stripTrailingSlash(url)] ?? this.site[`${url}/`] ?? {};
    return {
      requestedUrl: url,
      finalUrl: def.finalUrl ?? url,
      status: def.status ?? 200,
      title: def.title ?? "",
      domSkeleton: def.domSkeleton ?? "html>(body)",
      visibleText: def.visibleText ?? "",
      forms: def.forms ?? [],
      links: def.links ?? [],
      virtualRoutes: def.virtualRoutes ?? [],
      apiCalls: def.apiCalls ?? [],
    };
  }

  async close(): Promise<void> {
    /* no-op */
  }
}

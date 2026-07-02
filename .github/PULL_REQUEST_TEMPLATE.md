## What & why

Brief description of the change and the motivation.

## Checklist

- [ ] `pnpm -r build` and `pnpm -r test` pass (Node ≥ 24)
- [ ] New/changed behavior has tests (uses `FakeDriver` / `FakeHttpClient` / `FakeLlmClient` — no real network/LLM in tests)
- [ ] Evidence discipline preserved — no finding is marked `confirmed` without a failing negative control + ≥2 stable positive replays
- [ ] Contract types stay in `@veritas/core` (not redeclared elsewhere); scope gate intact on any new network action
- [ ] Docs/README updated if user-facing

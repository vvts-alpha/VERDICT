# Release procedure and quality gates

Releases identify the exact source, dependencies, tested installer, and published bytes. Unit tests alone do not establish that the packaged application works. A failed or pending Windows workflow blocks release, even if another machine produced a working installer.

## Versions and artifacts

Use `YEAR.MONTH.SEQUENCE` for stable versions, increasing the numeric sequence within the month. The last component is a release sequence, not a calendar day. Stable versions must increase; do not label a prerelease suffix as a stable hotfix or reuse a published tag.

The version source is `apps/desktop/package.json`. The tag is `v<version>`; the installer is `VERDICT.Setup.<version>.exe`. Electron is pinned there and inferred by the builder. Use Node 24+, pnpm 9.15.4, the unchanged lockfile, and the pinned builder version.

| File | Purpose |
| --- | --- |
| `VERDICT.Setup.<version>.exe` | Tested Windows x64 installer |
| `verdict-burp-audit.jar` | Companion extension with verified provenance |
| `WINDOWS-QUICKSTART.md` | Instructions rendered from the common template |
| `artifact-manifest.json` | CI source, runtime, installer hash, size, and package checks |
| `live-validation.json` | Windows live checks bound to that installer hash |
| `release-manifest.json` | Source, CI/build runs, and companion provenance |
| `SHA256SUMS.txt` | Hashes of all other assets |

## Build, test, promote

1. Reproduce the defect and add behavior-focused regression coverage. Build dependencies before dependent tests. Use fake models/HTTP clients for regressions and authorized local fixtures for integration checks.
2. Commit and push the complete change. Wait for **CI** and **Build Windows installer** to succeed on the same commit. Windows CI makes a frozen production install, materializes runtime dependencies, packages the app, compares every installer file with the tested directory, and runs GUI/API/CLI/native SDK checks before uploading. It then downloads both artifacts and repeats those checks to detect files lost or changed during artifact transfer, including hidden files.
3. Run `node tools/promote-release.cjs prepare <windows-run-id> <fresh-directory>`. It downloads the exact CI installer and unpacked application, rejecting failed/pending/mismatched CI, runtime mismatches, foreign packages, private files, version regressions, and size overruns.
4. On Windows, run `node tools/check-desktop-bundle.cjs <directory>/win-unpacked --live-settings <private-settings.json>`. Use Node 24+ and 7-Zip; `VERDICT_7ZIP` can specify its executable. This uses an isolated temporary profile, saves/reloads settings, checks both models and the automation browser, and performs a local no-op tool roundtrip. Its `live-validation.json` contains results, not credentials. The live roundtrip currently covers an OpenAI-compatible provider. Claude's executable is started separately; do not claim that a full Claude assessment was tested.
5. Fill a local copy of `templates/release-changes.example.json`. Run `node tools/promote-release.cjs check <windows-run-id> <changes.json> <live-validation.json>`. It downloads the CI installer again, binds validation to its hash, generates release notes, and verifies companion provenance. Changed Burp extension source blocks promotion until its new companion build is integrated and validated.
6. For an authorized release, run the same command with `publish`. No repeated permission question is needed. The tool creates/verifies the tag at the tested commit, creates/resumes a matching draft, uploads files, verifies GitHub's stored sizes and hashes, rechecks CI, and publishes with the explicit tag and source. It verifies the latest release, tag reference, and all download URLs afterward. Upload failure leaves a draft. Published assets are immutable; corrections need a newer version.

Never rebuild between validation and upload, substitute a local artifact, or publish while checks are running. WSL uploads use native Windows curl when available; credentials pass through memory, not command-line arguments or files. Transfer delays do not justify skipping validation.

## Failure classes and evidence

| Risk | Automated gate | Targeted verification |
| --- | --- | --- |
| Missing dependencies or foreign binaries | Frozen production install; CLI/SDK startup; platform inspection | Run the materialized app without workspace dependencies |
| Wrong Electron/Node or model transport | Runtime match; provider contract tests; Windows live model/tool checks | Check the affected provider and error categories; one provider's pass does not establish all-provider support |
| Premature completion or lost progress | Incomplete-stage, frontier, and persisted recon/plan regressions | Interrupt/resume the affected stage and retain queued work/findings |
| Scope, credentials, permissions | Scope/PSL and HTTP/WS origin/token suites | Rejected requests, redirects, session isolation, then a valid request |
| Invalid input or service outage | Malformed request, timeout, 401/429/5xx, and context-failure tests | App remains usable and errors reveal no credentials |
| UI or packaged startup regression | Windows GUI startup, IPC, renderer errors, screenshot | Visually check changed UI and the actual export/navigation/dialog |
| Saved data or settings migration | Existing-state fixtures and save/reload checks | Back up and exercise old data in an isolated profile; never mutate user data during smoke tests |
| Dependency security/drift | Frozen lockfile; CI audit at low severity | Review advisories and compatibility; never suppress alerts merely to obtain green CI |
| Size growth or private files | 200 MB installer, 800 MB unpacked, maximum 20% growth, private-file scan | Inspect component sizes before explicitly revising budgets |
| Wrong release, stale companion, partial upload | Source/run binding, increasing version, companion source comparison, uploaded hashes | Check the distribution path and intended latest tag |

Size budgets live in `tools/release-validation.cjs`. Changes need measured component sizes and a reason in the PR. Gate tests must reject faulty inputs; simply testing that the current configuration exists is insufficient.

## Formats and follow-up

Use the PR template, bug report form, release changes JSON, and `templates/incident-review.md`. Release notes always use **Summary, Changes, Upgrade, Validation, Known limitations**. Measured facts come from manifests/workflow results. Do not invent test counts or call skipped checks successful.

Keep actual internal incident records and handoff notes local. Separate confirmed defects from hypotheses, with reproduction evidence and priority. Newly found defects need a regression case and targeted verification. P1 findings block promotion; disclose lower-priority known limitations and never claim their affected paths passed.

Repository checks cannot prevent an administrator from manually bypassing the process. The working rule is to use the promotion tool and never treat a checklist or an earlier green commit as evidence for a different installer.

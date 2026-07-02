# Security Policy

## Reporting a vulnerability **in VERDICT itself**

If you discover a security issue in VERDICT's own code (not in a target you are
assessing), please report it **privately** — do **not** open a public issue.

- Preferred: open a **GitHub Security Advisory** on this repo
  (**Security → Report a vulnerability**). This keeps the report private until a
  fix is ready.
- We aim to acknowledge reports within **72 hours** and to agree a disclosure
  timeline with you.

Please include: affected version/commit, a minimal reproduction, and the impact
you observed. Coordinated disclosure is appreciated — give us reasonable time to
ship a fix before publishing.

## Authorized use only — this is an offensive tool

VERDICT actively probes and exploits web/API targets. **Use it only against
systems you own or are explicitly authorized in writing to test** (your own apps,
a signed penetration-testing engagement, a bug-bounty program's in-scope assets,
or a CTF/benchmark you control).

- Every network action passes a **scope gate** (`isInScope`) and out-of-scope
  requests are denied — but this is a *safety net*, **not** authorization. You are
  responsible for having permission for everything in scope.
- VERDICT never fabricates or steals credentials — it only uses auth material the
  operator explicitly supplies, and it never fires destructive PoCs (read-only
  file/command output or out-of-band callbacks only).

Unauthorized scanning or exploitation of systems you do not control may be
illegal. The authors accept no liability for misuse.

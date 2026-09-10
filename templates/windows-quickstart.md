# VERDICT {{VERSION}} — Windows quickstart

## Install

Close VERDICT, download `VERDICT.Setup.{{VERSION}}.exe`, and run it. Settings and saved assessments live in the VERDICT folder under your Windows roaming application data directory. Keep a backup before migrating important assessments.

`SHA256SUMS.txt` records release hashes. In PowerShell, use `Get-FileHash .\VERDICT.Setup.{{VERSION}}.exe -Algorithm SHA256` to compare the installer hash.

## Configure

Open **Settings → Models**, select your provider, and enter its model IDs and API key. For OpenCodeGo, the preset endpoint is `https://opencode.ai/zen/go/v1`. Deep and Light may use the same model. Run the connection checks after saving.

Install Chrome or Edge for automation. If detection fails, select its executable under **Network**. The automation browser is separate from VERDICT's bundled Electron runtime.

For Burp Audit integration, load `verdict-burp-audit.jar` and configure its API URL and `X-Scan-Token` under **Burp**. The token must match the extension. Enable post-diagnosis scanning only when needed, then check the connection.

## Run an assessment

Create an assessment for an authorized target. Review allowed hosts and scope before starting. Supply the target's login method when needed. An incomplete model stage should pause the assessment; correct its cause and resume.

## Export and troubleshoot

Export reports from the assessment's export menu. PDF export needs the automation browser.

When reporting a problem, include the version shown in **About**, Windows version, installer filename, provider/model IDs, reproduction steps, and the error. Remove API keys, tokens, cookies, target credentials, and private assessment data from logs or screenshots.

Release notes describe changes, upgrade requirements, validation, and limitations. `artifact-manifest.json` identifies the tested installer and runtime; `release-manifest.json` identifies its source and build jobs.

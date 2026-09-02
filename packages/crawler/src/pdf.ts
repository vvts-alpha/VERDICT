// HTML → PDF (Chromium print). Used for report PDF output. Reuses the existing playwright-core, so
// zero new dependencies. Local rendering, so it doesn't pass the scope gate (it's not a network action).
//
// The desktop app does not ship Playwright's chromium_headless_shell. Prefer an explicit binary
// (VERDICT_BROWSER_PATH / Settings), then installed Chrome/Edge, then a Playwright channel.

import { existsSync } from "node:fs";
import { join } from "node:path";

export interface HtmlToPdfOptions {
  /** Path to the chromium binary (CLI --browser-path / VERDICT_BROWSER_PATH / VERITAS_BROWSER_PATH). */
  executablePath?: string;
  /** Playwright browser channel (e.g. "msedge" / "chrome") when no binary path is set. */
  channel?: string;
  /** true for container runs (--no-sandbox). */
  noSandbox?: boolean;
  /** Paper size (default "A4"). */
  format?: string;
  landscape?: boolean;
}

export interface PlaywrightLaunchChoice {
  executablePath?: string;
  channel?: string;
}

export interface ResolvePlaywrightLaunchIo {
  exists?: (p: string) => boolean;
  env?: NodeJS.Dict<string | undefined>;
  platform?: NodeJS.Platform;
}

/** Installed Chrome/Edge/Chromium — keep in sync with apps/desktop/src/settings.ts detectSystemChromium. */
export function detectSystemChromium(
  io: Pick<ResolvePlaywrightLaunchIo, "exists" | "env" | "platform"> = {},
): string | undefined {
  const exists = io.exists ?? existsSync;
  const env = io.env ?? process.env;
  const platform = io.platform ?? process.platform;
  const candidates: string[] = [];
  if (platform === "win32") {
    const pf = env.PROGRAMFILES ?? "C:\\Program Files";
    const pf86 = env["PROGRAMFILES(X86)"] ?? "C:\\Program Files (x86)";
    const local = env.LOCALAPPDATA ?? "";
    candidates.push(
      join(pf, "Google", "Chrome", "Application", "chrome.exe"),
      join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
      join(local, "Google", "Chrome", "Application", "chrome.exe"),
      join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
      join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
    );
  } else if (platform === "darwin") {
    candidates.push(
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    );
  } else {
    candidates.push(
      "/usr/bin/google-chrome-stable",
      "/usr/bin/google-chrome",
      "/usr/bin/chromium-browser",
      "/usr/bin/chromium",
      "/usr/bin/microsoft-edge",
      "/snap/bin/chromium",
    );
  }
  return candidates.find((p) => p.length > 0 && exists(p));
}

/** Pick a Playwright launch target. Never default to the unbundled chromium_headless_shell on Windows. */
export function resolvePlaywrightLaunch(
  opts: Pick<HtmlToPdfOptions, "executablePath" | "channel"> = {},
  io: ResolvePlaywrightLaunchIo = {},
): PlaywrightLaunchChoice {
  const exists = io.exists ?? existsSync;
  const env = io.env ?? process.env;
  const platform = io.platform ?? process.platform;
  const paths = [
    opts.executablePath,
    env.VERDICT_BROWSER_PATH,
    env.VERITAS_BROWSER_PATH,
    detectSystemChromium({ exists, env, platform }),
  ];
  for (const raw of paths) {
    const p = raw?.trim();
    if (p && exists(p)) return { executablePath: p };
  }
  const channel = (opts.channel ?? env.VERDICT_BROWSER_CHANNEL)?.trim();
  if (channel) return { channel };
  if (platform === "win32") return { channel: "msedge" };
  return {};
}

/** Render an HTML string to an A4 PDF and return it as a Buffer. Images are assumed self-contained (inline). */
export async function htmlToPdf(html: string, opts: HtmlToPdfOptions = {}): Promise<Buffer> {
  const { chromium } = await import("playwright-core");
  const choice = resolvePlaywrightLaunch(opts);
  const launchOpts = {
    headless: true,
    ...(choice.executablePath ? { executablePath: choice.executablePath } : {}),
    ...(choice.channel ? { channel: choice.channel } : {}),
    ...(opts.noSandbox ? { args: ["--no-sandbox"] } : {}),
  };
  let browser;
  try {
    browser = await chromium.launch(launchOpts);
  } catch (e) {
    const where = choice.executablePath
      ? choice.executablePath
      : choice.channel
        ? `channel=${choice.channel}`
        : "Playwright Chromium";
    throw new Error(
      `PDF needs Chrome/Edge (Settings → scan browser, or VERDICT_BROWSER_PATH). Tried ${where}. ${String(e).split("\n")[0]}`,
    );
  }
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "load" });
    return await page.pdf({
      format: opts.format ?? "A4",
      printBackground: true,
      landscape: !!opts.landscape,
      margin: { top: "12mm", bottom: "14mm", left: "12mm", right: "12mm" },
    });
  } finally {
    await browser.close();
  }
}

// HTML → PDF (Chromium print). Used for report PDF output. Reuses the existing playwright-core, so
// zero new dependencies. Local rendering, so it doesn't pass the scope gate (it's not a network action).

export interface HtmlToPdfOptions {
  /** Path to the chromium binary (defaults to playwright's default; from the CLI --browser-path / VERITAS_BROWSER_PATH). */
  executablePath?: string;
  /** true for container runs (--no-sandbox). */
  noSandbox?: boolean;
  /** Paper size (default "A4"). */
  format?: string;
  landscape?: boolean;
}

/** Render an HTML string to an A4 PDF and return it as a Buffer. Images are assumed self-contained (inline). */
export async function htmlToPdf(html: string, opts: HtmlToPdfOptions = {}): Promise<Buffer> {
  const { chromium } = await import("playwright-core");
  const browser = await chromium.launch({
    headless: true,
    ...(opts.executablePath ? { executablePath: opts.executablePath } : {}),
    ...(opts.noSandbox ? { args: ["--no-sandbox"] } : {}),
  });
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

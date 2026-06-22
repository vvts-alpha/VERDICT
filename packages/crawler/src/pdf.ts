// HTML → PDF(Chromium 印刷)。レポートの PDF 出力に使う。既存の playwright-core を再利用するので
// 新規依存はゼロ。ローカル描画なのでスコープゲートは通さない(ネットワーク行為ではない)。

export interface HtmlToPdfOptions {
  /** chromium 実体のパス(未指定なら playwright 既定。CLI の --browser-path / VERITAS_BROWSER_PATH 由来)。 */
  executablePath?: string;
  /** コンテナ実行では true(--no-sandbox)。 */
  noSandbox?: boolean;
  /** 用紙(既定 "A4")。 */
  format?: string;
  landscape?: boolean;
}

/** HTML 文字列を A4 PDF にして Buffer で返す。画像は self-contained(inline)前提。 */
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

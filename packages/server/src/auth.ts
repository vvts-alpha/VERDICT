// WebUI 認証ゲート(単一パスワード + 署名セッション Cookie)。serve を 0.0.0.0 で公開する際に
// 誰でも観測 WebUI/API/WS に触れてしまうのを防ぐ。単一オペレータ前提・依存なし(node:crypto)。
//  - Cookie 値 = `<ts>.<hmacSHA256(password, ts)>`(発行時刻入り → 期限と毎回の変化を持つ・ステートレス)。
//  - パスワードは cmdServe が --password / env AMRAAM_WEB_PASSWORD(.env 自動ロード)で渡す。
import { createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

const COOKIE = "amraam_session";
const MAX_AGE_MS = 7 * 24 * 3600 * 1000; // 7 日

function hmac(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}

function eqConst(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/** セッション Cookie 値を発行(発行時刻 + HMAC)。 */
export function signSession(secret: string, now: number): string {
  const ts = String(now);
  return `${ts}.${hmac(secret, ts)}`;
}

/** Cookie 値を検証(HMAC 一致 + 期限内)。 */
export function verifySession(secret: string, value: string, now: number): boolean {
  const dot = value.indexOf(".");
  if (dot <= 0) return false;
  const ts = value.slice(0, dot);
  const mac = value.slice(dot + 1);
  const n = Number.parseInt(ts, 10);
  if (!Number.isFinite(n) || now - n > MAX_AGE_MS || now - n < -60_000) return false;
  return eqConst(mac, hmac(secret, ts));
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/** リクエストが認証済みか(セッション Cookie が有効か)。 */
export function isAuthedReq(req: IncomingMessage, secret: string, now: number): boolean {
  const v = parseCookies(req.headers.cookie)[COOKIE];
  return v ? verifySession(secret, v, now) : false;
}

/** POST /auth: パスワード照合 → Cookie 発行して / へ、失敗は /login?e=1 へ。 */
export function handleAuthSubmit(req: IncomingMessage, res: ServerResponse, secret: string, now: number): void {
  let body = "";
  let tooBig = false;
  req.on("data", (c) => {
    body += c;
    if (body.length > 8192) {
      tooBig = true;
      req.destroy();
    }
  });
  req.on("end", () => {
    if (tooBig) return;
    const pw = new URLSearchParams(body).get("password") ?? "";
    if (pw && eqConst(pw, secret)) {
      const cookie = signSession(secret, now);
      res.writeHead(302, {
        "set-cookie": `${COOKIE}=${cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${MAX_AGE_MS / 1000}`,
        location: "/",
      });
      res.end();
    } else {
      res.writeHead(302, { location: "/login?e=1" });
      res.end();
    }
  });
}

/** GET /logout: Cookie を失効させて /login へ。 */
export function handleLogout(res: ServerResponse): void {
  res.writeHead(302, { "set-cookie": `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`, location: "/login" });
  res.end();
}

/** ログインフォーム(自己完結・依存なし)。 */
export function loginPageHtml(error: boolean): string {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" /><title>AMRAAM — sign in</title>
<style>
  body { margin: 0; height: 100vh; display: grid; place-items: center; background: #14161a; color: #d7dbe0;
    font: 14px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  form { background: #1b1e24; border: 1px solid #2a2f38; border-radius: 10px; padding: 28px 26px; width: 300px; }
  .brand { font-weight: 700; letter-spacing: 2px; color: #6db0ff; margin: 0 0 18px; }
  input { width: 100%; box-sizing: border-box; background: #0d0f13; color: #d7dbe0; border: 1px solid #2a2f38;
    border-radius: 6px; padding: 9px 10px; font: inherit; }
  button { width: 100%; margin-top: 12px; background: #2b3340; color: #fff; border: 1px solid #3a414d;
    border-radius: 6px; padding: 9px; font: inherit; cursor: pointer; }
  button:hover { background: #353d4a; }
  .err { color: #e06c75; font-size: 12px; margin: 10px 0 0; }
</style></head><body>
  <form method="POST" action="/auth">
    <p class="brand">AMRAAM</p>
    <input type="password" name="password" placeholder="password" autofocus autocomplete="current-password" />
    <button type="submit">Sign in</button>
    ${error ? '<p class="err">Wrong password</p>' : ""}
  </form>
</body></html>`;
}

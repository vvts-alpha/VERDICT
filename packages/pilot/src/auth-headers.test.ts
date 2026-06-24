// 認証材料の伝播: http_request / probe_logic / verify_access が cookie だけでなく Bearer JWT も載せること。
// Juice Shop 等の token-auth write API(/rest/basket, /api/Orders…)が 401 で死なないための回帰テスト。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { authHeaders } from "./tools.js";

test("authHeaders carries both cookie and Bearer JWT", () => {
  const h = authHeaders({ currentCookie: "token=abc", currentBearer: "eyJhbG.payload.sig" });
  assert.equal(h.cookie, "token=abc");
  assert.equal(h.authorization, "Bearer eyJhbG.payload.sig");
});

test("authHeaders omits whichever material is absent", () => {
  // cookie 認証だけのアプリ(従来挙動)
  assert.deepEqual(authHeaders({ currentCookie: "s=1", currentBearer: "" }), { cookie: "s=1" });
  // bearer 認証だけのアプリ(Juice Shop 系)
  assert.deepEqual(authHeaders({ currentCookie: "", currentBearer: "jwt.tok.en" }), { authorization: "Bearer jwt.tok.en" });
  // 未ログイン
  assert.deepEqual(authHeaders({ currentCookie: "", currentBearer: "" }), {});
});

test("caller headers can override the session default (spread last) — enables an unauth control", () => {
  const session = { currentCookie: "token=abc", currentBearer: "jwt.tok.en" };
  // ツール側は { ...authHeaders(s), ...callerHeaders } の順で合成する。空指定で認証を外せる。
  const merged = { ...authHeaders(session), cookie: "", authorization: "" };
  assert.equal(merged.cookie, "");
  assert.equal(merged.authorization, "");
});

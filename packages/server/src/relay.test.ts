// attended×LiveHands 中継ハブ(Relay)を fake WS で検証。子(agent) ⇄ serve ⇄ 操作者(session) の結線。
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { IncomingMessage } from "node:http";
import type { WebSocket } from "ws";

import { Relay } from "./relay.js";

class FakeWs extends EventEmitter {
  readyState = 1;
  sent: unknown[] = [];
  send(s: string): void {
    this.sent.push(JSON.parse(s));
  }
  close(): void {
    this.readyState = 3;
    this.emit("close");
  }
  recv(obj: unknown): void {
    this.emit("message", JSON.stringify(obj));
  }
  last(): unknown {
    return this.sent[this.sent.length - 1];
  }
}
const req = (url: string): IncomingMessage => ({ url }) as IncomingMessage;
const ws = (w: FakeWs): WebSocket => w as unknown as WebSocket;

test("relay: agent registers, viewer relays frames in, input out", () => {
  const relay = new Relay();
  relay.issueToken("a-1", "tok");

  const agent = new FakeWs();
  relay.handleAgent(ws(agent), req("/ws/agent?id=a-1&token=tok"), () => {});
  agent.recv({ t: "sessions", roles: [{ role: "primary", url: "https://x/login" }] });
  assert.deepEqual(relay.rolesFor("a-1"), [{ role: "primary", url: "https://x/login", awaiting: true }]); // 登録直後はログイン待ち

  // 操作者がタブを開く → agent に start が飛ぶ + 現在 URL を受け取る
  const viewer = new FakeWs();
  relay.handleSession(ws(viewer), req("/ws/session?id=a-1&role=primary"));
  assert.deepEqual(agent.last(), { t: "start", role: "primary" });
  assert.deepEqual(viewer.last(), { t: "url", url: "https://x/login" });

  // agent の frame が viewer に中継される
  agent.recv({ t: "frame", role: "primary", data: "JPEG", meta: {} });
  assert.deepEqual(viewer.last(), { t: "frame", role: "primary", data: "JPEG", meta: {} });

  // 操作者の入力(done 等)が agent に転送される
  viewer.recv({ t: "done" });
  assert.deepEqual(agent.last(), { t: "input", role: "primary", msg: { t: "done" } });
  // done でログイン待ちが解除される(Sessions タブの強調が消える)
  assert.deepEqual(relay.rolesFor("a-1"), [{ role: "primary", url: "https://x/login", awaiting: false }]);

  // viewer が閉じると stop が agent に飛ぶ
  viewer.close();
  assert.deepEqual(agent.last(), { t: "stop", role: "primary" });
});

test("relay: wrong token rejected, no session without agent", () => {
  const relay = new Relay();
  relay.issueToken("a-2", "good");

  const bad = new FakeWs();
  relay.handleAgent(ws(bad), req("/ws/agent?id=a-2&token=bad"), () => {});
  assert.equal(bad.readyState, 3, "bad token → closed");
  assert.deepEqual(relay.rolesFor("a-2"), []);

  const viewer = new FakeWs();
  relay.handleSession(ws(viewer), req("/ws/session?id=a-2&role=primary"));
  assert.deepEqual(viewer.sent[0], { t: "fatal", message: "no live agent for this run" });
  assert.equal(viewer.readyState, 3);
});

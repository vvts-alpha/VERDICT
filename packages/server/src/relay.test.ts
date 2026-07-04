// Verify the attended×LiveHands relay hub (Relay) with fake WS. The wiring child (agent) ⇄ serve ⇄ operator (session).
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
  assert.deepEqual(relay.rolesFor("a-1"), [{ role: "primary", url: "https://x/login", awaiting: true }]); // right after registration, awaiting login

  // operator opens a tab → start is sent to the agent + receives the current URL
  const viewer = new FakeWs();
  relay.handleSession(ws(viewer), req("/ws/session?id=a-1&role=primary"));
  assert.deepEqual(agent.last(), { t: "start", role: "primary" });
  assert.deepEqual(viewer.last(), { t: "url", url: "https://x/login" });

  // the agent's frame is relayed to the viewer
  agent.recv({ t: "frame", role: "primary", data: "JPEG", meta: {} });
  assert.deepEqual(viewer.last(), { t: "frame", role: "primary", data: "JPEG", meta: {} });

  // the operator's input (done etc.) is forwarded to the agent
  viewer.recv({ t: "done" });
  assert.deepEqual(agent.last(), { t: "input", role: "primary", msg: { t: "done" } });
  // done clears awaiting-login (the Sessions tab highlight disappears)
  assert.deepEqual(relay.rolesFor("a-1"), [{ role: "primary", url: "https://x/login", awaiting: false }]);

  // when the viewer closes, stop is sent to the agent
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

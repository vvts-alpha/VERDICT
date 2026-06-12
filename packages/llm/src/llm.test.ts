import { test } from "node:test";
import assert from "node:assert/strict";

import { FakeLlmClient, extractJson } from "./index.js";

test("extractJson parses bare JSON", () => {
  assert.deepEqual(extractJson('{"a":1,"b":[2,3]}'), { a: 1, b: [2, 3] });
});

test("extractJson strips ```json fences", () => {
  assert.deepEqual(extractJson('```json\n{"ok":true}\n```'), { ok: true });
  assert.deepEqual(extractJson("```\n[1,2]\n```"), [1, 2]);
});

test("extractJson recovers an object embedded in prose", () => {
  const text = 'Sure! Here is the result:\n{"screenType":"detail","note":"see }{ braces"}\nHope that helps.';
  assert.deepEqual(extractJson(text), { screenType: "detail", note: "see }{ braces" });
});

test("extractJson throws when there is no JSON", () => {
  assert.throws(() => extractJson("no json here"), /no JSON value/);
});

test("FakeLlmClient records calls and scripts responses", async () => {
  const client = new FakeLlmClient(['{"first":1}', '{"second":2}']);
  assert.deepEqual(extractJson((await client.complete({ prompt: "a" })).text), { first: 1 });
  assert.deepEqual(extractJson((await client.complete({ prompt: "b" })).text), { second: 2 });
  // 配列を使い切ったら最後を反復
  assert.deepEqual(extractJson((await client.complete({ prompt: "c" })).text), { second: 2 });
  assert.equal(client.calls.length, 3);
  assert.equal(client.calls[0]?.prompt, "a");
});

test("FakeLlmClient supports a function responder", async () => {
  const client = new FakeLlmClient((req) => `{"echo":${JSON.stringify(req.prompt)}}`);
  const res = await client.complete({ prompt: "hi", model: "m" });
  assert.deepEqual(extractJson(res.text), { echo: "hi" });
  assert.equal(res.model, "m");
});

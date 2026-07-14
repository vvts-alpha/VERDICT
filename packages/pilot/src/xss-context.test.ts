// Reflected-XSS context guard. infiniteathlete.ai (Next.js) FP'd because the payload echoed into the RSC flight-data
// <script> as inert JSON (with `<` serialized to <), yet the marker substring matched. reflectionIsLive requires
// the marker to appear in a LIVE HTML position (outside <script>), so a script/flight-data-only reflection is refused.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { reflectionIsLive } from "./tools.js";

test("reflectionIsLive: a real reflection in live HTML is live", () => {
  const body = '<h1>Hello <img src=x onerror=alert(\'tok\')></h1>';
  assert.equal(reflectionIsLive(body, "<img src=x onerror=alert('tok')>"), true);
});

test("reflectionIsLive: a reflection ONLY inside a <script> (Next.js flight data) is NOT live", () => {
  // The exact shape from the infiniteathlete.ai evidence: marker inside self.__next_f flight data, < already <.
  const body =
    '<div>page</div>' +
    '<script>self.__next_f.push([1,"...\\"children\\":[\\"__PAGE__?{\\\\\\"name\\\\\\":\\\\\\"' +
    "\\u003cImG sRc=x OnErRoR=alert('tok')\\u003e" +
    '\\\\\\"}\\"..."])</script>';
  // The marker substring is present (the handler part), but only inside <script> → inert.
  assert.equal(reflectionIsLive(body, "OnErRoR=alert('tok')"), false);
});

test("reflectionIsLive: live occurrence wins even if another copy sits in a <script>", () => {
  const body =
    '<script>var x="onclick=alert(\'tok\')"</script>' + // inert copy
    '<button onclick=alert(\'tok\')>go</button>'; // live copy
  assert.equal(reflectionIsLive(body, "onclick=alert('tok')"), true);
});

test("reflectionIsLive: absent marker is not live", () => {
  assert.equal(reflectionIsLive("<h1>nothing here</h1>", "<img onerror=alert('tok')>"), false);
  assert.equal(reflectionIsLive("<h1>x</h1>", ""), false);
});

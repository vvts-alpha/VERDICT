// A3: open-redirect confirmation must parse the Location TARGET HOST, not substring-match the marker — a same-site
// interstitial that reflects the payload in its query (Location: /leaving?url=https://evil/) is NOT an open redirect.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { locationTargetsHost } from "./tools.js";

const OOB = "veritas-oob.example";
const base = "https://app.test/go?next=x";

test("locationTargetsHost: a real cross-host redirect confirms", () => {
  assert.ok(locationTargetsHost(`https://${OOB}/`, base, OOB));
  assert.ok(locationTargetsHost(`//${OOB}/path`, base, OOB)); // protocol-relative → still off-host
});

test("locationTargetsHost: a same-site redirect reflecting the payload does NOT confirm (the substring-match bug)", () => {
  assert.ok(!locationTargetsHost(`/leaving?url=https://${OOB}/`, base, OOB)); // relative → resolves to app.test
  assert.ok(!locationTargetsHost(`https://app.test/next?to=https://${OOB}/`, base, OOB)); // same-site, payload in query
  assert.ok(!locationTargetsHost("/dashboard", base, OOB)); // plain same-site
  assert.ok(!locationTargetsHost(undefined, base, OOB)); // no Location
});

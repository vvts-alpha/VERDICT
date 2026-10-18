import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { FetchHttpClient } from "./http.js";
import type { HttpRequest } from "./http.js";

const credentialNames = ["authorization", "cookie", "x-api-key"];
const defaultHeaders = {
  aUtHoRiZaTiOn: `Basic ${Buffer.from("synthetic-user:synthetic-password").toString("base64")}`,
  CoOkIe: "session=synthetic-baseline-session",
  "X-aPi-KeY": "synthetic-baseline-api-key",
  "X-Project": "synthetic-baseline-project",
};

interface ObservedRequest {
  headers: IncomingHttpHeaders;
  rawHeaders: string[];
}

async function startServer(t: TestContext): Promise<{ url: string; received: ObservedRequest[] }> {
  const received: ObservedRequest[] = [];
  const server = createServer((req, res) => {
    received.push({ headers: req.headers, rawHeaders: req.rawHeaders });
    res.setHeader("Connection", "close");
    res.end("ok");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  t.after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { url: `http://127.0.0.1:${address.port}/`, received };
}

function normalize(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
}

function assertEvidenceMatchesWire(client: FetchHttpClient, request: HttpRequest, observed: ObservedRequest): void {
  const evidence = normalize(client.effectiveHeaders(request.headers, request.inheritDefaultHeaders !== false));
  for (const [name, value] of Object.entries(evidence)) {
    assert.equal(observed.headers[name], value, `${name} evidence must match the network request`);
  }
  for (const name of credentialNames) {
    assert.equal(observed.headers[name], evidence[name], `${name} must also be absent when absent from evidence`);
    const count = observed.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === name).length;
    assert.equal(count, evidence[name] === undefined ? 0 : 1, `${name} must not be duplicated on the wire`);
  }
}

test("anonymous and alternate identities exclude all inherited authentication mechanisms on the wire", async (t) => {
  const { url, received } = await startServer(t);
  const client = new FetchHttpClient({ headers: defaultHeaders, userAgent: "verdict-auth-isolation-test" });
  const baseline: HttpRequest = { method: "GET", url };
  assert.equal((await client.send(baseline)).status, 200);
  assert.equal(received.length, 1);
  assertEvidenceMatchesWire(client, baseline, received[0]!);
  for (const name of credentialNames) assert.equal(received[0]!.headers[name], normalize(defaultHeaders)[name]);

  const anonymous: HttpRequest = { method: "GET", url, inheritDefaultHeaders: false };
  assert.equal((await client.send(anonymous)).status, 200);
  assertEvidenceMatchesWire(client, anonymous, received[1]!);
  for (const name of credentialNames) assert.equal(received[1]!.headers[name], undefined);
  assert.equal(received[1]!.headers["x-project"], undefined);
  assert.equal(received[1]!.headers["user-agent"], "verdict-auth-isolation-test");

  const alternateCredentials: Record<string, string>[] = [
    { AUTHORIZATION: "Bearer synthetic-role-token" },
    { cookie: "session=synthetic-role-session" },
    { "x-API-key": "synthetic-role-api-key" },
  ];
  for (const headers of alternateCredentials) {
    const request: HttpRequest = { method: "GET", url, inheritDefaultHeaders: false, headers };
    assert.equal((await client.send(request)).status, 200);
    const observed = received.at(-1)!;
    assertEvidenceMatchesWire(client, request, observed);
    const ownCredentials = normalize(headers);
    for (const name of credentialNames) assert.equal(observed.headers[name], ownCredentials[name]);
    assert.equal(observed.headers["x-project"], undefined);
  }
  assert.equal(received.length, 5);

  // Opting out for one replay must not mutate the client's baseline identity.
  await client.send(baseline);
  assertEvidenceMatchesWire(client, baseline, received[5]!);
  for (const name of credentialNames) assert.equal(received[5]!.headers[name], normalize(defaultHeaders)[name]);
});

test("credential overrides and evidence fold header names case-insensitively", async (t) => {
  const { url, received } = await startServer(t);
  const client = new FetchHttpClient({ headers: defaultHeaders, userAgent: "synthetic-default-agent" });
  const headers = {
    AUTHORIZATION: "Bearer synthetic-overridden-token",
    cookie: "session=synthetic-overridden-session",
    "x-api-key": "synthetic-overridden-key",
    "User-Agent": "synthetic-request-agent",
  };
  for (const inheritDefaultHeaders of [true, false]) {
    const request: HttpRequest = { method: "GET", url, headers, inheritDefaultHeaders };
    assert.equal((await client.send(request)).status, 200);
    const observed = received.at(-1)!;
    assertEvidenceMatchesWire(client, request, observed);
    for (const [name, value] of Object.entries(normalize(headers))) assert.equal(observed.headers[name], value);
    assert.equal(observed.headers["x-project"], inheritDefaultHeaders ? defaultHeaders["X-Project"] : undefined);
  }
  assert.equal(received.length, 2);
});

test("anonymous requests retain scope enforcement and the beforeSend budget gate", async (t) => {
  const { url, received } = await startServer(t);
  const reserved: HttpRequest[] = [];
  let attempts = 0;
  const client = new FetchHttpClient({
    headers: defaultHeaders,
    allow: (candidate) => candidate === url,
    beforeSend: (request) => {
      attempts++;
      if (reserved.length >= 2) throw new Error("synthetic request budget exhausted");
      reserved.push(request);
    },
  });
  const anonymous: HttpRequest = { method: "GET", url, inheritDefaultHeaders: false };
  await assert.rejects(client.send({ ...anonymous, url: `${url}outside-scope` }), /out-of-scope/);
  assert.equal(attempts, 0, "scope rejection must precede budget reservation");
  assert.equal(received.length, 0, "a disallowed local URL must never reach the server");

  await client.send(anonymous);
  await client.send({ ...anonymous, headers: { Authorization: "Bearer synthetic-budget-role" } });
  assert.equal(reserved.length, 2);
  assert.equal(received.length, 2);
  for (const [index, request] of reserved.entries()) {
    assert.equal(request.inheritDefaultHeaders, false);
    assertEvidenceMatchesWire(client, request, received[index]!);
  }

  await assert.rejects(client.send(anonymous), /synthetic request budget exhausted/);
  assert.equal(attempts, 3, "anonymous traffic must still pass through beforeSend");
  assert.equal(reserved.length, 2);
  assert.equal(received.length, 2, "budget rejection must occur before network transmission");
});

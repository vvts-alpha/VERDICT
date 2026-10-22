import test from "node:test";
import assert from "node:assert/strict";
import { mutationLedger, mutationEvents } from "./mutations.js";
import type { Mutation, StateEvent } from "./types/index.js";

function ev(seq: number, m: Mutation): StateEvent {
  return { seq, ts: `2026-01-01T00:00:0${seq}Z`, type: "mutation_recorded", payload: { mutation: m } };
}

const mut = (fields: Record<string, string>, over: Partial<Mutation> = {}): Mutation => ({
  screenId: "s-0001",
  role: "alice",
  action: "password-change",
  fields,
  method: "GET",
  url: "http://t/rest/user/change-password",
  status: 200,
  ...over,
});

test("ledger keeps only the latest value per (subject, field)", () => {
  const events: StateEvent[] = [
    ev(1, mut({ password: "Rp333!" })),
    ev(2, mut({ password: "Irrelevant123!" }, { action: "password-reset", url: "http://t/rest/user/reset-password", evidenceId: "ev-9" })),
    ev(3, mut({ answer: "VerdictTestAns1" }, { action: "register", subject: "alice@x.local" })),
  ];
  const rows = mutationLedger(events);
  assert.equal(rows.length, 2);
  const pw = rows.find((r) => r.field === "password")!;
  assert.equal(pw.value, "Irrelevant123!");
  assert.equal(pw.action, "password-reset");
  assert.equal(pw.evidenceId, "ev-9");
  assert.equal(pw.writes, 2);
  const ans = rows.find((r) => r.field === "answer")!;
  assert.equal(ans.subject, "alice@x.local");
});

test("subject falls back to role then sessionRef", () => {
  const events: StateEvent[] = [
    ev(1, mut({ password: "x" }, { role: null, sessionRef: "abc123" })),
  ];
  const rows = mutationLedger(events);
  assert.equal(rows[0]!.subject, "abc123");
});

test("mutationEvents preserves raw order", () => {
  const events: StateEvent[] = [ev(1, mut({ a: "1" })), ev(2, mut({ a: "2" }))];
  assert.equal(mutationEvents(events).length, 2);
});

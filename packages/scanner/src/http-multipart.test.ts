// Prove that FetchHttpClient's multipart send is **CRLF/boundary-correct** using a localhost echo server
// (regression guard for the issue where an LLM hand-writing it produces LF and gets rejected by python-multipart etc.). No external network.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { createServer } from "node:http";
import { FetchHttpClient } from "./http.js";

test("multipart upload is sent with correct boundary + CRLF (undici FormData)", async () => {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => {
      res.setHeader("x-req-content-type", req.headers["content-type"] ?? "");
      res.end(Buffer.concat(chunks).toString("latin1")); // echo the raw request body as-is
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;

  try {
    const http = new FetchHttpClient({ allow: () => true });
    const svg = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>';
    const res = await http.send({
      method: "POST",
      url: `http://127.0.0.1:${port}/upload`,
      multipart: {
        fields: { name: "amraam" },
        files: [{ name: "image", filename: "evil.svg", contentType: "image/svg+xml", base64: Buffer.from(svg, "utf8").toString("base64") }],
      },
    });
    // The Content-Type the server saw is multipart + boundary (set automatically by undici).
    assert.match(res.headers["x-req-content-type"] ?? "", /^multipart\/form-data; boundary=/);
    // The raw body is CRLF-delimited (the crux — hand-writing this yields LF).
    assert.ok(res.body.includes("\r\n"), "multipart parts must be CRLF-delimited");
    assert.ok(!/[^\r]\n/.test(res.body), "no bare LF between multipart lines");
    // The file part's headers + content + the field are all present.
    assert.match(res.body, /Content-Disposition: form-data; name="image"; filename="evil\.svg"/);
    assert.match(res.body, /Content-Type: image\/svg\+xml/);
    assert.ok(res.body.includes("file:///etc/passwd"), "the XXE payload body is present");
    assert.match(res.body, /Content-Disposition: form-data; name="name"\r\n\r\namraam/); // field name=value
  } finally {
    server.close();
  }
});

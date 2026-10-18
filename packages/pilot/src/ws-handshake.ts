// Minimal real WebSocket Upgrade handshake over a raw socket (net/tls). Needed because the browser/undici
// WebSocket API cannot set Origin/Cookie freely — CSWSH and unauthenticated-connect checks REQUIRE control
// of those headers. Implements just enough RFC6455: the HTTP/1.1 Upgrade exchange + one masked client frame
// + one decoded server frame. Not a general WS client.

import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { randomBytes } from "node:crypto";

export interface WsHandshakeRequest {
  url: string;
  /** Caller-controlled headers — Origin/Cookie/Sec-WebSocket-Protocol belong here. */
  headers: Record<string, string>;
  /** Optional single text frame to send after a 101 accept. */
  message?: string;
  /** How long to wait for a server-initiated frame after connect (default 1200ms). */
  timeoutMs?: number;
}

export interface WsHandshakeResult {
  /** HTTP status of the Upgrade response (101 = socket accepted). 0 on transport failure. */
  status: number;
  headers: Record<string, string>;
  /** First decoded server frame, if one arrived within the window. */
  firstFrame?: { opcode: number; payloadPreview: string } | null;
  /** The request head we sent (for evidence). */
  requestHead: string;
  /** The response head we received. */
  responseHead: string;
  error?: string;
}

/** Encode a client→server text frame (RFC6455: client frames MUST be masked). */
export function encodeClientFrame(payload: string): Buffer {
  const data = Buffer.from(payload, "utf8");
  const mask = randomBytes(4);
  const len = data.length;
  let head: Buffer;
  if (len < 126) {
    head = Buffer.from([0x81, 0x80 | len]);
  } else if (len < 65536) {
    head = Buffer.alloc(4);
    head[0] = 0x81;
    head[1] = 0x80 | 126;
    head.writeUInt16BE(len, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x81;
    head[1] = 0x80 | 127;
    head.writeBigUInt64BE(BigInt(len), 2);
  }
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = data[i]! ^ mask[i % 4]!;
  return Buffer.concat([head, mask, masked]);
}

/** Decode one server→client frame from the head of `buf` (server frames are unmasked).
 *  Returns null when the buffer doesn't yet hold a complete frame. */
export function decodeServerFrame(buf: Buffer): { opcode: number; payload: Buffer; rest: Buffer } | null {
  if (buf.length < 2) return null;
  const opcode = buf[0]! & 0x0f;
  const masked = (buf[1]! & 0x80) !== 0;
  let len = buf[1]! & 0x7f;
  let off = 2;
  if (len === 126) {
    if (buf.length < off + 2) return null;
    len = buf.readUInt16BE(off);
    off += 2;
  } else if (len === 127) {
    if (buf.length < off + 8) return null;
    len = Number(buf.readBigUInt64BE(off));
    off += 8;
  }
  if (masked) {
    if (buf.length < off + 4) return null;
    off += 4;
  }
  if (buf.length < off + len) return null;
  const payload = buf.subarray(off, off + len);
  if (masked) {
    const key = buf.subarray(off - 4, off);
    const un = Buffer.alloc(len);
    for (let i = 0; i < len; i++) un[i] = payload[i]! ^ key[i % 4]!;
    return { opcode, payload: un, rest: buf.subarray(off + len) };
  }
  return { opcode, payload, rest: buf.subarray(off + len) };
}

/** Perform one real handshake + optional first-frame read. Never throws — errors come back in-band. */
export async function wsHandshake(req: WsHandshakeRequest): Promise<WsHandshakeResult> {
  const timeoutMs = req.timeoutMs ?? 1200;
  let u: URL;
  try {
    u = new URL(req.url);
  } catch {
    return { status: 0, headers: {}, requestHead: "", responseHead: "", error: `bad ws url: ${req.url}` };
  }
  const secure = u.protocol === "wss:";
  const host = u.hostname;
  const port = Number(u.port) || (secure ? 443 : 80);
  const path = `${u.pathname || "/"}${u.search}`;
  const key = randomBytes(16).toString("base64");
  const head =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${u.host}\r\n` +
    `Upgrade: websocket\r\n` +
    `Connection: Upgrade\r\n` +
    `Sec-WebSocket-Key: ${key}\r\n` +
    `Sec-WebSocket-Version: 13\r\n` +
    Object.entries(req.headers)
      .map(([k, v]) => `${k}: ${v}\r\n`)
      .join("") +
    `\r\n`;

  return await new Promise<WsHandshakeResult>((resolve) => {
    const done = (r: WsHandshakeResult, sock?: { destroy(): void }) => {
      try {
        sock?.destroy();
      } catch {
        /* ignore */
      }
      resolve(r);
    };
    const sock = secure
      ? tlsConnect({ host, port, servername: host, rejectUnauthorized: true })
      : netConnect({ host, port });
    let buf = Buffer.alloc(0);
    let timer: NodeJS.Timeout | null = setTimeout(() => {
      timer = null;
      const headEnd = buf.indexOf("\r\n\r\n");
      done(
        {
          status: headEnd >= 0 ? Number((buf.subarray(0, buf.indexOf("\r\n")).toString("latin1").match(/HTTP\/1\.1 (\d+)/)?.[1] ?? 0)) : 0,
          headers: {},
          requestHead: head,
          responseHead: headEnd >= 0 ? buf.subarray(0, headEnd + 4).toString("latin1") : buf.toString("latin1").slice(0, 400),
          error: "timeout waiting for handshake/frame",
        },
        sock,
      );
    }, timeoutMs + 4000);

    sock.on("error", (e) => {
      if (timer) clearTimeout(timer);
      done({ status: 0, headers: {}, requestHead: head, responseHead: "", error: String(e).slice(0, 200) }, sock);
    });
    sock.on("connect", () => sock.write(head));
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const headEnd = buf.indexOf("\r\n\r\n");
      if (headEnd < 0) return;
      const responseHead = buf.subarray(0, headEnd + 4).toString("latin1");
      const statusLine = buf.subarray(0, buf.indexOf("\r\n")).toString("latin1");
      const status = Number(statusLine.match(/HTTP\/1\.1 (\d+)/)?.[1] ?? 0);
      const headers: Record<string, string> = {};
      for (const line of responseHead.split("\r\n").slice(1)) {
        const i = line.indexOf(":");
        if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      if (status !== 101) {
        if (timer) clearTimeout(timer);
        done({ status, headers, requestHead: head, responseHead }, sock);
        return;
      }
      // 101 — optionally send one frame, then wait for a server frame within the window.
      if (req.message) {
        try {
          sock.write(encodeClientFrame(req.message));
        } catch {
          /* ignore */
        }
      }
      const frameWait = Math.min(req.timeoutMs ?? 1200, 3000);
      const frameTimer = setTimeout(() => {
        if (timer) clearTimeout(timer);
        done({ status: 101, headers, requestHead: head, responseHead, firstFrame: null }, sock);
      }, frameWait);
      const tryFrame = () => {
        const fr = decodeServerFrame(buf.subarray(headEnd + 4));
        if (!fr) return false;
        clearTimeout(frameTimer);
        if (timer) clearTimeout(timer);
        done(
          {
            status: 101,
            headers,
            requestHead: head,
            responseHead,
            firstFrame: { opcode: fr.opcode, payloadPreview: fr.payload.toString("utf8", 0, Math.min(fr.payload.length, 120)) },
          },
          sock,
        );
        return true;
      };
      if (tryFrame()) return;
      sock.once("data", (chunk2: Buffer) => {
        buf = Buffer.concat([buf, chunk2]);
        if (tryFrame()) return;
        clearTimeout(frameTimer);
        if (timer) clearTimeout(timer);
        done({ status: 101, headers, requestHead: head, responseHead, firstFrame: null }, sock);
      });
    });
  });
}

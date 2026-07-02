package com.amraam.burpaudit;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 依存ゼロの最小 HTTP/1.1 サーバ(java.net.ServerSocket のみ。connection-close per request)。
 * Burp の拡張クラスローダは com.sun.net.httpserver(jdk.httpserver モジュール)を解決できないため、
 * java.base だけで動くこれを使う。VERDICT(行儀の良いクライアント)向けの小さな API 用。
 */
public final class MicroHttpServer {

    public interface Handler {
        void handle(Request req, Response resp) throws IOException;
    }

    public static final class Request {
        public final String method;
        public final String path;
        public final String rawQuery; // null 可
        private final Map<String, String> headers; // 小文字キー
        public final byte[] body;

        Request(String method, String path, String rawQuery, Map<String, String> headers, byte[] body) {
            this.method = method;
            this.path = path;
            this.rawQuery = rawQuery;
            this.headers = headers;
            this.body = body;
        }

        public String header(String name) {
            return headers.get(name.toLowerCase());
        }

        public String bodyString() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    public static final class Response {
        private final OutputStream out;
        private boolean sent = false;

        Response(OutputStream out) {
            this.out = out;
        }

        public void send(int code, String contentType, byte[] body) throws IOException {
            if (sent) return;
            sent = true;
            String head = "HTTP/1.1 " + code + " " + reason(code) + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n\r\n";
            out.write(head.getBytes(StandardCharsets.ISO_8859_1));
            out.write(body);
            out.flush();
        }
    }

    private final String host;
    private final int port;
    private final Handler handler;
    private final ExecutorService pool = Executors.newFixedThreadPool(8);
    private ServerSocket socket;
    private volatile boolean running;

    public MicroHttpServer(String host, int port, Handler handler) {
        this.host = host;
        this.port = port;
        this.handler = handler;
    }

    public void start() throws IOException {
        socket = new ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(host, port));
        running = true;
        Thread t = new Thread(this::acceptLoop, "verdict-audit-http");
        t.setDaemon(true);
        t.start();
    }

    public void stop() {
        running = false;
        try { if (socket != null) socket.close(); } catch (IOException ignored) { /* closing */ }
        pool.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket c = socket.accept();
                pool.submit(() -> handle(c));
            } catch (IOException e) {
                if (!running) break; // stop() による close
            }
        }
    }

    private void handle(Socket conn) {
        try (Socket s = conn) {
            s.setSoTimeout(20000);
            InputStream in = new BufferedInputStream(s.getInputStream());

            // ヘッダ終端(\r\n\r\n)までバイト読み(body を読み過ぎない)。
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            byte[] term = {'\r', '\n', '\r', '\n'};
            int matched = 0;
            int cur;
            while ((cur = in.read()) != -1) {
                head.write(cur);
                if (cur == term[matched]) matched++;
                else matched = (cur == term[0]) ? 1 : 0;
                if (matched == 4) break;
                if (head.size() > 64 * 1024) break; // ヘッダ肥大化ガード
            }
            String headStr = new String(head.toByteArray(), StandardCharsets.ISO_8859_1);
            String[] lines = headStr.split("\r\n");
            if (lines.length == 0 || lines[0].isEmpty()) return;

            String[] rl = lines[0].split(" ");
            if (rl.length < 2) return;
            String method = rl[0];
            String target = rl[1];
            String path = target;
            String rawQuery = null;
            int qi = target.indexOf('?');
            if (qi >= 0) {
                path = target.substring(0, qi);
                rawQuery = target.substring(qi + 1);
            }

            Map<String, String> headers = new HashMap<>();
            int contentLength = 0;
            for (int i = 1; i < lines.length; i++) {
                String ln = lines[i];
                if (ln.isEmpty()) continue;
                int ci = ln.indexOf(':');
                if (ci < 0) continue;
                String k = ln.substring(0, ci).trim().toLowerCase();
                String v = ln.substring(ci + 1).trim();
                headers.put(k, v);
                if (k.equals("content-length")) {
                    try { contentLength = Integer.parseInt(v); } catch (NumberFormatException ignored) { /* keep 0 */ }
                }
            }

            byte[] body = new byte[0];
            if (contentLength > 0) {
                body = new byte[contentLength];
                int off = 0;
                int r;
                while (off < contentLength && (r = in.read(body, off, contentLength - off)) != -1) off += r;
            }

            Request req = new Request(method, path, rawQuery, headers, body);
            Response resp = new Response(s.getOutputStream());
            try {
                handler.handle(req, resp);
            } catch (Exception e) {
                try {
                    String msg = String.valueOf(e.getMessage()).replace("\"", "'");
                    resp.send(400, "application/json", ("{\"error\":\"" + msg + "\"}").getBytes(StandardCharsets.UTF_8));
                } catch (IOException ignored) { /* socket gone */ }
            }
        } catch (IOException ignored) {
            /* per-connection failure is non-fatal */
        }
    }

    private static String reason(int code) {
        switch (code) {
            case 200: return "OK";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 500: return "Internal Server Error";
            default: return "OK";
        }
    }
}

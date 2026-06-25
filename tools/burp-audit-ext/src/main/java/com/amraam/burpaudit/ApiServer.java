package com.amraam.burpaudit;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ReportFormat;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** REST API のルーティング(依存ゼロの MicroHttpServer + Gson)。 */
public final class ApiServer {

    private final MontoyaApi api;
    private final IssueStore store;
    private final AuditRegistry registry;
    private final OobManager oob;
    private final String host;
    private final int port;
    private final String token; // null = 認証なし
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private MicroHttpServer server;

    public ApiServer(MontoyaApi api, IssueStore store, AuditRegistry registry, OobManager oob, String host, int port, String token) {
        this.api = api;
        this.store = store;
        this.registry = registry;
        this.oob = oob;
        this.host = host;
        this.port = port;
        this.token = token;
    }

    public void start() throws IOException {
        // host = 127.0.0.1(既定)or 0.0.0.0(別マシンの AMRAAM から到達させる場合。AUTH_TOKEN 併用推奨)。
        server = new MicroHttpServer(host, port, this::dispatch);
        server.start();
    }

    public void stop() {
        if (server != null) server.stop();
    }

    private void dispatch(MicroHttpServer.Request req, MicroHttpServer.Response resp) throws IOException {
        if (token != null && !token.equals(req.header("X-Scan-Token"))) {
            sendError(resp, 401, "invalid or missing X-Scan-Token");
            return;
        }
        String method = req.method;
        String path = req.path;
        Map<String, String> q = queryParams(req.rawQuery);

        if (path.equals("/scan")) {
            if (!method.equals("POST")) { sendError(resp, 405, "POST only"); return; }
            handleScan(req, resp);
        } else if (path.equals("/status")) {
            handleStatusAll(resp);
        } else if (path.startsWith("/status/")) {
            handleStatusOne(resp, urlDecode(path.substring("/status/".length())));
        } else if (path.equals("/issues")) {
            handleIssues(resp, q);
        } else if (path.equals("/report")) {
            handleReport(resp, q);
        } else if (path.equals("/reset")) {
            if (!method.equals("POST")) { sendError(resp, 405, "POST only"); return; }
            store.clear();
            registry.clear(); // 既存 Audit も破棄 → 次の run は新規 Audit で再スキャンできる
            if (oob != null) oob.clear();
            JsonObject o = new JsonObject();
            o.addProperty("status", "cleared");
            sendJson(resp, 200, o);
        } else if (path.equals("/oob/payload")) {
            if (!method.equals("POST")) { sendError(resp, 405, "POST only"); return; }
            handleOobPayload(resp);
        } else if (path.equals("/oob/interactions")) {
            handleOobInteractions(resp, q);
        } else if (path.equals("/oob/status")) {
            handleOobStatus(resp);
        } else if (path.equals("/openapi.yaml") || path.equals("/openapi.yml")) {
            serveResource(resp, "/burp-audit-api.openapi.yaml", "application/yaml; charset=utf-8");
        } else if (path.equals("/docs") || path.equals("/")) {
            resp.send(200, "text/html; charset=utf-8", SWAGGER_HTML.getBytes(StandardCharsets.UTF_8));
        } else {
            sendError(resp, 404, "no such endpoint (try /docs , /openapi.yaml)");
        }
    }

    // ── POST /scan ──
    private void handleScan(MicroHttpServer.Request req, MicroHttpServer.Response resp) throws IOException {
        JsonObject body;
        try {
            body = JsonParser.parseString(req.bodyString()).getAsJsonObject();
        } catch (Exception e) {
            sendError(resp, 400, "invalid JSON body");
            return;
        }
        if (!body.has("host") || !body.has("port") || !body.has("request")) {
            sendError(resp, 400, "host, port and request are required");
            return;
        }
        String h = body.get("host").getAsString();
        int p = body.get("port").getAsInt();
        boolean secure = body.has("secure") && body.get("secure").getAsBoolean();
        String mode = body.has("audit_mode") ? body.get("audit_mode").getAsString() : "active";
        String raw = body.get("request").getAsString();

        String key;
        try {
            key = registry.submit(h, p, secure, mode, raw);
        } catch (Exception e) {
            sendError(resp, 400, "could not submit request: " + e.getMessage());
            return;
        }
        JsonObject out = new JsonObject();
        out.addProperty("status", "queued");
        out.addProperty("host", key);
        out.addProperty("audit_mode", "passive".equalsIgnoreCase(mode) ? "passive" : "active");
        sendJson(resp, 200, out);
    }

    // ── GET /status/{host} ──
    private void handleStatusOne(MicroHttpServer.Response resp, String hostKey) throws IOException {
        Audit audit = registry.get(hostKey);
        if (audit == null) { sendError(resp, 404, "no audit for " + hostKey); return; }
        sendJson(resp, 200, statusObj(hostKey, audit, true));
    }

    // ── GET /status ──
    private void handleStatusAll(MicroHttpServer.Response resp) throws IOException {
        JsonArray hosts = new JsonArray();
        for (Map.Entry<String, Audit> e : registry.all().entrySet()) {
            hosts.add(statusObj(e.getKey(), e.getValue(), false));
        }
        JsonObject out = new JsonObject();
        out.add("hosts", hosts);
        sendJson(resp, 200, out);
    }

    private JsonObject statusObj(String key, Audit audit, boolean full) {
        JsonObject o = new JsonObject();
        o.addProperty("host", key);
        o.addProperty("audit_mode", registry.mode(key));
        o.addProperty("status", safe(audit::statusMessage));
        o.addProperty("requests_made", audit.requestCount());
        o.addProperty("errors", audit.errorCount());
        if (full) o.addProperty("insertion_points", audit.insertionPointCount());
        return o;
    }

    // ── GET /issues ──
    private void handleIssues(MicroHttpServer.Response resp, Map<String, String> q) throws IOException {
        Long since = q.containsKey("since") ? Long.valueOf(q.get("since")) : null;
        String host = q.get("host");
        boolean evidence = "true".equalsIgnoreCase(q.getOrDefault("evidence", "false"));
        JsonArray arr = new JsonArray();
        for (IssueStore.Entry e : store.query(since, host)) arr.add(issueJson(e, evidence));
        JsonObject out = new JsonObject();
        out.add("issues", arr);
        sendJson(resp, 200, out);
    }

    private JsonObject issueJson(IssueStore.Entry e, boolean evidence) {
        AuditIssue iss = e.issue;
        JsonObject o = new JsonObject();
        o.addProperty("found_at", e.foundAt);
        o.addProperty("name", iss.name());
        o.addProperty("severity", iss.severity().name());
        o.addProperty("confidence", iss.confidence().name());
        o.addProperty("url", iss.baseUrl());
        String detail = iss.detail();
        if (detail != null) o.addProperty("detail", detail);
        if (evidence) {
            JsonArray ev = new JsonArray();
            for (HttpRequestResponse rr : iss.requestResponses()) {
                JsonObject one = new JsonObject();
                if (rr.request() != null) one.addProperty("request_b64", b64(rr.request().toByteArray().getBytes()));
                if (rr.response() != null) one.addProperty("response_b64", b64(rr.response().toByteArray().getBytes()));
                ev.add(one);
            }
            o.add("evidence", ev);
        }
        return o;
    }

    // ── GET /report ──
    private void handleReport(MicroHttpServer.Response resp, Map<String, String> q) throws IOException {
        Long since = q.containsKey("since") ? Long.valueOf(q.get("since")) : null;
        String host = q.get("host");
        boolean html = "html".equalsIgnoreCase(q.getOrDefault("format", "xml"));
        List<AuditIssue> issues = new ArrayList<>();
        for (IssueStore.Entry e : store.query(since, host)) issues.add(e.issue);

        Path tmp = Files.createTempFile("amraam-burp-report", html ? ".html" : ".xml");
        try {
            api.scanner().generateReport(issues, html ? ReportFormat.HTML : ReportFormat.XML, tmp);
            byte[] bytes = Files.readAllBytes(tmp);
            resp.send(200, html ? "text/html" : "application/xml", bytes);
        } finally {
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) { /* best effort */ }
        }
    }

    // ── OOB(Burp Collaborator)── AMRAAM がブラインド SSRF/XXE/SQLi 等の確証に使う。
    // POST /oob/payload → 一意ドメイン発行 / GET /oob/interactions?since=&id= → コールバック回収。
    private void handleOobPayload(MicroHttpServer.Response resp) throws IOException {
        if (oob == null || !oob.available()) {
            sendError(resp, 503, "Collaborator unavailable" + (oob != null && !oob.error().isEmpty() ? ": " + oob.error() : " (enable it in Burp project settings)"));
            return;
        }
        String[] p;
        try {
            p = oob.generate();
        } catch (Exception e) {
            // 一時障害(無効化/接続不能等)→ クライアントエラー(400)ではなく 503 を返す。
            sendError(resp, 503, "Collaborator payload generation failed: " + e.getMessage());
            return;
        }
        JsonObject o = new JsonObject();
        o.addProperty("host", p[0]); // 注入用の完全なドメイン
        o.addProperty("id", p[1]); // interaction.id と一致する相関キー
        sendJson(resp, 200, o);
    }

    private void handleOobInteractions(MicroHttpServer.Response resp, Map<String, String> q) throws IOException {
        if (oob == null || !oob.available()) { sendError(resp, 503, "Collaborator unavailable"); return; }
        Long since = q.containsKey("since") ? Long.valueOf(q.get("since")) : null;
        String idFilter = q.get("id");
        JsonArray arr = new JsonArray();
        for (Interaction i : oob.poll()) {
            long ts = i.timeStamp().toInstant().toEpochMilli();
            if (since != null && ts < since) continue;
            String iid = i.id().toString();
            if (idFilter != null && !idFilter.equals(iid)) continue;
            JsonObject o = new JsonObject();
            o.addProperty("id", iid);
            o.addProperty("type", i.type().name()); // DNS / HTTP / SMTP
            o.addProperty("time", ts);
            try {
                o.addProperty("client_ip", i.clientIp().getHostAddress());
            } catch (Exception ignored) {
                /* best-effort */
            }
            arr.add(o);
        }
        JsonObject out = new JsonObject();
        out.add("interactions", arr);
        sendJson(resp, 200, out);
    }

    private void handleOobStatus(MicroHttpServer.Response resp) throws IOException {
        JsonObject o = new JsonObject();
        boolean ok = oob != null && oob.available();
        o.addProperty("available", ok);
        o.addProperty("server", oob != null ? oob.server() : "");
        if (!ok && oob != null && !oob.error().isEmpty()) o.addProperty("error", oob.error());
        sendJson(resp, 200, o);
    }

    // バンドルした OpenAPI を Swagger UI(CDN)で描画。オフラインでも /openapi.yaml は生で取れる。
    private static final String SWAGGER_HTML =
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>AMRAAM Audit REST</title>"
        + "<link rel=\"stylesheet\" href=\"https://unpkg.com/swagger-ui-dist/swagger-ui.css\"></head>"
        + "<body><div id=\"swagger-ui\"></div>"
        + "<script src=\"https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js\"></script>"
        + "<script>window.onload=function(){SwaggerUIBundle({url:'openapi.yaml',dom_id:'#swagger-ui'});};</script>"
        + "</body></html>";

    private void serveResource(MicroHttpServer.Response resp, String name, String contentType) throws IOException {
        try (InputStream in = getClass().getResourceAsStream(name)) {
            if (in == null) { sendError(resp, 404, "resource not bundled: " + name); return; }
            resp.send(200, contentType, in.readAllBytes());
        }
    }

    // ── helpers ──
    private interface SafeStr { String get(); }

    private static String safe(SafeStr s) {
        try { String v = s.get(); return v == null ? "" : v; } catch (Exception e) { return ""; }
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private static String urlDecode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static Map<String, String> queryParams(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null) return m;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            int i = pair.indexOf('=');
            if (i < 0) m.put(urlDecode(pair), "");
            else m.put(urlDecode(pair.substring(0, i)), urlDecode(pair.substring(i + 1)));
        }
        return m;
    }

    private void sendJson(MicroHttpServer.Response resp, int code, Object obj) throws IOException {
        resp.send(code, "application/json", gson.toJson(obj).getBytes(StandardCharsets.UTF_8));
    }

    private void sendError(MicroHttpServer.Response resp, int code, String msg) throws IOException {
        JsonObject o = new JsonObject();
        o.addProperty("error", msg == null ? "error" : msg);
        sendJson(resp, code, o);
    }
}

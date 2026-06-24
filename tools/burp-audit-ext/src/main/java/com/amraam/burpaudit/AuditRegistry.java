package com.amraam.burpaudit;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * host:port ごとに 1 つの Audit を束ねる。最初の POST /scan で Audit を起動し、以降の同一 host:port は
 * 既存 Audit へ addRequest で集約する(GUI の「Audit selected items」を同一ホストにまとめるのと同じ)。
 */
public final class AuditRegistry {

    private final MontoyaApi api;
    private final Map<String, Audit> audits = new ConcurrentHashMap<>();
    private final Map<String, String> modes = new ConcurrentHashMap<>();

    public AuditRegistry(MontoyaApi api) {
        this.api = api;
    }

    /** 生リクエストを host:port の Audit へ投入。Audit キー(host:port)を返す。 */
    public synchronized String submit(String host, int port, boolean secure, String mode, String rawRequest) {
        String key = host + ":" + port;
        Audit audit = audits.get(key);
        if (audit == null) {
            boolean passive = "passive".equalsIgnoreCase(mode);
            BuiltInAuditConfiguration cfg = passive
                ? BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                : BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS;
            audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(cfg));
            audits.put(key, audit);
            modes.put(key, passive ? "passive" : "active");
        }
        HttpService service = HttpService.httpService(host, port, secure);
        // 生 HTTP をバイト保持(URL エンコード済み body 等のバイトを壊さないよう ISO-8859-1)。
        HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(rawRequest.getBytes(StandardCharsets.ISO_8859_1)));
        audit.addRequest(request);
        return key;
    }

    public Audit get(String hostKey) {
        return audits.get(hostKey);
    }

    public String mode(String hostKey) {
        return modes.getOrDefault(hostKey, "active");
    }

    public Map<String, Audit> all() {
        return audits;
    }

    /** 既存の Audit を全て破棄してレジストリを空に(/reset 用)。次の run が host:port ごとに新規 Audit で
     *  再スキャンできるようにする(finished な Audit に addRequest しても再走しないため)。 */
    public synchronized void clear() {
        for (Audit a : audits.values()) {
            try {
                a.delete();
            } catch (Exception ignored) {
                /* already gone */
            }
        }
        audits.clear();
        modes.clear();
    }
}

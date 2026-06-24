package com.amraam.burpaudit;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.io.IOException;
import java.nio.file.Path;

/**
 * AMRAAM Audit REST — Montoya 拡張のエントリ。
 * - Scanner の AuditIssueHandler を登録して、検出 issue を発生時刻 + req/resp つきで蓄積する。
 * - 設定(host/port/token)は jar 隣の amraam-audit.properties から読む(初回に雛形を自動生成)。
 * - REST API(POST /scan, GET /status, /issues, /report, /docs, /openapi.yaml, POST /reset)を立てる。
 */
public class AuditExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AMRAAM Audit REST");

        IssueStore store = new IssueStore();
        api.scanner().registerAuditIssueHandler(new AuditIssueHandler() {
            @Override
            public void handleNewAuditIssue(AuditIssue auditIssue) {
                store.add(auditIssue);
            }
        });

        // 設定ファイルが無ければ jar の隣に雛形を生成(編集→Reload してもらう導線)。
        Path written = Config.writeTemplateIfMissing(AuditExtension.class);
        Config cfg = Config.load(AuditExtension.class);
        api.logging().logToOutput("config: " + cfg.source);
        if (written != null) {
            api.logging().logToOutput("created settings template → " + written + " (edit host/token there, then Reload the extension)");
        }
        if ("0.0.0.0".equals(cfg.host) && cfg.token == null) {
            api.logging().logToOutput("⚠ binding 0.0.0.0 WITHOUT a token — anyone on the network can submit scans. Set token= in " + cfg.source);
        }

        AuditRegistry registry = new AuditRegistry(api);
        try {
            ApiServer server = new ApiServer(api, store, registry, cfg.host, cfg.port, cfg.token);
            server.start();
            api.logging().logToOutput(
                "AMRAAM Audit REST listening on http://" + cfg.host + ":" + cfg.port
                + (cfg.token != null ? " (X-Scan-Token required)" : " (no auth)")
                + "  — docs: /docs , spec: /openapi.yaml");
            api.extension().registerUnloadingHandler(server::stop);
        } catch (IOException e) {
            api.logging().logToError("Failed to start API server on " + cfg.host + ":" + cfg.port + ": " + e.getMessage());
        }
    }
}

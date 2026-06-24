package com.amraam.burpaudit;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

/**
 * 拡張の設定(host / port / token)。Windows の GUI Burp には env が伝わりにくいので、
 * **jar の隣の amraam-audit.properties** を主軸にする(初回に雛形を自動生成)。
 * 優先順位: 設定ファイル > 環境変数(SCAN_API_HOST/SCAN_API_PORT/AUTH_TOKEN)> 既定。
 */
public final class Config {

    public final String host;
    public final int port;
    public final String token; // null = 認証なし
    public final String source; // どこから読んだか(ログ表示用)

    private Config(String host, int port, String token, String source) {
        this.host = host;
        this.port = port;
        this.token = token;
        this.source = source;
    }

    public static Config load(Class<?> anchor) {
        Properties p = new Properties();
        Path used = null;
        for (Path cand : candidates(anchor)) {
            if (cand != null && Files.isRegularFile(cand)) {
                try (InputStream in = Files.newInputStream(cand)) {
                    p.load(in);
                    used = cand;
                    break;
                } catch (IOException ignored) { /* try next */ }
            }
        }
        String host = firstNonBlank(p.getProperty("host"), System.getenv("SCAN_API_HOST"), "127.0.0.1").trim();
        int port = parseInt(firstNonBlank(p.getProperty("port"), System.getenv("SCAN_API_PORT"), null), 1338);
        String token = trimToNull(firstNonBlank(p.getProperty("token"), System.getenv("AUTH_TOKEN"), null));
        return new Config(host, port, token, used != null ? used.toString() : "(defaults/env)");
    }

    /** 設定ファイルが無ければ **ユーザホーム**に雛形を書く(編集→reload してもらうため)。書けた path を返す。
     *  ※ Burp は jar を temp にコピーしてロードするので「jar の隣」は不安定 → ホームを正準にする。 */
    public static Path writeTemplateIfMissing(Class<?> anchor) {
        Path home = pathOrNull(System.getProperty("user.home"));
        if (home == null) return null;
        Path file = home.resolve(".amraam-audit.properties");
        // 既にどこかに設定があるなら雛形は書かない。
        if (Files.exists(file)) return null;
        for (Path cand : candidates(anchor)) {
            if (cand != null && Files.isRegularFile(cand)) return null;
        }
        String tpl = ""
            + "# AMRAAM Audit REST 設定。編集したら Burp で拡張を Reload。\n"
            + "# bind 先。別マシンの AMRAAM から叩くなら 0.0.0.0(token 必須)。\n"
            + "host=127.0.0.1\n"
            + "# listen ポート。\n"
            + "port=1338\n"
            + "# X-Scan-Token。0.0.0.0 で公開する時は必ず設定。空なら認証なし。\n"
            + "token=\n";
        try {
            Files.write(file, tpl.getBytes(StandardCharsets.UTF_8));
            return file;
        } catch (IOException e) {
            return null;
        }
    }

    private static Path[] candidates(Class<?> anchor) {
        // 優先順: 明示 env パス > ユーザホーム(Burp の temp コピーに左右されない正準) > jar の隣(保険)。
        Path envPath = pathOrNull(System.getenv("AMRAAM_AUDIT_CONFIG"));
        Path home = pathOrNull(System.getProperty("user.home"));
        Path homeCfg = home != null ? home.resolve(".amraam-audit.properties") : null;
        Path jarSide = jarDir(anchor) != null ? jarDir(anchor).resolve("amraam-audit.properties") : null;
        return new Path[] { envPath, homeCfg, jarSide };
    }

    static Path jarDir(Class<?> c) {
        try {
            URI uri = c.getProtectionDomain().getCodeSource().getLocation().toURI();
            Path p = Paths.get(uri);
            return Files.isDirectory(p) ? p : p.getParent();
        } catch (Exception e) {
            return null;
        }
    }

    private static Path pathOrNull(String s) {
        String t = trimToNull(s);
        return t == null ? null : Paths.get(t);
    }

    private static String firstNonBlank(String... vals) {
        for (String v : vals) {
            if (v != null && !v.trim().isEmpty()) return v;
        }
        return "";
    }

    private static int parseInt(String s, int def) {
        try { return (s == null || s.isBlank()) ? def : Integer.parseInt(s.trim()); }
        catch (NumberFormatException e) { return def; }
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}

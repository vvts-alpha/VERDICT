package com.amraam.burpaudit;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.Interaction;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Burp Collaborator を使った OOB(out-of-band)相互作用の薄いラッパ。
 * - generate(): 一意ペイロード(ドメイン)を発行。VERDICT が標的の注入点(SSRF url / XXE SYSTEM /
 *   blind-SQLi の DNS exfil / メール / X-Forwarded-Host 等)に埋める。
 * - poll():     Collaborator サーバから interaction(DNS/HTTP/SMTP)を回収して **自前で蓄積**し、全件返す
 *   (getAllInteractions が「新着のみ」を返す実装に備える)。VERDICT 側で since/id で絞る。
 * Collaborator が無効/利用不可(プロジェクト設定で off 等)なら available()=false。
 */
public final class OobManager {

    private final MontoyaApi api;
    private volatile CollaboratorClient client; // null = 利用不可(構築時に1回だけ設定)
    private String error = "";
    // 重複排除キー(id|epochMs|type)→ interaction。getAllInteractions の重複/差分どちらでも正しく溜まる。
    private final Map<String, Interaction> seen = new LinkedHashMap<>();

    public OobManager(MontoyaApi api) {
        this.api = api;
        try {
            this.client = api.collaborator().createClient();
        } catch (Exception e) {
            this.error = String.valueOf(e.getMessage());
            api.logging().logToError("Collaborator unavailable: " + this.error);
        }
    }

    public boolean available() {
        return client != null;
    }

    public String error() {
        return error;
    }

    public String server() {
        try {
            return client != null ? client.server().address() : "";
        } catch (Exception e) {
            return "";
        }
    }

    /** 一意ペイロードを発行。返り値 [0]=完全なドメイン(注入用), [1]=id(interaction.id と一致する相関キー)。
     *  Collaborator 無効/一時障害なら IllegalStateException(呼び出し側 ApiServer が 503 にする)。 */
    public synchronized String[] generate() {
        if (client == null) throw new IllegalStateException("Collaborator unavailable");
        CollaboratorPayload p = client.generatePayload();
        return new String[] { p.toString(), p.id().toString() };
    }

    /** Collaborator を1回ポーリングして新着を蓄積し、これまでの全 interaction を返す(絞り込みは呼び出し側)。
     *  ネットワーク I/O(getAllInteractions)は **ロック外** で行い、generate()/clear() を塞がない。 */
    public List<Interaction> poll() {
        CollaboratorClient c = this.client; // 一度ローカルに(構築後は不変)
        if (c == null) return new ArrayList<>();
        List<Interaction> fresh;
        try {
            fresh = c.getAllInteractions(); // ← ロックの外(Collaborator サーバへの I/O は遅いことがある)
        } catch (Exception e) {
            api.logging().logToError("Collaborator poll failed: " + e.getMessage());
            fresh = java.util.Collections.emptyList();
        }
        synchronized (this) {
            for (Interaction i : fresh) {
                String k = i.id().toString() + "|" + i.timeStamp().toInstant().toEpochMilli() + "|" + i.type().name();
                seen.putIfAbsent(k, i);
            }
            return new ArrayList<>(seen.values());
        }
    }

    /** 蓄積した interaction を破棄(/reset 用)。発行ペイロードは一意なので必須ではないが run 間を綺麗にする。 */
    public synchronized void clear() {
        seen.clear();
    }
}

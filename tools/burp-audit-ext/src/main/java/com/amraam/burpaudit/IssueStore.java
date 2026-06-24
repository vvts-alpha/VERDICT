package com.amraam.burpaudit;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * 捕捉した AuditIssue を発生時刻つきで蓄積する(スレッドセーフ)。
 * /issues・/report は since(epoch ms)/host(host:port)でこのストアから絞り込んで返す。
 */
public final class IssueStore {

    public static final class Entry {
        public final long foundAt;
        public final AuditIssue issue;
        Entry(long foundAt, AuditIssue issue) {
            this.foundAt = foundAt;
            this.issue = issue;
        }
    }

    private final List<Entry> entries = new ArrayList<>();

    public synchronized void add(AuditIssue issue) {
        entries.add(new Entry(System.currentTimeMillis(), issue));
    }

    /** since(これより後に捕捉)/ host(host:port 一致)で絞った Entry を返す。null は無条件。 */
    public synchronized List<Entry> query(Long since, String host) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : entries) {
            if (since != null && e.foundAt <= since) continue;
            if (host != null && !host.isEmpty() && !hostMatches(e.issue, host)) continue;
            out.add(e);
        }
        return out;
    }

    public synchronized void clear() {
        entries.clear();
    }

    private static boolean hostMatches(AuditIssue issue, String hostPort) {
        try {
            URI u = URI.create(issue.baseUrl());
            int port = u.getPort() != -1 ? u.getPort() : ("https".equalsIgnoreCase(u.getScheme()) ? 443 : 80);
            return (u.getHost() + ":" + port).equalsIgnoreCase(hostPort);
        } catch (Exception e) {
            return false;
        }
    }
}

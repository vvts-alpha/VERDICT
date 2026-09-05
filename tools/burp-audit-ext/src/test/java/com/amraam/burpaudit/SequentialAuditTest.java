package com.amraam.burpaudit;

import burp.api.montoya.scanner.audit.Audit;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Standalone regression test; no running Burp or network required. */
public final class SequentialAuditTest {
    private static Audit audit(AtomicReference<String> status, AtomicInteger deleted) {
        return (Audit) Proxy.newProxyInstance(Audit.class.getClassLoader(), new Class<?>[] { Audit.class }, (proxy, method, args) -> {
            switch (method.getName()) {
                case "statusMessage": return status.get();
                case "issues": return List.of();
                case "delete": deleted.incrementAndGet(); return null;
                case "requestCount": case "errorCount": case "insertionPointCount": return 0;
                default: return null;
            }
        });
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError();
    }

    private static void busy(Runnable operation) {
        try { operation.run(); throw new AssertionError("overlapping audit accepted"); }
        catch (AuditRegistry.BusyException expected) { }
    }

    public static void main(String[] args) throws Exception {
        AuditRegistry registry = new AuditRegistry(null);
        AtomicReference<String> status = new AtomicReference<>("auditing");
        AtomicInteger deleted = new AtomicInteger();
        AtomicInteger created = new AtomicInteger();
        Audit first = audit(status, deleted);
        String id = registry.submitSerial(() -> { created.incrementAndGet(); return first; }, a -> {});
        check(registry.getSerial(id) == first);
        for (String state : List.of("auditing", "paused", "failed", "unfinished", "unknown")) {
            status.set(state);
            busy(() -> registry.submitSerial(() -> { created.incrementAndGet(); return first; }, a -> {}));
            busy(() -> registry.submit("example.com", 443, true, "active", ""));
        }
        check(created.get() == 1);
        status.set("Finished.");
        Audit second = audit(new AtomicReference<>("auditing"), deleted);
        String id2 = registry.submitSerial(() -> second, a -> {});
        check(!id.equals(id2) && registry.getSerial(id2) == second && registry.getSerial(id) == first);
        check(deleted.get() == 0);
        registry.clear();
        check(deleted.get() == 2 && registry.getSerial(id) == null);

        registry.all().put("legacy:443", audit(new AtomicReference<>("auditing"), deleted));
        busy(() -> registry.submitSerial(() -> first, a -> {}));
        registry.clear();
        try { registry.submitSerial(() -> { throw new IllegalStateException("lost start response"); }, a -> {}); }
        catch (IllegalStateException expected) { }
        busy(() -> registry.submitSerial(() -> first, a -> {}));

        AuditRegistry concurrent = new AuditRegistry(null);
        AtomicInteger accepted = new AtomicInteger();
        Runnable submit = () -> {
            try { concurrent.submitSerial(() -> second, a -> {}); accepted.incrementAndGet(); }
            catch (AuditRegistry.BusyException expected) { }
        };
        Thread a = new Thread(submit), b = new Thread(submit);
        a.start(); b.start(); a.join(); b.join();
        check(accepted.get() == 1);
        System.out.println("SequentialAuditTest passed");
    }
}

// Admin pane (multi-user mode): account CRUD, disable/enable, password reset, and the audit log.
// Mounted from the top nav only when /api/me reports role "admin" — the server enforces it regardless.
import { useCallback, useEffect, useState } from "react";
import { apiCall, useRole } from "../api";
import { KeyRound, RefreshCw, ShieldCheck, UserRound } from "lucide-react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import { Input } from "./ui/input";
import { NativeSelect } from "./ui/native-select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

interface AdminUser {
  id: string;
  username: string;
  displayName: string;
  role: "admin" | "user";
  status: "active" | "disabled";
  createdAt: number;
}

interface AuditRow {
  seq: number;
  ts: number;
  actorName: string | null;
  action: string;
  target: string | null;
  ip: string | null;
  detail: string | null;
}

function fmt(ts: number): string {
  const d = new Date(ts);
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function Users() {
  const { role, user: me } = useRole();
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [audit, setAudit] = useState<AuditRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tempPw, setTempPw] = useState<{ user: string; password: string } | null>(null);
  const [form, setForm] = useState({ username: "", displayName: "", role: "user" as "admin" | "user", password: "" });
  const [formMsg, setFormMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback((): void => {
    apiCall<AdminUser[]>("/api/admin/users").then(setUsers).catch((e: Error) => setErr(e.message));
    apiCall<AuditRow[]>("/api/admin/audit").then(setAudit).catch(() => {});
  }, []);
  useEffect(load, [load]);

  if (role !== "admin") {
    return <p className="mx-auto max-w-[1100px] p-8 text-muted-foreground">User management requires the admin role.</p>;
  }

  const patch = (id: string, body: Record<string, unknown>) => async (): Promise<void> => {
    setErr(null);
    setTempPw(null);
    try {
      await apiCall(`/api/admin/users/${encodeURIComponent(id)}`, "PATCH", body);
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const resetPassword = async (u: AdminUser): Promise<void> => {
    setErr(null);
    setTempPw(null);
    try {
      const r = await apiCall<{ temporaryPassword: string }>(`/api/admin/users/${encodeURIComponent(u.id)}/reset-password`, "POST");
      setTempPw({ user: u.username, password: r.temporaryPassword });
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const createUser = async (): Promise<void> => {
    setFormMsg(null);
    setTempPw(null);
    try {
      await apiCall("/api/admin/users", "POST", {
        username: form.username,
        displayName: form.displayName,
        role: form.role,
        password: form.password,
      });
      setFormMsg({ kind: "ok", text: `Created ${form.username.trim()}` });
      setForm({ username: "", displayName: "", role: "user", password: "" });
      load();
    } catch (e) {
      setFormMsg({ kind: "err", text: (e as Error).message });
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1100px] space-y-4 px-5 py-6">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="flex items-center gap-2 text-base font-semibold"><ShieldCheck className="size-4" /> Users</h1>
        <Button type="button" variant="outline" size="sm" onClick={load}><RefreshCw /> Refresh</Button>
      </header>
      {err ? <p role="alert" className="text-xs text-destructive">{err}</p> : null}
      {tempPw ? (
        <div className="rounded-md border border-warning/40 bg-warning/10 p-3">
          <p className="mb-1 text-xs font-medium text-warning">Temporary password for {tempPw.user} — shown once, all their sessions were signed out.</p>
          <code className="block break-all font-mono text-xs select-all">{tempPw.password}</code>
        </div>
      ) : null}

      <Card>
        <CardContent className="p-4">
          <h2 className="mb-3 text-sm font-semibold">New user</h2>
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void createUser();
            }}
          >
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              username
              <Input className="w-44" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="off" />
            </label>
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              display name
              <Input className="w-44" value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} autoComplete="off" />
            </label>
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              role
              <NativeSelect value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as "admin" | "user" })}>
                <option value="user">user</option>
                <option value="admin">admin</option>
              </NativeSelect>
            </label>
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              password (12+ chars)
              <Input className="w-52" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="new-password" />
            </label>
            <Button type="submit" size="sm" disabled={!form.username.trim() || !form.password}>Create</Button>
          </form>
          {formMsg ? <p role={formMsg.kind === "err" ? "alert" : "status"} className={`mt-2 text-xs ${formMsg.kind === "err" ? "text-destructive" : "text-success"}`}>{formMsg.text}</p> : null}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-4">
          <h2 className="mb-2 text-sm font-semibold">Accounts</h2>
          {users && users.length > 0 ? (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Username</TableHead>
                  <TableHead>Display name</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead><span className="sr-only">Actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => (
                  <TableRow key={u.id}>
                    <TableCell className="font-mono font-medium">
                      {u.username}
                      {u.id === me?.id ? <span className="ml-1 text-muted-foreground">(you)</span> : null}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{u.displayName || "—"}</TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <NativeSelect
                        size="sm"
                        value={u.role}
                        aria-label={`Role for ${u.username}`}
                        onChange={(e) => void patch(u.id, { role: e.target.value })()}
                      >
                        <option value="user">user</option>
                        <option value="admin">admin</option>
                      </NativeSelect>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={u.status === "active" ? "border-success/40 text-success" : "border-destructive/40 text-destructive"}>{u.status}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{fmt(u.createdAt)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button type="button" variant="outline" size="xs" title="Reset password — signs out all their sessions" onClick={() => void resetPassword(u)}>
                          <KeyRound /> Reset pw
                        </Button>
                        <Button
                          type="button"
                          variant={u.status === "active" ? "outline" : "secondary"}
                          size="xs"
                          onClick={patch(u.id, { status: u.status === "active" ? "disabled" : "active" })}
                        >
                          {u.status === "active" ? "Disable" : "Enable"}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : users ? (
            <p className="text-xs text-muted-foreground"><UserRound className="mr-1 inline size-3.5" />No accounts.</p>
          ) : (
            <p className="text-xs text-muted-foreground">Loading…</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-4">
          <h2 className="mb-2 text-sm font-semibold">Audit log <span className="font-normal text-muted-foreground">(latest 200)</span></h2>
          {audit && audit.length > 0 ? (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {audit.map((a) => (
                  <TableRow key={a.seq}>
                    <TableCell className="whitespace-nowrap text-muted-foreground">{fmt(a.ts)}</TableCell>
                    <TableCell className="font-mono">{a.actorName ?? "—"}</TableCell>
                    <TableCell>{a.action}</TableCell>
                    <TableCell className="max-w-64 truncate font-mono text-muted-foreground" title={a.target ?? ""}>{a.target ?? "—"}</TableCell>
                    <TableCell className="font-mono text-muted-foreground">{a.ip ?? "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : audit ? (
            <p className="text-xs text-muted-foreground">No audit events yet.</p>
          ) : (
            <p className="text-xs text-muted-foreground">Loading…</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

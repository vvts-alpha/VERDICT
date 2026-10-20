// Admin pane (multi-user mode): account list + creation only. Role changes, disable/enable,
// password resets and the audit log are deliberately host-local — `veritas user …` on the server.
// Mounted from the top nav only when /api/me reports role "admin" — the server enforces it regardless.
import { useCallback, useEffect, useState } from "react";
import { apiCall, useRole } from "../api";
import { RefreshCw, ShieldCheck, UserRound } from "lucide-react";
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

function fmt(ts: number): string {
  const d = new Date(ts);
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function Users() {
  const { role, user: me } = useRole();
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ username: "", displayName: "", role: "user" as "admin" | "user", password: "" });
  const [formMsg, setFormMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = useCallback((): void => {
    apiCall<AdminUser[]>("/api/admin/users").then(setUsers).catch((e: Error) => setErr(e.message));
  }, []);
  useEffect(load, [load]);

  if (role !== "admin") {
    return <p className="mx-auto max-w-[1100px] p-8 text-muted-foreground">User management requires the admin role.</p>;
  }

  const createUser = async (): Promise<void> => {
    setFormMsg(null);
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
                    <TableCell>
                      <Badge variant="outline" className={u.role === "admin" ? "border-primary/40 text-primary" : "text-muted-foreground"}>{u.role}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={u.status === "active" ? "border-success/40 text-success" : "border-destructive/40 text-destructive"}>{u.status}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{fmt(u.createdAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : users ? (
            <p className="text-xs text-muted-foreground"><UserRound className="mr-1 inline size-3.5" />No accounts.</p>
          ) : (
            <p className="text-xs text-muted-foreground">Loading…</p>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            Role changes, disable/enable, password resets and the audit log are host-local:
            <code className="mx-1">veritas user …</code> on the server.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

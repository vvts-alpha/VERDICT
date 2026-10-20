// Self-service account pane (multi-user mode): identity, password change, API tokens for the CLI,
// sign out. Rendered as an overlay pane from the top nav — the assessment DOM stays mounted behind it.
import { useEffect, useState } from "react";
import { apiCall, signOut, useRole } from "../api";
import { KeyRound, LogOut, Trash2 } from "lucide-react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import { Input } from "./ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

interface ApiToken {
  id: string;
  name: string;
  createdAt: number;
  lastUsedAt: number | null;
}

function fmt(ts: number | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function Account() {
  const { user, role } = useRole();
  const [pw, setPw] = useState({ current: "", next: "", confirm: "" });
  const [pwMsg, setPwMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [tokenName, setTokenName] = useState("");
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [tokenErr, setTokenErr] = useState<string | null>(null);

  const loadTokens = (): void => {
    apiCall<ApiToken[]>("/api/tokens").then(setTokens).catch((e: Error) => setTokenErr(e.message));
  };
  useEffect(loadTokens, []);

  const changePassword = async (): Promise<void> => {
    setPwMsg(null);
    if (pw.next !== pw.confirm) {
      setPwMsg({ kind: "err", text: "New passwords do not match" });
      return;
    }
    try {
      await apiCall("/api/auth/change-password", "POST", { currentPassword: pw.current, newPassword: pw.next });
      setPwMsg({ kind: "ok", text: "Password changed — signing you out of all sessions…" });
      window.setTimeout(() => void signOut(true), 1200);
    } catch (e) {
      setPwMsg({ kind: "err", text: (e as Error).message });
    }
  };

  const createToken = async (): Promise<void> => {
    setTokenErr(null);
    try {
      const r = await apiCall<{ id: string; token: string }>("/api/tokens", "POST", { name: tokenName.trim() || "cli" });
      setNewSecret(r.token);
      setTokenName("");
      loadTokens();
    } catch (e) {
      setTokenErr((e as Error).message);
    }
  };

  const revokeToken = async (id: string): Promise<void> => {
    setTokenErr(null);
    try {
      await apiCall(`/api/tokens/${encodeURIComponent(id)}`, "DELETE");
      loadTokens();
    } catch (e) {
      setTokenErr((e as Error).message);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[720px] space-y-4 px-5 py-6">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="text-base font-semibold">Account</h1>
        <Button type="button" variant="outline" size="sm" onClick={() => void signOut(true)}>
          <LogOut /> Sign out
        </Button>
      </header>

      <Card>
        <CardContent className="flex items-center gap-3 p-4">
          <span className="font-mono text-sm">{user?.username ?? "—"}</span>
          <Badge variant="outline" className="border-primary/40 text-primary">{role}</Badge>
          <span className="text-xs text-muted-foreground">via {user?.method ?? "session"}</span>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-3 p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><KeyRound className="size-4" /> Change password</h2>
          <form
            className="grid max-w-sm gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void changePassword();
            }}
          >
            <Input type="password" placeholder="current password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />
            <Input type="password" placeholder="new password (12+ chars)" autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
            <Input type="password" placeholder="confirm new password" autoComplete="new-password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} />
            <Button type="submit" size="sm" className="w-fit" disabled={!pw.current || !pw.next}>Update password</Button>
          </form>
          {pwMsg ? <p role={pwMsg.kind === "err" ? "alert" : "status"} className={pwMsg.kind === "err" ? "text-xs text-destructive" : "text-xs text-success"}>{pwMsg.text}</p> : null}
          <p className="text-xs text-muted-foreground">Changing the password signs out every session on every device.</p>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-3 p-4">
          <h2 className="text-sm font-semibold">API tokens</h2>
          <p className="text-xs text-muted-foreground">Bearer tokens for the CLI (<code>Authorization: Bearer …</code>). They act as your account.</p>
          <form
            className="flex max-w-sm items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void createToken();
            }}
          >
            <Input placeholder="token name (e.g. laptop cli)" value={tokenName} onChange={(e) => setTokenName(e.target.value)} />
            <Button type="submit" size="sm">Create</Button>
          </form>
          {newSecret ? (
            <div className="rounded-md border border-warning/40 bg-warning/10 p-3">
              <p className="mb-1 text-xs font-medium text-warning">Copy this token now — it is shown only once.</p>
              <code className="block break-all font-mono text-xs select-all">{newSecret}</code>
            </div>
          ) : null}
          {tokenErr ? <p role="alert" className="text-xs text-destructive">{tokenErr}</p> : null}
          {tokens && tokens.length > 0 ? (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead><span className="sr-only">Action</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="font-medium">{t.name}</TableCell>
                    <TableCell className="text-muted-foreground">{fmt(t.createdAt)}</TableCell>
                    <TableCell className="text-muted-foreground">{fmt(t.lastUsedAt)}</TableCell>
                    <TableCell className="text-right">
                      <Button type="button" variant="ghost" size="icon-sm" title="Revoke token" aria-label={`Revoke token ${t.name}`} onClick={() => void revokeToken(t.id)}>
                        <Trash2 className="size-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : tokens ? (
            <p className="text-xs text-muted-foreground">No active tokens.</p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

// Self-service account pane (multi-user mode): identity, password change, sign out.
// Rendered as an overlay pane from the top nav — the assessment DOM stays mounted behind it.
import { useState } from "react";
import { apiCall, signOut, useRole } from "../api";
import { useT } from "../i18n";
import { KeyRound, LogOut } from "lucide-react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import { Input } from "./ui/input";

export function Account() {
  const { user, role } = useRole();
  const t = useT();
  const [pw, setPw] = useState({ current: "", next: "", confirm: "" });
  const [pwMsg, setPwMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const changePassword = async (): Promise<void> => {
    setPwMsg(null);
    if (pw.next !== pw.confirm) {
      setPwMsg({ kind: "err", text: t("New passwords do not match") });
      return;
    }
    try {
      await apiCall("/api/auth/change-password", "POST", { currentPassword: pw.current, newPassword: pw.next });
      setPwMsg({ kind: "ok", text: t("Password changed — signing you out of all sessions…") });
      window.setTimeout(() => void signOut(true), 1200);
    } catch (e) {
      setPwMsg({ kind: "err", text: (e as Error).message });
    }
  };

  return (
    <div className="mx-auto w-full max-w-[720px] space-y-4 px-5 py-6">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="text-base font-semibold">{t("Account")}</h1>
        <Button type="button" variant="outline" size="sm" onClick={() => void signOut(true)}>
          <LogOut /> {t("Sign out")}
        </Button>
      </header>

      <Card>
        <CardContent className="flex items-center gap-3 p-4">
          <span className="font-mono text-sm">{user?.username ?? "—"}</span>
          <Badge variant="outline" className="border-primary/40 text-primary">{role ? t(role) : "—"}</Badge>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="space-y-3 p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><KeyRound className="size-4" /> {t("Change password")}</h2>
          <form
            className="grid max-w-sm gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void changePassword();
            }}
          >
            <Input type="password" placeholder={t("current password")} autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} />
            <Input type="password" placeholder={t("new password (12+ chars)")} autoComplete="new-password" value={pw.next} onChange={(e) => setPw({ ...pw, next: e.target.value })} />
            <Input type="password" placeholder={t("confirm new password")} autoComplete="new-password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} />
            <Button type="submit" size="sm" className="w-fit" disabled={!pw.current || !pw.next}>{t("Update password")}</Button>
          </form>
          {pwMsg ? <p role={pwMsg.kind === "err" ? "alert" : "status"} className={pwMsg.kind === "err" ? "text-xs text-destructive" : "text-xs text-success"}>{pwMsg.text}</p> : null}
          <p className="text-xs text-muted-foreground">{t("Changing the password signs out every session on every device.")}</p>
        </CardContent>
      </Card>
    </div>
  );
}

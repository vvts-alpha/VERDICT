import type { Severity } from "@veritas/core";
import { useT } from "../i18n";
import { Badge } from "./ui/badge";

export const severityBorder: Record<Severity, string> = {
  critical: "border-l-critical",
  high: "border-l-destructive",
  medium: "border-l-warning",
  low: "border-l-success",
  info: "border-l-primary",
};

const severityTone: Record<Severity, string> = {
  critical: "bg-critical text-white",
  high: "bg-destructive text-on-error",
  medium: "bg-warning text-on-warning",
  low: "bg-success text-on-success",
  info: "bg-primary text-primary-foreground",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const t = useT();
  return <Badge className={severityTone[severity]}>{t(severity)}</Badge>;
}

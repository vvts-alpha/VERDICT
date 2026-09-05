/** Desktop connection checks contain no target data or credentials. */
export interface ReadinessCheck {
  name: string;
  status: "ok" | "error" | "skipped";
  message: string;
}

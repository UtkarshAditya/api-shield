import { Link } from "react-router-dom";
import type { LearningStatus } from "@/api/schemas";
import { Tooltip } from "@/components/ui/Tooltip";
import { StatusDot } from "@/components/ui/Primitives";
import { formatRelative } from "@/lib/format";

/** Top-bar learning status: a dot and a mono word. */
export function LearningChip({ status }: { status: LearningStatus | undefined }) {
  if (!status) return <span className="h-4 w-24 animate-pulse bg-surface-2" aria-hidden />;

  const label =
    status.mode === "warmup" ? `Learning ${Math.round(status.progress * 100)}%` : status.mode === "active" ? "Learning active" : "Learning off";
  const tip =
    status.mode === "warmup"
      ? `Warming up on normal traffic. Alerts start ${status.ends_at ? formatRelative(status.ends_at) : "when warm-up completes"}.`
      : status.mode === "active"
        ? `Baseline ready: ${status.endpoints_learned} endpoints, ${status.shapes_learned ?? "?"} payload shapes. Shapes only, never values.`
        : "Anomaly detection is off for this upstream.";

  return (
    <Tooltip content={tip}>
      <Link to="/app/learning" className="rounded-sm px-1 text-fg hover:underline hover:underline-offset-4">
        <StatusDot tone={status.mode === "active" ? "ok" : status.mode === "warmup" ? "ink" : "muted"}>{label}</StatusDot>
      </Link>
    </Tooltip>
  );
}

import { Brain } from "lucide-react";
import { Link } from "react-router-dom";
import type { LearningStatus } from "@/api/schemas";
import { Tooltip } from "@/components/ui/Tooltip";
import { formatRelative } from "@/lib/format";

function Ring({ progress }: { progress: number }) {
  const r = 7;
  const c = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 18 18" className="size-4 -rotate-90" aria-hidden>
      <circle cx="9" cy="9" r={r} fill="none" stroke="var(--border)" strokeWidth="2.5" />
      <circle cx="9" cy="9" r={r} fill="none" stroke="var(--accent)" strokeWidth="2.5" strokeDasharray={c} strokeDashoffset={c * (1 - progress)} strokeLinecap="round" />
    </svg>
  );
}

export function LearningChip({ status }: { status: LearningStatus | undefined }) {
  if (!status) return <span className="h-7 w-28 animate-pulse rounded-full bg-surface-2" aria-hidden />;

  const label =
    status.mode === "warmup" ? `Learning ${Math.round(status.progress * 100)}%` : status.mode === "active" ? "Learning active" : "Learning off";
  const tip =
    status.mode === "warmup"
      ? `Warming up: observing normal traffic shapes. Alerts start ${status.ends_at ? formatRelative(status.ends_at) : "soon"}.`
      : status.mode === "active"
        ? `Baseline ready: ${status.endpoints_learned} endpoints, ${status.shapes_learned ?? "?"} payload shapes. Only shapes are stored, never values.`
        : "Anomaly detection is disabled for this upstream.";

  return (
    <Tooltip content={tip}>
      <Link
        to="/app/learning"
        className="inline-flex h-7 items-center gap-1.5 rounded-full border border-border bg-surface-2 px-3 text-xs font-medium text-fg hover:border-accent/50"
      >
        {status.mode === "warmup" ? <Ring progress={status.progress} /> : <Brain className={status.mode === "active" ? "size-3.5 text-accent" : "size-3.5 text-muted"} aria-hidden />}
        {label}
      </Link>
    </Tooltip>
  );
}

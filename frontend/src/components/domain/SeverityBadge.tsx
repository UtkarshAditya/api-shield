import type { Severity } from "@/api/schemas";
import { cn } from "@/lib/cn";

const label: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const order: Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Severity as a mark plus the word, never color alone. The ramp is ordered:
 * info (hollow) -> low -> medium -> high -> critical (vermilion), and the square fills with rank.
 */
export function SeverityMark({ severity, className, compact }: { severity: Severity; className?: string; compact?: boolean }) {
  const rank = order.indexOf(severity);
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap", className)}>
      <span
        aria-hidden
        className={cn("inline-block size-2.5 shrink-0 border", rank === 0 ? "border-sev-info bg-transparent" : "border-transparent")}
        style={rank > 0 ? { background: `var(--sev-${severity})` } : undefined}
      />
      <span className={cn(compact && "sr-only", severity === "critical" ? "font-medium text-sev-critical" : "text-fg")}>{label[severity]}</span>
    </span>
  );
}

/** Kept for existing imports (and the brief's name): same component. */
export const SeverityBadge = SeverityMark;

export function severityForScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 1) return "low";
  return "info";
}

/** Thin left edge bar in the severity color, for list rows. */
export function severityEdge(severity: Severity) {
  return { boxShadow: `inset 2px 0 0 var(--sev-${severity})` };
}

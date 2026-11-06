import { AlertOctagon, AlertTriangle, Info, ShieldAlert, type LucideIcon } from "lucide-react";
import { ArrowDownCircle } from "lucide-react";
import type { Severity } from "@/api/schemas";
import { cn } from "@/lib/cn";

const config: Record<Severity, { label: string; icon: LucideIcon; cls: string }> = {
  critical: { label: "Critical", icon: AlertOctagon, cls: "text-sev-critical bg-sev-critical/12 border-sev-critical/30" },
  high: { label: "High", icon: ShieldAlert, cls: "text-sev-high bg-sev-high/12 border-sev-high/30" },
  medium: { label: "Medium", icon: AlertTriangle, cls: "text-sev-medium bg-sev-medium/12 border-sev-medium/30" },
  low: { label: "Low", icon: ArrowDownCircle, cls: "text-sev-low bg-sev-low/12 border-sev-low/30" },
  info: { label: "Info", icon: Info, cls: "text-sev-info bg-sev-info/12 border-sev-info/30" },
};

/** Severity is always color + icon + text, never color alone. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const c = config[severity];
  const Icon = c.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium", c.cls, className)}>
      <Icon className="size-3" aria-hidden />
      {c.label}
    </span>
  );
}

export function severityForScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 1) return "low";
  return "info";
}

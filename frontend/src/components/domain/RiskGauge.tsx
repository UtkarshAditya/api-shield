import { cn } from "@/lib/cn";
import { severityForScore, SeverityMark } from "./SeverityBadge";

/** A 10-segment horizontal bar for a 0-10 score; filled segments take the severity color. */
export function SegmentBar({ value, max = 10, segments = 10, color, label, className }: {
  value: number;
  max?: number;
  segments?: number;
  color?: string;
  label: string;
  className?: string;
}) {
  const filled = Math.round((Math.min(max, Math.max(0, value)) / max) * segments);
  return (
    <div role="img" aria-label={label} className={cn("flex gap-[3px]", className)}>
      {Array.from({ length: segments }, (_, i) => (
        <span
          key={i}
          aria-hidden
          className={cn("h-2 flex-1", i < filled ? "" : "bg-border")}
          style={i < filled ? { background: color ?? "var(--text)" } : undefined}
        />
      ))}
    </div>
  );
}

/** API risk: a large number, a segmented bar and the severity word. Replaces the gauge arc. */
export function RiskMeter({ score, className }: { score: number; className?: string }) {
  const sev = severityForScore(score);
  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex items-baseline gap-3">
        <span className="font-mono text-[56px] leading-none font-medium tracking-tight">{score.toFixed(1)}</span>
        <span className="font-mono text-sm text-muted">/ 10</span>
        <SeverityMark severity={sev} className="ml-auto" />
      </div>
      <SegmentBar value={score} color={`var(--sev-${sev})`} label={`API risk score ${score.toFixed(1)} out of 10, ${sev}`} />
    </div>
  );
}

/** Kept for existing imports. */
export const RiskGauge = RiskMeter;

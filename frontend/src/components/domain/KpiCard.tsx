import { ArrowDownRight, ArrowUpRight, Minus, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Card } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { cn } from "@/lib/cn";
import { formatDelta } from "@/lib/format";
import { WhyTooltip } from "./WhyTooltip";

type Props = {
  label: string;
  value: ReactNode;
  icon: LucideIcon;
  /** Fractional change vs previous period, e.g. 0.12 = +12%. */
  delta?: number;
  /** Whether an increase is good (requests) or bad (blocked, alerts, latency). */
  upIsGood?: boolean;
  sub?: ReactNode;
  why: ReactNode;
  loading?: boolean;
};

export function KpiCard({ label, value, icon: Icon, delta, upIsGood = false, sub, why, loading }: Props) {
  const flat = delta === undefined || Math.abs(delta) < 0.005;
  const good = !flat && (delta! > 0) === upIsGood;
  const DeltaIcon = flat ? Minus : delta! > 0 ? ArrowUpRight : ArrowDownRight;

  return (
    <Card className="flex flex-col gap-2 p-4">
      <div className="flex items-center gap-1.5 text-xs font-medium text-muted">
        <Icon className="size-3.5" aria-hidden />
        <span>{label}</span>
        <WhyTooltip label={`What does ${label} mean?`}>{why}</WhyTooltip>
      </div>
      {loading ? (
        <>
          <Skeleton className="h-7 w-24" />
          <Skeleton className="h-4 w-32" />
        </>
      ) : (
        <>
          <div className="text-2xl font-semibold tracking-tight tabular-nums">{value}</div>
          <div className="flex items-center gap-2 text-xs">
            {delta !== undefined && (
              <span
                className={cn("inline-flex items-center gap-0.5 font-medium tabular-nums", flat ? "text-muted" : good ? "text-act-allow" : "text-sev-critical")}
              >
                <DeltaIcon className="size-3.5" aria-hidden />
                {formatDelta(delta)}
                <span className="sr-only">{flat ? "no change" : good ? "(improvement)" : "(worse)"} vs previous period</span>
              </span>
            )}
            {sub && <span className="text-muted">{sub}</span>}
          </div>
        </>
      )}
    </Card>
  );
}

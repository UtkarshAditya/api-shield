import type { ReactNode } from "react";
import { Skeleton } from "@/components/ui/Skeleton";
import { cn } from "@/lib/cn";
import { formatDelta } from "@/lib/format";
import { Term } from "./Term";

type Props = {
  label: string;
  value: ReactNode;
  /** Explanation shown on the label (dotted underline). */
  tip: ReactNode;
  /** Fractional change vs previous period, e.g. 0.12 = +12%. */
  delta?: number;
  /** Whether an increase is good (requests) or bad (blocked, alerts, latency). */
  upIsGood?: boolean;
  sub?: ReactNode;
  loading?: boolean;
  /** Paint the figure in the signal color (e.g. open alerts > 0). */
  signal?: boolean;
};

/** A number as typography: small caps label above, large mono figure, plain-text delta below. */
export function StatFigure({ label, value, tip, delta, upIsGood = false, sub, loading, signal }: Props) {
  const flat = delta === undefined || Math.abs(delta) < 0.005;
  const worse = !flat && (delta! > 0) !== upIsGood;
  return (
    <div className="flex min-w-0 flex-col gap-2 px-5 py-4 first:pl-0">
      <span className="eyebrow">
        <Term tip={tip}>{label}</Term>
      </span>
      {loading ? (
        <>
          <Skeleton className="h-10 w-28" />
          <Skeleton className="h-3.5 w-24" />
        </>
      ) : (
        <>
          <span className={cn("font-mono text-[40px] leading-none font-medium tracking-[-0.03em]", signal ? "text-signal" : "text-fg")}>{value}</span>
          <span className="font-mono text-xs text-muted">
            {delta !== undefined && (
              <span className={cn(worse && "text-signal")}>
                {flat ? "no change" : `${formatDelta(delta)} vs prev.`}
                {!flat && <span className="sr-only">{worse ? " (worse)" : " (better)"}</span>}
              </span>
            )}
            {delta !== undefined && sub ? <span aria-hidden> · </span> : null}
            {sub}
          </span>
        </>
      )}
    </div>
  );
}

/** One horizontal row of figures divided by hairlines (wraps to 2-up / 3-up on narrow screens). */
export function StatStrip({ children }: { children: ReactNode }) {
  return (
    <div className="grid grid-cols-2 border-y border-border sm:grid-cols-3 xl:grid-cols-5 [&>*]:border-border [&>*+*]:border-l max-sm:[&>*:nth-child(odd)]:border-l-0 max-sm:[&>*:nth-child(odd)]:pl-0">
      {children}
    </div>
  );
}

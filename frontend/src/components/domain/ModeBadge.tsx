import type { ReactNode } from "react";
import { Tooltip } from "@/components/ui/Tooltip";
import { cn } from "@/lib/cn";

type Mode = "monitor" | "enforce";

export const modeExplain: Record<Mode, string> = {
  monitor: "MONITOR: everything passes. Rule matches are logged, so you can see what would be blocked.",
  enforce: "ENFORCE: requests that match a block, throttle or challenge rule are rejected before they reach your API.",
};

/** One segment of the two-state mode control. Active MONITOR is ink; active ENFORCE is the signal color. */
export function ModeSegment({ mode, active, children, className }: { mode: Mode; active: boolean; children?: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-7 items-center px-2.5 font-mono text-[11px] font-medium tracking-wider",
        active ? (mode === "enforce" ? "bg-signal-mark text-surface" : "bg-accent text-accent-fg") : "text-muted",
        className,
      )}
    >
      {children ?? mode.toUpperCase()}
    </span>
  );
}

/** Read-only mode display (non-admins). */
export function ModeBadge({ mode }: { mode: Mode | undefined }) {
  if (!mode) return <span className="h-7 w-36 animate-pulse bg-surface-2" aria-hidden />;
  return (
    <Tooltip content={modeExplain[mode]}>
      <span tabIndex={0} className="inline-flex border border-border-strong" aria-label={`Gateway mode: ${mode.toUpperCase()}`}>
        <ModeSegment mode="monitor" active={mode === "monitor"} />
        <ModeSegment mode="enforce" active={mode === "enforce"} className="border-l border-border-strong" />
      </span>
    </Tooltip>
  );
}

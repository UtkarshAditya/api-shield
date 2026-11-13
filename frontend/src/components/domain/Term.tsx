import type { ReactNode } from "react";
import { Tooltip } from "@/components/ui/Tooltip";
import { cn } from "@/lib/cn";

/**
 * A label that explains itself: dotted underline, tooltip on hover and on keyboard focus.
 * Replaces the separate "?" icon; this is the "why" affordance on scores, blocks and alerts.
 */
export function Term({ children, tip, className }: { children: ReactNode; tip: ReactNode; className?: string }) {
  return (
    <Tooltip content={tip}>
      <span
        tabIndex={0}
        className={cn(
          "cursor-help underline decoration-border-strong decoration-dotted underline-offset-[3px] hover:decoration-fg focus-visible:decoration-fg",
          className,
        )}
      >
        {children}
      </span>
    </Tooltip>
  );
}

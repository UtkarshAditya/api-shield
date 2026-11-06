import { Eye, ShieldCheck } from "lucide-react";
import { Tooltip } from "@/components/ui/Tooltip";
import { cn } from "@/lib/cn";

export function ModeBadge({ mode }: { mode: "monitor" | "enforce" | undefined }) {
  if (!mode) return <span className="h-7 w-24 animate-pulse rounded-full bg-surface-2" aria-hidden />;
  const enforce = mode === "enforce";
  return (
    <Tooltip
      content={
        enforce
          ? "ENFORCE: requests that match a block rule are rejected before they reach your API."
          : "MONITOR: everything is allowed through. Rule matches are logged so you can see what would be blocked."
      }
    >
      <span
        tabIndex={0}
        className={cn(
          "inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-[11px] font-bold tracking-wider",
          enforce ? "border-sev-critical/40 bg-sev-critical/10 text-sev-critical" : "border-sev-low/40 bg-sev-low/10 text-sev-low",
        )}
      >
        {enforce ? <ShieldCheck className="size-3.5" aria-hidden /> : <Eye className="size-3.5" aria-hidden />}
        {enforce ? "ENFORCE" : "MONITOR"}
      </span>
    </Tooltip>
  );
}

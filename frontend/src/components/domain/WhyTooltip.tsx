import { HelpCircle } from "lucide-react";
import type { ReactNode } from "react";
import { Tooltip } from "@/components/ui/Tooltip";

/** The "why?" affordance required on every score, block and alert. */
export function WhyTooltip({ children, label = "Why?" }: { children: ReactNode; label?: string }) {
  return (
    <Tooltip content={children}>
      <button type="button" className="inline-flex rounded text-muted hover:text-fg" aria-label={label}>
        <HelpCircle className="size-3.5" aria-hidden />
      </button>
    </Tooltip>
  );
}

import { cn } from "@/lib/cn";
import { Tooltip } from "@/components/ui/Tooltip";

/** Renders a value that has been redacted upstream. We never receive or render the raw value. */
export function MaskedValue({ label = "redacted", className }: { label?: string; className?: string }) {
  return (
    <Tooltip content="Redacted at the gateway. APIShield stores the shape of the data, never its contents.">
      <span tabIndex={0} className={cn("inline-flex items-center border border-dashed border-border-strong px-1.5 font-mono text-[11px] text-muted", className)}>
        ‹{label}›
      </span>
    </Tooltip>
  );
}

/** Caller IDs arrive pre-masked ("key_9f3a••••"); render them consistently in mono. */
export function CallerId({ value }: { value: string }) {
  return <span className="font-mono text-[13px] text-fg">{value}</span>;
}

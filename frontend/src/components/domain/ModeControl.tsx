import { ChevronDown, Eye, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useSettings, useUpdateSettings } from "@/api/queries";
import { useAuth } from "@/auth/AuthContext";
import { ConfirmDialog } from "@/components/ui/Dialog";
import { Tooltip } from "@/components/ui/Tooltip";
import { cn } from "@/lib/cn";
import { ModeBadge } from "./ModeBadge";

type Mode = "monitor" | "enforce";

/** Confirmation for switching between MONITOR and ENFORCE. Shared by the topbar and Settings. */
export function ModeSwitchDialog({ open, onOpenChange, target }: { open: boolean; onOpenChange: (v: boolean) => void; target: Mode }) {
  const update = useUpdateSettings();
  const enforce = target === "enforce";
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={enforce ? "Switch to ENFORCE?" : "Switch back to MONITOR?"}
      tone={enforce ? "danger" : "primary"}
      confirmLabel={enforce ? "Switch to ENFORCE" : "Switch to MONITOR"}
      description={
        enforce ? (
          <>
            <p>
              The gateway will start <strong className="text-fg">rejecting</strong> requests that match a block, throttle or challenge rule,
              before they reach your API. Callers will get 403, 429 or 401 answers.
            </p>
            <p className="mt-2">Check the Rules page first: an over-broad rule will block real users. You can switch back at any time.</p>
          </>
        ) : (
          <p>Everything will be allowed through again. Rule matches are still logged, so you can see what would have been blocked.</p>
        )
      }
      onConfirm={() => update.mutateAsync({ mode: target })}
    />
  );
}

/** The topbar mode badge. Admins can click it to switch modes (with confirmation). */
export function ModeControl() {
  const { data: settings } = useSettings();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const mode = settings?.mode;

  if (!mode || !can("mode.switch")) return <ModeBadge mode={mode} />;

  const enforce = mode === "enforce";
  const target: Mode = enforce ? "monitor" : "enforce";
  return (
    <>
      <Tooltip
        content={
          (enforce
            ? "ENFORCE: requests that match a block rule are rejected before they reach your API."
            : "MONITOR: everything is allowed through. Rule matches are logged so you can see what would be blocked.") +
          ` Click to switch to ${target.toUpperCase()}.`
        }
      >
        <button
          type="button"
          onClick={() => setOpen(true)}
          aria-label={`Gateway mode: ${mode.toUpperCase()}. Switch to ${target.toUpperCase()}`}
          aria-haspopup="dialog"
          className={cn(
            "inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-[11px] font-bold tracking-wider hover:brightness-110",
            enforce ? "border-sev-critical/40 bg-sev-critical/10 text-sev-critical" : "border-sev-low/40 bg-sev-low/10 text-sev-low",
          )}
        >
          {enforce ? <ShieldCheck className="size-3.5" aria-hidden /> : <Eye className="size-3.5" aria-hidden />}
          {enforce ? "ENFORCE" : "MONITOR"}
          <ChevronDown className="size-3" aria-hidden />
        </button>
      </Tooltip>
      <ModeSwitchDialog open={open} onOpenChange={setOpen} target={target} />
    </>
  );
}

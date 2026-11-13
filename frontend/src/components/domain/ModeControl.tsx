import { useState } from "react";
import { useSettings, useUpdateSettings } from "@/api/queries";
import { useAuth } from "@/auth/AuthContext";
import { ConfirmDialog } from "@/components/ui/Dialog";
import { Tooltip } from "@/components/ui/Tooltip";
import { cn } from "@/lib/cn";
import { ModeBadge, modeExplain, ModeSegment } from "./ModeBadge";

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
              The gateway starts <strong className="text-fg">rejecting</strong> requests that match a block, throttle or challenge rule, before
              they reach your API. Callers get 403, 429 or 401.
            </p>
            <p className="mt-2">Review the Rules page first: an over-broad rule blocks real users. You can switch back at any time.</p>
          </>
        ) : (
          <p>Everything passes again. Rule matches are still logged, so you can see what would have been blocked.</p>
        )
      }
      onConfirm={() => update.mutateAsync({ mode: target })}
    />
  );
}

/**
 * Two-state segmented control in the top bar. The active state is a filled segment (ENFORCE uses
 * the signal color); the other segment is the button that asks to switch, with confirmation.
 * Non-admins get the same control, read-only.
 */
export function ModeControl() {
  const { data: settings } = useSettings();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const mode = settings?.mode;

  if (!mode || !can("mode.switch")) return <ModeBadge mode={mode} />;

  const target: Mode = mode === "enforce" ? "monitor" : "enforce";
  const switchButton = (
    <Tooltip content={`${modeExplain[mode]} Click to switch to ${target.toUpperCase()}.`}>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label={`Gateway mode: ${mode.toUpperCase()}. Switch to ${target.toUpperCase()}`}
        aria-haspopup="dialog"
        className={cn("transition-colors ease-ui hover:bg-surface-2", target === "enforce" && "border-l border-border-strong")}
      >
        <ModeSegment mode={target} active={false} className="hover:text-fg" />
      </button>
    </Tooltip>
  );
  const current = <ModeSegment mode={mode} active className={mode === "enforce" ? "border-l border-border-strong" : undefined} />;

  return (
    <>
      <span className="inline-flex border border-border-strong">
        {mode === "monitor" ? (
          <>
            {current}
            {switchButton}
          </>
        ) : (
          <>
            {switchButton}
            {current}
          </>
        )}
      </span>
      <ModeSwitchDialog open={open} onOpenChange={setOpen} target={target} />
    </>
  );
}

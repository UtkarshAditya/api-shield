import { useEffect, useState, type ReactNode } from "react";
import { useLearningMutations, useLearningStatus } from "@/api/queries";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { Term } from "@/components/domain/Term";
import { Button } from "@/components/ui/Button";
import { CardError } from "@/components/ui/Card";
import { ConfirmDialog, InlineError } from "@/components/ui/Dialog";
import { PageHeader, Section, StatusDot } from "@/components/ui/Primitives";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { describeError } from "@/lib/errors";
import { cn } from "@/lib/cn";
import { formatRelative } from "@/lib/format";

const modeLabel = { warmup: "Warming up", active: "Active", disabled: "Disabled" } as const;
const SEGMENTS = 20;

function sensitivityWords(v: number) {
  if (v < 0.34) return "Relaxed: only strong outliers become alerts.";
  if (v < 0.67) return "Balanced: the default.";
  return "Strict: smaller deviations become alerts; expect more of them.";
}

function Figure({ label, value, tip }: { label: string; value: ReactNode; tip?: string }) {
  return (
    <div className="space-y-1.5 border-l border-border px-5 py-3 first:border-l-0 first:pl-0">
      <p className="eyebrow">{tip ? <Term tip={tip}>{label}</Term> : label}</p>
      <p className="font-mono text-3xl font-medium tracking-tight">{value}</p>
    </div>
  );
}

export default function LearningPage() {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const status = useLearningStatus(upstreamId);
  const { update, reset } = useLearningMutations(upstreamId);
  const [sensitivity, setSensitivity] = useState(0.5);
  const [confirm, setConfirm] = useState<"reset" | "disable" | null>(null);
  const s = status.data;
  const editable = can("settings.edit");

  useEffect(() => {
    if (s?.sensitivity !== undefined) setSensitivity(s.sensitivity);
  }, [s?.sensitivity]);

  const pct = s ? Math.round(s.progress * 100) : 0;
  const filled = s ? Math.round(s.progress * SEGMENTS) : 0;

  return (
    <div className="max-w-5xl space-y-8">
      <PageHeader
        title="Learning"
        description={
          <>
            The learner builds a baseline of normal traffic per endpoint. It learns shapes (field names, types, sizes and rates), never the values inside requests.
          </>
        }
      />

      {status.isError ? (
        <CardError onRetry={() => status.refetch()} />
      ) : !s ? (
        <Skeleton className="h-64" />
      ) : (
        <>
          <Section title={<Term tip="During warm-up the learner only observes. Once active, traffic far from the baseline becomes an alert.">Status</Term>}>
            <div className="grid grid-cols-3 border-b border-border">
              <div className="space-y-1.5 px-5 py-3 pl-0">
                <p className="eyebrow">Mode</p>
                <p className="pt-1">
                  <StatusDot tone={s.mode === "active" ? "ok" : s.mode === "warmup" ? "ink" : "muted"} className="text-lg">
                    {modeLabel[s.mode]}
                  </StatusDot>
                </p>
              </div>
              <Figure label="Endpoints learned" value={s.endpoints_learned} />
              <Figure label="Payload shapes" value={s.shapes_learned ?? "—"} tip="Distinct request shapes (field names and types). Never values." />
            </div>
            <div className="mt-4 grid items-center gap-x-4 gap-y-1 sm:grid-cols-[1fr_auto]">
              <div
                role="progressbar"
                aria-label="Baseline progress"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={pct}
                className="flex gap-[3px]"
              >
                {Array.from({ length: SEGMENTS }, (_, i) => (
                  <span key={i} aria-hidden className={cn("h-1.5 flex-1", i < filled ? "bg-fg" : "bg-border")} />
                ))}
              </div>
              <span className="font-mono text-sm">{pct}%</span>
              <p className="font-mono text-xs text-muted sm:col-span-2">
                started {formatRelative(s.started_at)}
                {s.ends_at && (s.mode === "warmup" ? ` · ready ${formatRelative(s.ends_at)}` : ` · baseline ready since ${formatRelative(s.ends_at)}`)}
              </p>
            </div>
          </Section>

          <Section title={<Term tip="Higher sensitivity flags smaller deviations from the baseline. False-positive feedback on alerts also adjusts thresholds.">Sensitivity</Term>}>
            <div className="space-y-3">
              <div className="flex items-center gap-4">
                <label htmlFor="sensitivity" className="sr-only">
                  Sensitivity
                </label>
                <input
                  id="sensitivity"
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={sensitivity}
                  disabled={!editable}
                  onChange={(e) => setSensitivity(Number(e.target.value))}
                  aria-valuetext={`${Math.round(sensitivity * 100)}%. ${sensitivityWords(sensitivity)}`}
                  className="max-w-md flex-1 accent-[var(--text)]"
                />
                <span className="w-12 text-right font-mono text-sm">{Math.round(sensitivity * 100)}%</span>
              </div>
              <p className="text-sm text-muted">{sensitivityWords(sensitivity)}</p>
              {editable ? (
                <Button size="sm" onClick={() => update.mutate({ sensitivity })} disabled={update.isPending || sensitivity === s.sensitivity}>
                  {update.isPending ? "Saving…" : "Save sensitivity"}
                </Button>
              ) : (
                <p className="text-xs text-muted">Only admins can change learning settings.</p>
              )}
              {update.isError && <InlineError message={describeError(update.error)} />}
            </div>
          </Section>

          {editable && (
            <Section title="Control">
              <div className="flex flex-wrap items-center gap-6">
                <label className="flex items-center gap-3 text-sm">
                  <Switch
                    checked={s.mode !== "disabled"}
                    label="Anomaly detection enabled"
                    disabled={update.isPending}
                    onCheckedChange={(on) => (on ? update.mutate({ mode: "active" }) : setConfirm("disable"))}
                  />
                  Anomaly detection {s.mode === "disabled" ? "off" : "on"}
                </label>
                <Button variant="secondary" size="sm" onClick={() => setConfirm("reset")}>
                  Reset baseline
                </Button>
              </div>
            </Section>
          )}
        </>
      )}

      <ConfirmDialog
        open={confirm === "reset"}
        onOpenChange={(v) => !v && setConfirm(null)}
        title="Reset the learned baseline?"
        tone="danger"
        confirmLabel="Reset baseline"
        description="The learner forgets every learned endpoint and shape and starts a new warm-up. No alerts are raised until it is ready again."
        onConfirm={() => reset.mutateAsync()}
      />
      <ConfirmDialog
        open={confirm === "disable"}
        onOpenChange={(v) => !v && setConfirm(null)}
        title="Turn off anomaly detection?"
        tone="danger"
        confirmLabel="Turn off"
        description="No new alerts are raised for this API until you turn it back on. Gateway rules keep working."
        onConfirm={() => update.mutateAsync({ mode: "disabled" })}
      />
    </div>
  );
}

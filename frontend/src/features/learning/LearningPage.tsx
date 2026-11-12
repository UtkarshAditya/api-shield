import { useEffect, useState } from "react";
import { Brain, RotateCcw } from "lucide-react";
import { useLearningMutations, useLearningStatus } from "@/api/queries";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Button } from "@/components/ui/Button";
import { Card, CardError, CardHeader } from "@/components/ui/Card";
import { ConfirmDialog, InlineError } from "@/components/ui/Dialog";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { describeError } from "@/lib/errors";
import { formatRelative } from "@/lib/format";

const modeLabel = { warmup: "Warming up", active: "Active", disabled: "Disabled" } as const;

function sensitivityWords(v: number) {
  if (v < 0.34) return "Relaxed: only strong outliers become alerts.";
  if (v < 0.67) return "Balanced: the default.";
  return "Strict: smaller deviations become alerts, expect more of them.";
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

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Learning</h1>
        <p className="text-sm text-muted">
          The learner builds a baseline of normal traffic per endpoint. It learns <strong className="text-fg">shapes</strong> (field names, types, sizes and rates),
          never the values inside requests.
        </p>
      </div>

      {status.isError ? (
        <Card>
          <CardError onRetry={() => status.refetch()} />
        </Card>
      ) : !s ? (
        <Skeleton className="h-64" />
      ) : (
        <>
          <Card>
            <CardHeader
              title="Status"
              hint={
                <WhyTooltip label="What do these numbers mean?">
                  During warm-up the learner only observes. Once it is active, traffic that strays far from the baseline becomes an alert.
                </WhyTooltip>
              }
            />
            <div className="grid gap-4 px-5 pb-5 sm:grid-cols-3">
              <div>
                <p className="text-xs text-muted">Mode</p>
                <p className="mt-1 flex items-center gap-2 text-lg font-semibold">
                  <Brain className={s.mode === "disabled" ? "size-4 text-muted" : "size-4 text-accent"} aria-hidden />
                  {modeLabel[s.mode]}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted">Endpoints learned</p>
                <p className="mt-1 text-lg font-semibold tabular-nums">{s.endpoints_learned}</p>
              </div>
              <div>
                <p className="text-xs text-muted">Payload shapes learned</p>
                <p className="mt-1 text-lg font-semibold tabular-nums">{s.shapes_learned ?? "—"}</p>
              </div>
              <div className="sm:col-span-3">
                <div className="mb-1 flex justify-between text-xs text-muted">
                  <span>Baseline progress</span>
                  <span className="tabular-nums">{Math.round(s.progress * 100)}%</span>
                </div>
                <div role="progressbar" aria-label="Baseline progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(s.progress * 100)} className="h-2 overflow-hidden rounded-full bg-surface-2">
                  <div className="h-full rounded-full bg-accent" style={{ width: `${s.progress * 100}%` }} />
                </div>
                <p className="mt-1 text-xs text-muted">
                  Started {formatRelative(s.started_at)}
                  {s.ends_at && (s.mode === "warmup" ? `, ready ${formatRelative(s.ends_at)}` : `, baseline ready since ${formatRelative(s.ends_at)}`)}.
                </p>
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Sensitivity"
              hint={<WhyTooltip label="What does sensitivity change?">Higher sensitivity flags smaller deviations from the baseline. Your false-positive feedback on alerts nudges thresholds too.</WhyTooltip>}
            />
            <div className="space-y-3 px-5 pb-5">
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
                  className="flex-1 accent-[var(--accent)]"
                />
                <span className="w-12 text-right text-sm tabular-nums">{Math.round(sensitivity * 100)}%</span>
              </div>
              <p className="text-xs text-muted">{sensitivityWords(sensitivity)}</p>
              {editable ? (
                <Button size="sm" onClick={() => update.mutate({ sensitivity })} disabled={update.isPending || sensitivity === s.sensitivity}>
                  {update.isPending ? "Saving…" : "Save sensitivity"}
                </Button>
              ) : (
                <p className="text-xs text-muted">Only admins can change learning settings.</p>
              )}
              {update.isError && <InlineError message={describeError(update.error)} />}
            </div>
          </Card>

          {editable && (
            <Card>
              <CardHeader title="Control" />
              <div className="flex flex-wrap items-center gap-6 px-5 pb-5">
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
                  <RotateCcw className="size-3.5" aria-hidden /> Reset baseline
                </Button>
              </div>
            </Card>
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

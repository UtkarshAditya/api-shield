import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Bell, Check, CircleSlash, Eye, SlidersHorizontal, ThumbsUp } from "lucide-react";
import { useAlert, useAlerts, useAlertStatus, usePromoteAlert } from "@/api/queries";
import type { Alert, AlertFeedbackResponse, Rule } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { EmptyState } from "@/components/domain/EmptyState";
import { CallerId } from "@/components/domain/MaskedValue";
import { SeverityBadge } from "@/components/domain/SeverityBadge";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Button } from "@/components/ui/Button";
import { Card, CardError } from "@/components/ui/Card";
import { ConfirmDialog, InlineError } from "@/components/ui/Dialog";
import { Segmented } from "@/components/ui/Segmented";
import { Skeleton } from "@/components/ui/Skeleton";
import { describeError } from "@/lib/errors";
import { cn } from "@/lib/cn";
import { formatRelative } from "@/lib/format";

const statusLabel: Record<Alert["status"], string> = {
  new: "New",
  acknowledged: "Acknowledged",
  true_positive: "Confirmed attack",
  false_positive: "False positive",
};

const sevBar: Record<Alert["severity"], string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

function StatusChip({ status }: { status: Alert["status"] }) {
  return <span className="rounded-full border border-border px-2 py-0.5 text-[11px] text-muted">{statusLabel[status]}</span>;
}

function ScoreWhy({ alert }: { alert: Alert }) {
  return (
    <WhyTooltip label={`Why is this alert ranked #${alert.rank}?`}>
      Score {alert.score.toFixed(2)} (0 to 1) says how far this caller's behaviour is from the learned baseline. Rank #{alert.rank} combines that with how risky
      the endpoint is, so #1 is the one to look at first.
    </WhyTooltip>
  );
}

// ---- Queue -------------------------------------------------------------------------

function AlertQueue({ alerts, selected }: { alerts: Alert[]; selected?: string }) {
  const groups = useMemo(() => {
    const map = new Map<string, Alert[]>();
    for (const a of [...alerts].sort((x, y) => x.rank - y.rank)) map.set(a.caller, [...(map.get(a.caller) ?? []), a]);
    return [...map.entries()];
  }, [alerts]);

  return (
    <div className="space-y-4">
      {groups.map(([caller, items]) => (
        <Card key={caller}>
          <header className="flex items-center gap-2 border-b border-border/60 px-4 py-2.5">
            <h2 className="text-xs text-muted">
              Caller <CallerId value={caller} />
            </h2>
            <span className="ml-auto text-[11px] text-muted">
              {items.length} alert{items.length === 1 ? "" : "s"}
            </span>
          </header>
          <ul>
            {items.map((a) => (
              <li key={a.id}>
                <Link
                  to={`/app/alerts/${a.id}`}
                  aria-current={a.id === selected ? "page" : undefined}
                  className={cn("block px-4 py-2.5 hover:bg-surface-2", a.id === selected && "bg-accent-soft hover:bg-accent-soft")}
                >
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[11px] text-muted">#{a.rank}</span>
                    <SeverityBadge severity={a.severity} />
                    <span className="truncate font-mono text-xs">{a.endpoint}</span>
                    <span className="text-[11px] text-muted tabular-nums">score {a.score.toFixed(2)}</span>
                    <StatusChip status={a.status} />
                    <span className="ml-auto shrink-0 text-[11px] text-muted">{formatRelative(a.ts)}</span>
                  </span>
                  <span className="mt-1 line-clamp-2 block text-xs leading-relaxed text-muted">{a.explanation}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      ))}
    </div>
  );
}

// ---- Detail ------------------------------------------------------------------------

const firstNumber = (s: string) => {
  const m = s.replace(/,/g, "").match(/-?\d+(\.\d+)?/);
  return m ? Number(m[0]) : undefined;
};

function ReasonBars({ alert }: { alert: Alert }) {
  return (
    <ul className="space-y-3">
      {alert.reasons.map((r) => {
        const obs = firstNumber(r.observed);
        const base = firstNumber(r.baseline);
        const max = Math.max(obs ?? 0, base ?? 0);
        const bars = obs !== undefined && base !== undefined && max > 0;
        return (
          <li key={r.feature}>
            <div className="flex flex-wrap items-baseline gap-2 text-sm">
              <span className="font-medium">{r.feature}</span>
              {r.z !== undefined && <span className="text-xs text-muted tabular-nums">{r.z.toFixed(1)}σ from normal</span>}
            </div>
            <dl className="mt-1 grid grid-cols-[5.5rem_1fr] items-center gap-x-2 gap-y-1 text-xs">
              <dt className="text-muted">Observed</dt>
              <dd className="flex items-center gap-2">
                {bars && <span aria-hidden className={cn("h-2 rounded-full", sevBar[alert.severity])} style={{ width: `${Math.max(2, (obs! / max) * 60)}%` }} />}
                <span className="font-mono">{r.observed}</span>
              </dd>
              <dt className="text-muted">Baseline</dt>
              <dd className="flex items-center gap-2">
                {bars && <span aria-hidden className="h-2 rounded-full bg-muted/50" style={{ width: `${Math.max(2, (base! / max) * 60)}%` }} />}
                <span className="font-mono">{r.baseline}</span>
              </dd>
            </dl>
          </li>
        );
      })}
    </ul>
  );
}

function Timeline({ points }: { points: NonNullable<Alert["timeline"]> }) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const peak = points.reduce((a, b) => (b.count > a.count ? b : a), points[0]);
  return (
    <div>
      <div
        role="img"
        aria-label={`Requests per bucket over ${points.length} buckets; peak ${peak.count} ${formatRelative(peak.ts)}.`}
        className="flex h-20 items-end gap-1 rounded-md border border-border bg-surface-2/50 p-2"
      >
        {points.map((p) => (
          <span key={p.ts} title={`${p.count} at ${new Date(p.ts).toLocaleTimeString()}`} className="flex-1 rounded-sm opacity-80" style={{ height: `${Math.max(3, (p.count / max) * 100)}%`, backgroundColor: "var(--chart-blocked)" }} />
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[11px] text-muted">
        <span>{formatRelative(points[0].ts)}</span>
        <span>{formatRelative(points[points.length - 1].ts)}</span>
      </div>
    </div>
  );
}

function PromoteDialog({ alert, open, onOpenChange, onDone }: { alert: Alert; open: boolean; onOpenChange: (v: boolean) => void; onDone: (r: Rule) => void }) {
  const { upstreamId } = useWorkspace();
  const promote = usePromoteAlert(upstreamId);
  const [action, setAction] = useState<Rule["action"]>("throttle");
  const keyed = alert.caller.startsWith("key_");
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Promote to a gateway rule?"
      confirmLabel="Create rule"
      description={
        keyed ? (
          <p>
            The rule targets only this API key (<CallerId value={alert.caller} />) on <span className="font-mono text-xs">{alert.endpoint}</span>.
          </p>
        ) : (
          <p>
            Only API-key callers can be targeted individually. This caller is a pseudonym (<CallerId value={alert.caller} />): APIShield never stores the raw IP
            or user id behind it, so the rule applies to <strong className="text-fg">every caller</strong> of{" "}
            <span className="font-mono text-xs">{alert.endpoint}</span>.
          </p>
        )
      }
      onConfirm={async () => onDone(await promote.mutateAsync({ id: alert.id, action }))}
    >
      <label className="block text-sm">
        <span className="mb-1 block font-medium">Action</span>
        <select value={action} onChange={(e) => setAction(e.target.value as Rule["action"])} className="h-9 w-full rounded-md border border-border bg-surface-2 px-2 text-sm">
          <option value="throttle">throttle (10 requests per minute)</option>
          <option value="block">block</option>
          <option value="log">log only</option>
        </select>
      </label>
    </ConfirmDialog>
  );
}

function formatDelta(n: number) {
  return `${n > 0 ? "+" : n < 0 ? "−" : "±"}${Math.abs(n)}`;
}

function AlertDetail({ id }: { id: string }) {
  const alert = useAlert(id);
  const { can } = useAuth();
  const setStatus = useAlertStatus();
  const [feedback, setFeedback] = useState<AlertFeedbackResponse | null>(null);
  const [promoting, setPromoting] = useState(false);
  const [promoted, setPromoted] = useState<Rule | null>(null);

  if (alert.isError) return <CardError onRetry={() => alert.refetch()} message="Couldn't load this alert." />;
  const a = alert.data;
  if (!a) return <Skeleton className="m-5 h-80" />;

  const act = (status: Alert["status"]) => {
    setFeedback(null);
    setStatus.mutate({ id: a.id, status }, { onSuccess: setFeedback });
  };

  return (
    <div className="space-y-5 p-5">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-muted">#{a.rank}</span>
          <SeverityBadge severity={a.severity} />
          <StatusChip status={a.status} />
          <span className="ml-auto text-xs text-muted">{formatRelative(a.ts)}</span>
        </div>
        <h2 className="font-mono text-base font-semibold">{a.endpoint}</h2>
        <p className="flex flex-wrap items-center gap-2 text-xs text-muted">
          Caller <CallerId value={a.caller} />
          <span aria-hidden>·</span>
          <span className="tabular-nums">score {a.score.toFixed(2)}</span>
          <ScoreWhy alert={a} />
        </p>
      </header>

      <section>
        <h3 className="mb-1 text-xs font-semibold text-muted">What happened</h3>
        <p className="text-sm leading-relaxed">{a.explanation}</p>
      </section>

      {a.reasons.length > 0 && (
        <section>
          <h3 className="mb-2 flex items-center gap-1 text-xs font-semibold text-muted">
            Why it was flagged
            <WhyTooltip label="About these reasons">
              Each reason compares what this caller did with the baseline learned from normal traffic. Only shapes and counts are compared, never payload values.
            </WhyTooltip>
          </h3>
          <ReasonBars alert={a} />
        </section>
      )}

      {a.timeline && a.timeline.length > 1 && (
        <section>
          <h3 className="mb-2 text-xs font-semibold text-muted">Timeline</h3>
          <Timeline points={a.timeline} />
        </section>
      )}

      <section className="space-y-3 border-t border-border pt-4">
        {can("alerts.triage") ? (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => act("acknowledged")} disabled={setStatus.isPending || a.status === "acknowledged"}>
              <Eye className="size-3.5" aria-hidden /> Acknowledge
            </Button>
            <Button size="sm" variant="secondary" onClick={() => act("true_positive")} disabled={setStatus.isPending || a.status === "true_positive"}>
              <ThumbsUp className="size-3.5" aria-hidden /> True positive
            </Button>
            <Button size="sm" variant="secondary" onClick={() => act("false_positive")} disabled={setStatus.isPending || a.status === "false_positive"}>
              <CircleSlash className="size-3.5" aria-hidden /> False positive
            </Button>
            {can("rules.edit") && (
              <Button size="sm" onClick={() => setPromoting(true)}>
                <SlidersHorizontal className="size-3.5" aria-hidden /> Promote to rule
              </Button>
            )}
          </div>
        ) : (
          <p className="text-xs text-muted">Viewers can read alerts. Admins and analysts can triage them.</p>
        )}
        <div role="status" aria-live="polite" className="space-y-1 text-sm">
          {feedback?.adjustment && (
            <p className="flex items-center gap-2 rounded-md border border-act-allow/30 bg-act-allow/12 px-3 py-2">
              <Check className="size-4 text-act-allow" aria-hidden />
              <span>
                Threshold adjusted: <strong>{feedback.adjustment.feature}</strong> {formatDelta(feedback.adjustment.threshold_delta)}. Similar behaviour will be
                flagged less eagerly.
              </span>
            </p>
          )}
          {feedback && !feedback.adjustment && <p className="text-muted">Marked as {statusLabel[feedback.alert.status].toLowerCase()}.</p>}
          {promoted && (
            <p>
              Rule created:{" "}
              <Link to={`/app/rules?highlight=${encodeURIComponent(promoted.id)}`} className="font-mono text-xs text-accent hover:underline">
                {promoted.id}
              </Link>
            </p>
          )}
        </div>
        {setStatus.isError && <InlineError message={describeError(setStatus.error)} />}
      </section>
      <PromoteDialog alert={a} open={promoting} onOpenChange={setPromoting} onDone={setPromoted} />
    </div>
  );
}

export default function AlertsPage() {
  const { id } = useParams();
  const { upstreamId } = useWorkspace();
  const [filter, setFilter] = useState<"active" | "all">("active");
  const alerts = useAlerts(upstreamId, { status: filter === "active" ? "active" : undefined, limit: 200 });
  const items = alerts.data?.items ?? [];

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Alerts</h1>
          <p className="text-sm text-muted">Anomalies ranked by urgency and grouped by caller. Your feedback tunes the thresholds.</p>
        </div>
        <Segmented label="Which alerts" value={filter} options={["active", "all"] as const} onChange={setFilter} />
      </div>
      <div className={cn("grid gap-4", id && "lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]")}>
        <div>
          {alerts.isError ? (
            <Card>
              <CardError onRetry={() => alerts.refetch()} />
            </Card>
          ) : alerts.isLoading ? (
            <Skeleton className="h-80" />
          ) : items.length === 0 ? (
            <Card>
              <EmptyState icon={Bell} title="All quiet" body={filter === "active" ? "No active alerts. Switch to “all” to see resolved ones." : "No alerts yet."} />
            </Card>
          ) : (
            <AlertQueue alerts={items} selected={id} />
          )}
        </div>
        {id && (
          <Card className="self-start lg:sticky lg:top-20">
            <AlertDetail key={id} id={id} />
          </Card>
        )}
      </div>
    </div>
  );
}

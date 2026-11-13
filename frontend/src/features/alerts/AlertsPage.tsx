import { useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useAlert, useAlerts, useAlertStatus, usePromoteAlert } from "@/api/queries";
import type { Alert, AlertFeedbackResponse, Rule } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { EmptyState } from "@/components/domain/EmptyState";
import { CallerId } from "@/components/domain/MaskedValue";
import { SeverityMark, severityEdge } from "@/components/domain/SeverityBadge";
import { Term } from "@/components/domain/Term";
import { Button } from "@/components/ui/Button";
import { CardError } from "@/components/ui/Card";
import { ConfirmDialog, InlineError } from "@/components/ui/Dialog";
import { PageHeader } from "@/components/ui/Primitives";
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

function StatusText({ status }: { status: Alert["status"] }) {
  return <span className={cn("font-mono text-[11px] uppercase tracking-wider", status === "new" ? "text-fg" : "text-muted")}>{statusLabel[status]}</span>;
}

// ---- Queue -------------------------------------------------------------------------

function AlertQueue({ alerts, selected }: { alerts: Alert[]; selected?: string }) {
  const groups = useMemo(() => {
    const map = new Map<string, Alert[]>();
    for (const a of [...alerts].sort((x, y) => x.rank - y.rank)) map.set(a.caller, [...(map.get(a.caller) ?? []), a]);
    return [...map.entries()];
  }, [alerts]);

  return (
    <div className="space-y-6">
      {groups.map(([caller, items]) => (
        <section key={caller} aria-label={`Alerts for ${caller}`}>
          <header className="flex items-baseline gap-2 border-b border-border pb-1.5">
            <span className="eyebrow">Caller</span>
            <h2>
              <CallerId value={caller} />
            </h2>
            <span className="ml-auto font-mono text-[11px] text-muted">
              {items.length} alert{items.length === 1 ? "" : "s"}
            </span>
          </header>
          <ul>
            {items.map((a) => (
              <li key={a.id} className="border-b border-border">
                <Link
                  to={`/app/alerts/${a.id}`}
                  aria-current={a.id === selected ? "page" : undefined}
                  className={cn("block py-2.5 pr-2 pl-3 transition-colors ease-ui hover:bg-surface-2", a.id === selected && "bg-surface-2")}
                  style={a.id === selected ? { boxShadow: "inset 2px 0 0 var(--text)" } : severityEdge(a.severity)}
                >
                  <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="font-mono text-xs text-muted">#{a.rank}</span>
                    <SeverityMark severity={a.severity} />
                    <span className="truncate font-mono text-[13px]">{a.endpoint}</span>
                    <span className="font-mono text-xs text-muted">{a.score.toFixed(2)}</span>
                    <StatusText status={a.status} />
                    <span className="ml-auto shrink-0 font-mono text-[11px] text-muted">{formatRelative(a.ts)}</span>
                  </span>
                  <span className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted">{a.explanation}</span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

// ---- Detail ------------------------------------------------------------------------

/** "Why this alert": metric, observed, baseline, deviation, as a mono ledger. */
function ReasonLedger({ alert }: { alert: Alert }) {
  return (
    <table className="w-full text-[13px]">
      <caption className="sr-only">Why this alert was flagged</caption>
      <thead>
        <tr className="text-left">
          <th scope="col" className="eyebrow border-b border-border py-1.5 pr-3 font-medium">Metric</th>
          <th scope="col" className="eyebrow border-b border-border py-1.5 pr-3 font-medium">Observed</th>
          <th scope="col" className="eyebrow border-b border-border py-1.5 pr-3 font-medium">Baseline</th>
          <th scope="col" className="eyebrow border-b border-border py-1.5 text-right font-medium">Deviation</th>
        </tr>
      </thead>
      <tbody>
        {alert.reasons.map((r) => (
          <tr key={r.feature} className="border-b border-border/70 align-top">
            <td className="py-2 pr-3">{r.feature}</td>
            <td className="py-2 pr-3 font-mono font-medium">{r.observed}</td>
            <td className="py-2 pr-3 font-mono text-muted">{r.baseline}</td>
            <td className={cn("py-2 text-right font-mono", r.z !== undefined && r.z >= 3 && "text-signal")}>{r.z !== undefined ? `${r.z.toFixed(1)}σ` : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Timeline({ points }: { points: NonNullable<Alert["timeline"]> }) {
  const max = Math.max(1, ...points.map((p) => p.count));
  const peak = points.reduce((a, b) => (b.count > a.count ? b : a), points[0]);
  return (
    <div>
      <div role="img" aria-label={`Requests per bucket over ${points.length} buckets; peak ${peak.count} ${formatRelative(peak.ts)}.`} className="flex h-16 items-end gap-[3px] border-b border-border">
        {points.map((p) => (
          <span
            key={p.ts}
            title={`${p.count} at ${new Date(p.ts).toLocaleTimeString()}`}
            className="flex-1"
            style={{ height: `${Math.max(2, (p.count / max) * 100)}%`, background: p.count === peak.count ? "var(--chart-blocked)" : "var(--text-muted)" }}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[11px] text-muted">
        <span>{formatRelative(points[0].ts)}</span>
        <span>peak {peak.count}</span>
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
            or user id behind it, so the rule applies to <strong className="text-fg">every caller</strong> of <span className="font-mono text-xs">{alert.endpoint}</span>.
          </p>
        )
      }
      onConfirm={async () => onDone(await promote.mutateAsync({ id: alert.id, action }))}
    >
      <label className="block text-sm">
        <span className="eyebrow mb-1 block">Action</span>
        <select value={action} onChange={(e) => setAction(e.target.value as Rule["action"])} className="h-8 w-full rounded-sm border border-border-strong bg-surface px-2 text-sm">
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

function Block({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <section className="border-t border-border pt-3">
      <h3 className="eyebrow mb-2 text-fg">{title}</h3>
      {children}
    </section>
  );
}

function AlertDetail({ id }: { id: string }) {
  const alert = useAlert(id);
  const { can } = useAuth();
  const setStatus = useAlertStatus();
  const [feedback, setFeedback] = useState<AlertFeedbackResponse | null>(null);
  const [promoting, setPromoting] = useState(false);
  const [promoted, setPromoted] = useState<Rule | null>(null);

  if (alert.isError) return <CardError onRetry={() => alert.refetch()} message="This alert did not load." />;
  const a = alert.data;
  if (!a) return <Skeleton className="h-80" />;

  const act = (status: Alert["status"]) => {
    setFeedback(null);
    setStatus.mutate({ id: a.id, status }, { onSuccess: setFeedback });
  };

  return (
    <div className="space-y-5">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-mono text-sm text-muted">#{a.rank}</span>
          <SeverityMark severity={a.severity} />
          <StatusText status={a.status} />
          <span className="ml-auto font-mono text-xs text-muted">{formatRelative(a.ts)}</span>
        </div>
        <h2 className="font-mono text-xl font-medium tracking-tight">{a.endpoint}</h2>
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted">
          <span>
            Caller <CallerId value={a.caller} />
          </span>
          <Term
            tip={`Score ${a.score.toFixed(2)} (0 to 1) is how far this caller's behaviour is from the learned baseline. Rank #${a.rank} also weighs how risky the endpoint is, so #1 is first to look at.`}
          >
            <span className="font-mono">score {a.score.toFixed(2)}</span>
          </Term>
        </p>
      </header>

      <Block title="What happened">
        <p className="text-sm leading-relaxed">{a.explanation}</p>
      </Block>

      {a.reasons.length > 0 && (
        <Block title={<Term tip="Each line compares this caller with the baseline learned from normal traffic. Only shapes and counts, never payload values.">Why this alert</Term>}>
          <ReasonLedger alert={a} />
        </Block>
      )}

      {a.timeline && a.timeline.length > 1 && (
        <Block title="Timeline">
          <Timeline points={a.timeline} />
        </Block>
      )}

      <section className="space-y-3 border-t border-border pt-4">
        {can("alerts.triage") ? (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => act("acknowledged")} disabled={setStatus.isPending || a.status === "acknowledged"}>
              Acknowledge
            </Button>
            <Button size="sm" variant="secondary" onClick={() => act("true_positive")} disabled={setStatus.isPending || a.status === "true_positive"}>
              True positive
            </Button>
            <Button size="sm" variant="secondary" onClick={() => act("false_positive")} disabled={setStatus.isPending || a.status === "false_positive"}>
              False positive
            </Button>
            {can("rules.edit") && (
              <Button size="sm" onClick={() => setPromoting(true)} className="ml-auto">
                Promote to rule
              </Button>
            )}
          </div>
        ) : (
          <p className="text-xs text-muted">Viewers can read alerts. Admins and analysts can triage them.</p>
        )}
        <div role="status" aria-live="polite" className="space-y-1 text-sm">
          {feedback?.adjustment && (
            <p className="border-l-2 border-ok py-1 pl-3">
              Threshold adjusted: <strong>{feedback.adjustment.feature}</strong> <span className="font-mono">{formatDelta(feedback.adjustment.threshold_delta)}</span>. Sent to the
              learner as feedback.
            </p>
          )}
          {feedback && !feedback.adjustment && <p className="text-muted">Marked as {statusLabel[feedback.alert.status].toLowerCase()}.</p>}
          {promoted && (
            <p>
              Rule created:{" "}
              <Link to={`/app/rules?rule=${encodeURIComponent(promoted.id)}`} className="link font-mono text-xs">
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
    <div className="space-y-6">
      <PageHeader
        title="Alerts"
        description="Anomalies from the learner, ranked by urgency and grouped by caller. Feedback is sent back to the learner."
        actions={<Segmented label="Which alerts" value={filter} options={["active", "all"] as const} onChange={setFilter} />}
      />
      <div className={cn("grid gap-x-10 gap-y-6", id && "lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]")}>
        <div className="min-w-0">
          {alerts.isError ? (
            <CardError onRetry={() => alerts.refetch()} />
          ) : alerts.isLoading ? (
            <Skeleton className="h-80" />
          ) : items.length === 0 ? (
            <div className="border-y border-border">
              <EmptyState title={filter === "active" ? "0 active alerts" : "0 alerts"} body={filter === "active" ? "Switch to “all” to see resolved alerts." : undefined} />
            </div>
          ) : (
            <AlertQueue alerts={items} selected={id} />
          )}
        </div>
        {id && (
          <div className="self-start border-border lg:sticky lg:top-[calc(var(--topbar-h)+24px)] lg:border-l lg:pl-8">
            <AlertDetail key={id} id={id} />
          </div>
        )}
      </div>
    </div>
  );
}

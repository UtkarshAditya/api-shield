import { useState } from "react";
import { Link } from "react-router-dom";
import { Activity, Bell, Gauge, ShieldBan, Timer } from "lucide-react";
import { useAlerts, useSummary, useTimeseries } from "@/api/queries";
import type { MetricsSummary, Range } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { KpiCard } from "@/components/domain/KpiCard";
import { CallerId } from "@/components/domain/MaskedValue";
import { RiskGauge } from "@/components/domain/RiskGauge";
import { SeverityBadge, severityForScore } from "@/components/domain/SeverityBadge";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Card, CardError, CardHeader } from "@/components/ui/Card";
import { Segmented } from "@/components/ui/Segmented";
import { Skeleton } from "@/components/ui/Skeleton";
import { formatCompact, formatMs, formatNumber, formatPercent, formatRelative } from "@/lib/format";
import { Onboarding } from "./Onboarding";
import { TrafficChart, TrafficLegend } from "./TrafficChart";

const ranges = ["1h", "24h", "7d"] as const;
const delta = (cur: number, prev: number) => (prev === 0 ? 0 : (cur - prev) / prev);

function KpiRow({ s, loading }: { s?: MetricsSummary; loading: boolean }) {
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
      <KpiCard
        label="Requests"
        icon={Activity}
        loading={loading}
        value={s && formatCompact(s.requests)}
        delta={s && delta(s.requests, s.previous.requests)}
        upIsGood
        sub="vs prev. period"
        why="Every request that passed through the gateway in this time range, allowed or not."
      />
      <KpiCard
        label="Blocked"
        icon={ShieldBan}
        loading={loading}
        value={s && formatCompact(s.blocked)}
        delta={s && delta(s.blocked, s.previous.blocked)}
        sub={s && `${formatPercent(s.blocked / Math.max(1, s.requests))} of traffic`}
        why="Requests stopped by a rule (or that would be stopped, in monitor mode). A spike usually means an attack, or a rule that's too strict."
      />
      <KpiCard
        label="Active alerts"
        icon={Bell}
        loading={loading}
        value={s?.active_alerts}
        delta={s && delta(s.active_alerts, s.previous.active_alerts)}
        why="Anomalies the learning engine flagged that nobody has resolved yet. Ranked by how unusual they are and how risky the endpoint is."
      />
      <KpiCard
        label="Risk score"
        icon={Gauge}
        loading={loading}
        value={s && `${s.risk_score.toFixed(1)} / 10`}
        delta={s && delta(s.risk_score, s.previous.risk_score)}
        why="Overall exposure from open scanner findings, weighted by severity. Fixing findings or applying their suggested rules lowers it."
      />
      <KpiCard
        label="p95 latency"
        icon={Timer}
        loading={loading}
        value={s && formatMs(s.p95_latency_ms)}
        delta={s && delta(s.p95_latency_ms, s.previous.p95_latency_ms)}
        why="95% of requests finished faster than this, including the gateway's own overhead."
      />
    </div>
  );
}

export default function OverviewPage() {
  const { upstreamId, upstream, upstreams, isLoading: wsLoading } = useWorkspace();
  const [range, setRange] = useState<Range>("24h");
  const summary = useSummary(upstreamId, range);
  const series = useTimeseries(upstreamId, range);
  const alerts = useAlerts(upstreamId, { status: "active", limit: 5 });

  if (!wsLoading && upstreams.length === 0) return <Onboarding />;

  const s = summary.data;

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted">{upstream ? `How ${upstream.name} is doing right now.` : "Loading…"}</p>
        </div>
        <Segmented label="Time range" value={range} options={ranges} onChange={setRange} />
      </div>

      {summary.isError ? (
        <Card>
          <CardError onRetry={() => summary.refetch()} />
        </Card>
      ) : (
        <KpiRow s={s} loading={summary.isLoading} />
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Traffic"
            hint={<WhyTooltip>Allowed and blocked requests over time. A red spike is worth a look; it often lines up with a new alert.</WhyTooltip>}
            action={<TrafficLegend />}
          />
          <div className="px-3 pb-4">
            {series.isError ? <CardError onRetry={() => series.refetch()} /> : series.data ? <TrafficChart data={series.data} range={range} /> : <Skeleton className="mx-2 h-80" />}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="API risk"
            hint={<WhyTooltip>Computed from open scanner findings. Each driver below links to its fix.</WhyTooltip>}
            action={
              <Link to="/app/scans" className="text-xs text-accent hover:underline">
                Scans →
              </Link>
            }
          />
          <div className="px-5 pb-5">
            {s ? (
              <>
                <RiskGauge score={s.risk_score} />
                <h3 className="mt-5 mb-2 text-xs font-semibold text-muted">Why this score</h3>
                {s.risk_drivers.length === 0 ? (
                  <p className="text-sm text-muted">No open findings. Nice.</p>
                ) : (
                  <ul className="space-y-2">
                    {s.risk_drivers.map((d) => (
                      <li key={d.title} className="flex items-start justify-between gap-3 text-sm">
                        <div className="min-w-0">
                          <p className="truncate">{d.title}</p>
                          <p className="font-mono text-[11px] text-muted">{d.endpoint}</p>
                        </div>
                        <SeverityBadge severity={d.severity} />
                      </li>
                    ))}
                  </ul>
                )}
              </>
            ) : (
              <Skeleton className="h-60" />
            )}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader title="Top endpoints" />
          <div className="overflow-x-auto px-2 pb-3">
            {s ? (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[11px] text-muted uppercase">
                    <th className="px-3 py-1.5 font-medium">Endpoint</th>
                    <th className="px-3 py-1.5 text-right font-medium">Requests</th>
                    <th className="px-3 py-1.5 text-right font-medium">Block rate</th>
                    <th className="px-3 py-1.5 text-right font-medium">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {s.top_endpoints.slice(0, 6).map((e) => (
                    <tr key={e.method + e.path_template} className="border-t border-border/60">
                      <td className="px-3 py-2 font-mono text-xs">
                        <span className="mr-1.5 text-muted">{e.method}</span>
                        {e.path_template}
                      </td>
                      <td className="px-3 py-2 text-right tabular-nums">{formatCompact(e.requests)}</td>
                      <td className="px-3 py-2 text-right text-muted tabular-nums">{formatPercent(e.blocked / Math.max(1, e.requests))}</td>
                      <td className="px-3 py-2 text-right">
                        <span className="sr-only">{severityForScore(e.risk_score)} risk, </span>
                        <span className="font-medium tabular-nums" style={{ color: `var(--sev-${severityForScore(e.risk_score)})` }}>
                          {e.risk_score.toFixed(1)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Skeleton className="mx-3 h-48" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Top callers" hint={<WhyTooltip>Callers are identified by API-key fingerprint or masked IP. Raw keys are never stored.</WhyTooltip>} />
          <div className="px-2 pb-3">
            {s ? (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[11px] text-muted uppercase">
                    <th className="px-3 py-1.5 font-medium">Caller</th>
                    <th className="px-3 py-1.5 text-right font-medium">Requests</th>
                    <th className="px-3 py-1.5 text-right font-medium">Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {s.top_callers.map((c) => (
                    <tr key={c.caller} className="border-t border-border/60">
                      <td className="px-3 py-2">
                        <CallerId value={c.caller} />
                      </td>
                      <td className="px-3 py-2 text-right tabular-nums">{formatNumber(c.requests)}</td>
                      <td className="px-3 py-2 text-right tabular-nums">
                        {c.alerts > 0 ? <span className="font-medium text-sev-high">{c.alerts}</span> : <span className="text-muted">0</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Skeleton className="mx-3 h-48" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Latest alerts"
            action={
              <Link to="/app/alerts" className="text-xs text-accent hover:underline">
                All alerts →
              </Link>
            }
          />
          <div className="px-3 pb-3">
            {alerts.isError ? (
              <CardError onRetry={() => alerts.refetch()} />
            ) : alerts.data ? (
              alerts.data.items.length === 0 ? (
                <p className="px-2 py-8 text-center text-sm text-muted">All quiet. No active alerts.</p>
              ) : (
                <ul className="space-y-1">
                  {alerts.data.items.map((a) => (
                    <li key={a.id}>
                      <Link to={`/app/alerts/${a.id}`} className="block rounded-lg px-2 py-2 hover:bg-surface-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[11px] text-muted">#{a.rank}</span>
                          <SeverityBadge severity={a.severity} />
                          <span className="truncate font-mono text-xs">{a.endpoint}</span>
                          <span className="ml-auto shrink-0 text-[11px] text-muted">{formatRelative(a.ts)}</span>
                        </div>
                        <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted">{a.explanation}</p>
                      </Link>
                    </li>
                  ))}
                </ul>
              )
            ) : (
              <Skeleton className="h-48" />
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

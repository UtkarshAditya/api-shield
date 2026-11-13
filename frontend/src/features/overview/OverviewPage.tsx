import { useState } from "react";
import { Link } from "react-router-dom";
import { useAlerts, useSummary, useTimeseries } from "@/api/queries";
import type { MetricsSummary, Range } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { CallerId } from "@/components/domain/MaskedValue";
import { RiskMeter } from "@/components/domain/RiskGauge";
import { SeverityMark, severityEdge, severityForScore } from "@/components/domain/SeverityBadge";
import { StatFigure, StatStrip } from "@/components/domain/StatFigure";
import { Term } from "@/components/domain/Term";
import { CardError } from "@/components/ui/Card";
import { DataTable, PageHeader, Section, Td, Th, THead, Tr } from "@/components/ui/Primitives";
import { Segmented } from "@/components/ui/Segmented";
import { Skeleton } from "@/components/ui/Skeleton";
import { formatCompact, formatMs, formatNumber, formatPercent, formatRelative } from "@/lib/format";
import { Onboarding } from "./Onboarding";
import { TrafficChart, TrafficLegend } from "./TrafficChart";

const ranges = ["1h", "24h", "7d"] as const;
const delta = (cur: number, prev: number) => (prev === 0 ? 0 : (cur - prev) / prev);

function Figures({ s, loading }: { s?: MetricsSummary; loading: boolean }) {
  return (
    <StatStrip>
      <StatFigure
        label="Requests"
        loading={loading}
        value={s && formatCompact(s.requests)}
        delta={s && delta(s.requests, s.previous.requests)}
        upIsGood
        tip="Every request that passed through the gateway in this range, allowed or not."
      />
      <StatFigure
        label="Blocked"
        loading={loading}
        value={s && formatCompact(s.blocked)}
        delta={s && delta(s.blocked, s.previous.blocked)}
        sub={s && `${formatPercent(s.blocked / Math.max(1, s.requests))} of traffic`}
        tip="Requests stopped by a rule (or that would be stopped, in MONITOR). A spike usually means an attack or an over-strict rule."
      />
      <StatFigure
        label="Active alerts"
        loading={loading}
        value={s?.active_alerts}
        signal={!!s?.active_alerts}
        delta={s && delta(s.active_alerts, s.previous.active_alerts)}
        tip="Anomalies the learner flagged that nobody has resolved. Ranked by how unusual they are and how risky the endpoint is."
      />
      <StatFigure
        label="Risk score"
        loading={loading}
        value={s && s.risk_score.toFixed(1)}
        sub="of 10"
        delta={s && delta(s.risk_score, s.previous.risk_score)}
        tip="Exposure from open scanner findings, weighted by severity. Fixing findings or applying their rules lowers it."
      />
      <StatFigure
        label="p95 latency"
        loading={loading}
        value={s && formatMs(s.p95_latency_ms)}
        delta={s && delta(s.p95_latency_ms, s.previous.p95_latency_ms)}
        tip="95% of requests finished faster than this, including the gateway's own overhead."
      />
    </StatStrip>
  );
}

function RiskSection({ s }: { s?: MetricsSummary }) {
  return (
    <Section
      title={<Term tip="Computed from open scanner findings. The top drivers are listed below.">API risk</Term>}
      action={
        <Link to="/app/scans" className="link text-xs">
          Scans
        </Link>
      }
    >
      {s ? (
        <div className="space-y-5">
          <RiskMeter score={s.risk_score} />
          {s.risk_drivers.length === 0 ? (
            <p className="font-mono text-sm text-muted">0 open findings. Run a scan to measure exposure.</p>
          ) : (
            <ol className="border-t border-border">
              {s.risk_drivers.slice(0, 3).map((d, i) => (
                <li key={d.title} className="grid grid-cols-[1.5rem_1fr_auto] items-baseline gap-2 border-b border-border py-2 text-sm" style={severityEdge(d.severity)}>
                  <span className="pl-2 font-mono text-xs text-muted">{i + 1}</span>
                  <span className="min-w-0">
                    <span className="block truncate">{d.title}</span>
                    <span className="block font-mono text-[11px] text-muted">{d.endpoint}</span>
                  </span>
                  <span className="flex items-baseline gap-3">
                    <span className="font-mono text-[13px]">{d.risk_score.toFixed(1)}</span>
                    <SeverityMark severity={d.severity} />
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      ) : (
        <Skeleton className="h-56" />
      )}
    </Section>
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
    <div className="space-y-8">
      <PageHeader
        title="Overview"
        meta={upstream ? upstream.name : "Loading"}
        description="Traffic, exposure and open alerts for the protected API."
        actions={<Segmented label="Time range" value={range} options={ranges} onChange={setRange} />}
      />

      {summary.isError ? <CardError onRetry={() => summary.refetch()} /> : <Figures s={s} loading={summary.isLoading} />}

      <div className="grid gap-x-10 gap-y-8 lg:grid-cols-3">
        <Section
          className="lg:col-span-2"
          title={<Term tip="Allowed and blocked requests over time. A vermilion spike often lines up with a new alert.">Traffic</Term>}
          action={<TrafficLegend />}
        >
          {series.isError ? <CardError onRetry={() => series.refetch()} /> : series.data ? <TrafficChart data={series.data} range={range} /> : <Skeleton className="h-72" />}
        </Section>
        <RiskSection s={s} />
      </div>

      <div className="grid gap-x-10 gap-y-8 lg:grid-cols-3">
        <Section title="Top endpoints">
          {s ? (
            <DataTable caption="Top endpoints">
              <THead>
                <Th className="first:pl-0">Endpoint</Th>
                <Th align="right">Requests</Th>
                <Th align="right">Blocked</Th>
                <Th align="right" className="last:pr-0">Risk</Th>
              </THead>
              <tbody>
                {s.top_endpoints.slice(0, 6).map((e) => (
                  <Tr key={e.method + e.path_template}>
                    <Td mono className="first:pl-0 text-xs">
                      <span className="mr-1.5 text-muted">{e.method}</span>
                      {e.path_template}
                    </Td>
                    <Td align="right" mono>{formatCompact(e.requests)}</Td>
                    <Td align="right" mono className="text-muted">{formatPercent(e.blocked / Math.max(1, e.requests))}</Td>
                    <Td align="right" className="last:pr-0">
                      <span className="inline-flex items-center justify-end gap-2">
                        <span className="font-mono text-[13px]">{e.risk_score.toFixed(1)}</span>
                        <SeverityMark severity={severityForScore(e.risk_score)} compact />
                      </span>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </DataTable>
          ) : (
            <Skeleton className="h-48" />
          )}
        </Section>

        <Section title={<Term tip="Callers are API-key fingerprints or masked IPs. Raw keys are never stored.">Top callers</Term>}>
          {s ? (
            <DataTable caption="Top callers">
              <THead>
                <Th className="first:pl-0">Caller</Th>
                <Th align="right">Requests</Th>
                <Th align="right" className="last:pr-0">Alerts</Th>
              </THead>
              <tbody>
                {s.top_callers.map((c) => (
                  <Tr key={c.caller}>
                    <Td className="first:pl-0">
                      <CallerId value={c.caller} />
                    </Td>
                    <Td align="right" mono>{formatNumber(c.requests)}</Td>
                    <Td align="right" mono className={c.alerts > 0 ? "last:pr-0 font-medium text-signal" : "last:pr-0 text-muted"}>
                      {c.alerts}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </DataTable>
          ) : (
            <Skeleton className="h-48" />
          )}
        </Section>

        <Section
          title="Latest alerts"
          action={
            <Link to="/app/alerts" className="link text-xs">
              All alerts
            </Link>
          }
        >
          {alerts.isError ? (
            <CardError onRetry={() => alerts.refetch()} />
          ) : alerts.data ? (
            alerts.data.items.length === 0 ? (
              <p className="py-6 font-mono text-sm text-muted">0 active alerts.</p>
            ) : (
              <ul>
                {alerts.data.items.map((a) => (
                  <li key={a.id} className="border-b border-border last:border-b-0">
                    <Link to={`/app/alerts/${a.id}`} className="block py-2.5 pl-3 transition-colors ease-ui hover:bg-surface-2" style={severityEdge(a.severity)}>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs text-muted">#{a.rank}</span>
                        <SeverityMark severity={a.severity} />
                        <span className="truncate font-mono text-xs">{a.endpoint}</span>
                        <span className="ml-auto shrink-0 pr-2 font-mono text-[11px] text-muted">{formatRelative(a.ts)}</span>
                      </div>
                      <p className="mt-1 line-clamp-2 pr-2 text-xs leading-relaxed text-muted">{a.explanation}</p>
                    </Link>
                  </li>
                ))}
              </ul>
            )
          ) : (
            <Skeleton className="h-48" />
          )}
        </Section>
      </div>
    </div>
  );
}

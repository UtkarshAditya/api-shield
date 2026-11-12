/** In-memory mock store. Writes persist for the browser session so actions visibly change the UI. */
import type { MetricsSummary, Range, Timeseries, TrafficEvent } from "@/api/schemas";
import {
  baseRpm,
  callers,
  endpointProfiles,
  rng,
  seedAlerts,
  seedAudit,
  seedFindings,
  seedInventory,
  seedLearning,
  seedRules,
  seedScans,
  settings,
  upstreams,
} from "./seed";

export const db = {
  upstreams: [...upstreams],
  settings: structuredClone(settings),
  alerts: seedAlerts(),
  learning: seedLearning(),
  findings: seedFindings(),
  rules: seedRules(),
  scans: seedScans(),
  inventory: seedInventory(),
  audit: seedAudit(),
};

let auditSeq = 100;
export function audit(actor: string, action: string, target_type: string, target_id?: string, details: Record<string, unknown> = {}) {
  db.audit.unshift({ id: `au_${++auditSeq}`, ts: new Date().toISOString(), actor, action, target_type, target_id, details });
}

/** Recent traffic events, newest first, shaped like the Admin API's masked events. */
export function buildRecentTraffic(upstreamId: string, limit: number): TrafficEvent[] {
  const profiles = endpointProfiles[upstreamId] ?? [];
  const callerList = callers[upstreamId] ?? [];
  if (!profiles.length) return [];
  const rand = rng(Math.floor(Date.now() / 5000));
  const out: TrafficEvent[] = [];
  for (let i = 0; i < limit; i++) {
    const p = profiles[Math.floor(rand() * profiles.length)];
    const caller = callerList[Math.floor(rand() * callerList.length)];
    const blocked = rand() < p.blockRate * 4;
    out.push({
      ts: new Date(Date.now() - i * 900).toISOString(),
      req_id: `req_${(Date.now() - i).toString(16)}`,
      caller,
      ip: caller.startsWith("ip_") ? caller : `ip_${caller.slice(-8)}`,
      method: p.method,
      path_template: p.path_template,
      status: blocked ? 403 : 200,
      latency_ms: Math.round((20 + rand() * 160) * 100) / 100,
      req_size: p.method === "GET" ? 0 : Math.round(rand() * 800),
      resp_size: Math.round(200 + rand() * 3000),
      shape_hash: Math.floor(rand() * 2 ** 48).toString(16).padStart(12, "0"),
      rule_hits: blocked ? ["builtin-sqli"] : [],
      action: blocked ? "block" : "allow",
    });
  }
  return out;
}

const rangeConfig: Record<Range, { points: number; stepMin: number }> = {
  "1h": { points: 60, stepMin: 1 },
  "24h": { points: 96, stepMin: 15 },
  "7d": { points: 84, stepMin: 120 },
};

/** Time series with a daily rhythm, noise, and a visible attack burst in the recent past. */
export function buildTimeseries(upstreamId: string, range: Range): Timeseries {
  const { points, stepMin } = rangeConfig[range];
  const rpm = baseRpm[upstreamId] ?? 500;
  const step = stepMin * 60_000;
  const end = Math.floor(Date.now() / step) * step;
  const out: Timeseries["points"] = [];

  for (let i = points - 1; i >= 0; i--) {
    const t = end - i * step;
    const r = rng(Math.floor(t / step) + upstreamId.length * 7919)();
    const hour = new Date(t).getHours() + new Date(t).getMinutes() / 60;
    const diurnal = 0.65 + 0.35 * Math.sin(((hour - 8) / 24) * Math.PI * 2);
    const noise = 0.9 + r * 0.2;
    const total = rpm * stepMin * diurnal * noise;

    // Attack burst: ~6–12 minutes ago, visible in every range.
    const minsAgo = (Date.now() - t) / 60_000;
    const burst = upstreamId === "up_shop" && minsAgo >= 3 && minsAgo <= 12 + stepMin;
    const blockedRatio = burst ? 0.32 : 0.012 + r * 0.01;
    const burstExtra = burst ? rpm * Math.min(stepMin, 10) * 1.4 : 0;

    const allTotal = total + burstExtra;
    const blocked = Math.round(allTotal * blockedRatio);
    out.push({ t: new Date(t).toISOString(), allowed: Math.round(allTotal - blocked), blocked });
  }
  return { range, metric: "requests", points: out };
}

export function buildSummary(upstreamId: string, range: Range): MetricsSummary {
  const ts = buildTimeseries(upstreamId, range);
  const requests = ts.points.reduce((s, p) => s + p.allowed + p.blocked, 0);
  const blocked = ts.points.reduce((s, p) => s + p.blocked, 0);
  const rand = rng(upstreamId.length * 31 + range.length);

  const profiles = endpointProfiles[upstreamId] ?? [];
  const top_endpoints = profiles
    .map((p) => {
      const req = Math.round(requests * p.weight);
      return { method: p.method, path_template: p.path_template, requests: req, blocked: Math.round(req * p.blockRate * 3), risk_score: p.risk };
    })
    .sort((a, b) => b.requests - a.requests);

  const alerts = db.alerts[upstreamId] ?? [];
  const callerList = callers[upstreamId] ?? [];
  const top_callers = callerList
    .map((c, i) => ({
      caller: c,
      requests: Math.round(requests * (0.3 / (i + 1)) * (0.8 + rand() * 0.4)),
      alerts: alerts.filter((a) => a.caller === c && a.status !== "false_positive").length,
    }))
    .sort((a, b) => b.requests - a.requests)
    .slice(0, 5);

  const openFindings = (db.findings[upstreamId] ?? []).filter((f) => f.status === "open");
  const risk_score = openFindings.length
    ? Math.min(10, Math.max(...openFindings.map((f) => f.risk_score)) * 0.7 + openFindings.length * 0.4)
    : 1.2;

  const active_alerts = alerts.filter((a) => a.status === "new" || a.status === "acknowledged").length;
  const p95 = upstreamId === "up_shop" ? 182 : 96;

  return {
    range,
    requests,
    blocked,
    allowed: requests - blocked,
    active_alerts,
    p95_latency_ms: p95,
    risk_score: Math.round(risk_score * 10) / 10,
    risk_drivers: openFindings
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 3)
      .map((f) => ({ title: f.title, endpoint: `${f.method} ${f.endpoint}`, severity: f.severity, risk_score: f.risk_score })),
    previous: {
      requests: Math.round(requests * 0.91),
      blocked: Math.round(blocked * 0.42),
      active_alerts: Math.max(0, active_alerts - 3),
      p95_latency_ms: p95 - 9,
      risk_score: Math.round((risk_score + 0.6) * 10) / 10,
    },
    top_endpoints,
    top_callers,
  };
}

/**
 * Data contracts for the Admin API. Mirrors §4 of the frontend brief.
 * These schemas are the single source of truth on the frontend: types are inferred from them
 * and every response is parsed through them, so contract drift fails loudly in dev.
 *
 * Anything marked CONTRACT-TBD is an assumption not yet confirmed by the backend owners.
 * See CONTRACT_QUESTIONS.md.
 */
import { z } from "zod";

export const Action = z.enum(["allow", "log", "block", "throttle", "challenge"]);
export const Severity = z.enum(["critical", "high", "medium", "low", "info"]);
export const AlertSeverity = z.enum(["critical", "high", "medium", "low"]);
export const Role = z.enum(["admin", "analyst", "viewer"]);
export const Range = z.enum(["1h", "24h", "7d"]);

export type Action = z.infer<typeof Action>;
export type Severity = z.infer<typeof Severity>;
export type Role = z.infer<typeof Role>;
export type Range = z.infer<typeof Range>;

export const TrafficEvent = z.object({
  ts: z.string(),
  req_id: z.string(),
  caller: z.string(),
  ip: z.string(),
  method: z.string(),
  path_template: z.string(),
  status: z.number(),
  latency_ms: z.number(),
  req_size: z.number(),
  resp_size: z.number(),
  shape_hash: z.string(),
  rule_hits: z.array(z.string()),
  action: Action,
});
export type TrafficEvent = z.infer<typeof TrafficEvent>;

export const Rule = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  match: z.object({
    path: z.string().optional(),
    method: z.string().optional(),
    ip: z.string().optional(),
    header: z.record(z.string()).optional(),
    signature: z.string().optional(),
    condition: z.string().optional(),
  }),
  action: Action,
  source: z.enum(["builtin", "scanner", "analyst", "learner"]),
  expires_at: z.string().optional(),
  hits_24h: z.number(),
});
export type Rule = z.infer<typeof Rule>;

export const Finding = z.object({
  id: z.string(),
  scan_id: z.string(),
  endpoint: z.string(),
  method: z.string(),
  owasp_cat: z.string(),
  title: z.string(),
  severity: Severity,
  risk_score: z.number().min(0).max(10),
  evidence: z.object({ request: z.string(), response: z.string() }),
  fix: z.string(),
  suggested_rule: Rule.optional(),
  status: z.enum(["open", "mitigated", "accepted", "fixed"]),
});
export type Finding = z.infer<typeof Finding>;

export const Alert = z.object({
  id: z.string(),
  ts: z.string(),
  caller: z.string(),
  endpoint: z.string(),
  score: z.number(),
  rank: z.number(),
  severity: AlertSeverity,
  reasons: z.array(
    z.object({ feature: z.string(), observed: z.string(), baseline: z.string(), z: z.number().optional() }),
  ),
  explanation: z.string(),
  status: z.enum(["new", "acknowledged", "true_positive", "false_positive"]),
  group_id: z.string().optional(),
});
export type Alert = z.infer<typeof Alert>;

export const LearningStatus = z.object({
  mode: z.enum(["warmup", "active", "disabled"]),
  progress: z.number().min(0).max(1),
  started_at: z.string(),
  ends_at: z.string().optional(),
  endpoints_learned: z.number(),
  shapes_learned: z.number().optional(), // CONTRACT-TBD: brief mentions "shape count" but it is not in the type
});
export type LearningStatus = z.infer<typeof LearningStatus>;

export const Upstream = z.object({ id: z.string(), name: z.string(), url: z.string() });
export type Upstream = z.infer<typeof Upstream>;

export const Settings = z.object({
  mode: z.enum(["monitor", "enforce"]),
  fail_open: z.boolean(),
  retention_days: z.number(),
  redaction_patterns: z.array(z.string()),
  upstreams: z.array(Upstream),
});
export type Settings = z.infer<typeof Settings>;

// ---- Shapes not fully specified in the brief (CONTRACT-TBD) ----

export const Me = z.object({
  id: z.string(),
  email: z.string(),
  name: z.string(),
  role: Role,
});
export type Me = z.infer<typeof Me>;

export const LoginResponse = z.object({ token: z.string(), user: Me });
export type LoginResponse = z.infer<typeof LoginResponse>;

export const MetricsSummary = z.object({
  range: Range,
  requests: z.number(),
  blocked: z.number(),
  allowed: z.number(),
  active_alerts: z.number(),
  p95_latency_ms: z.number(),
  risk_score: z.number().min(0).max(10), // CONTRACT-TBD: owner M2, which endpoint?
  risk_drivers: z.array(z.object({ title: z.string(), endpoint: z.string(), severity: Severity, risk_score: z.number() })),
  previous: z.object({
    requests: z.number(),
    blocked: z.number(),
    active_alerts: z.number(),
    p95_latency_ms: z.number(),
    risk_score: z.number(),
  }), // CONTRACT-TBD: previous-period values for deltas
  top_endpoints: z.array(
    z.object({ method: z.string(), path_template: z.string(), requests: z.number(), blocked: z.number(), risk_score: z.number() }),
  ),
  top_callers: z.array(z.object({ caller: z.string(), requests: z.number(), alerts: z.number() })),
});
export type MetricsSummary = z.infer<typeof MetricsSummary>;

export const TimeseriesPoint = z.object({ t: z.string(), allowed: z.number(), blocked: z.number() });
export const Timeseries = z.object({ range: Range, metric: z.string(), points: z.array(TimeseriesPoint) });
export type Timeseries = z.infer<typeof Timeseries>;

export const Paged = <T extends z.ZodTypeAny>(item: T) =>
  z.object({ items: z.array(item), total: z.number() }); // CONTRACT-TBD: pagination envelope

export const ApiError = z.object({ error: z.object({ code: z.string(), message: z.string() }) }); // CONTRACT-TBD

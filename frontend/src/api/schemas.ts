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

/** A string or a list of strings, as the gateway accepts for `match.method` and `match.ip`. */
const OneOrMany = z.union([z.string(), z.array(z.string())]);

export const Rule = z.object({
  id: z.string(),
  name: z.string(), // the gateway treats it as optional; the Admin API defaults it to the id
  enabled: z.boolean(),
  match: z.object({
    path: z.string().optional(),
    method: OneOrMany.optional(),
    ip: OneOrMany.optional(),
    header: z.record(z.string(), z.string()).optional(),
    signature: z.string().optional(),
    condition: z.string().optional(),
  }),
  action: Action,
  source: z.enum(["builtin", "scanner", "analyst", "learner"]),
  expires_at: z.string().optional(),
  priority: z.number().optional(), // lower runs first; gateway default 100
  throttle: z.object({ limit: z.number(), per: z.number() }).optional(), // only for action: throttle
  hits_24h: z.number(),
  created_at: z.string().optional(), // Admin API metadata (M1 answer to Q10)
  created_by: z.string().optional(),
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
  timeline: z.array(z.object({ ts: z.string(), count: z.number() })).optional(), // CONTRACT-TBD: M3, Q15
});
export type Alert = z.infer<typeof Alert>;

/** Response to `PATCH /alerts/:id` with status false_positive. CONTRACT-TBD: M3, Q14. */
export const AlertFeedbackResponse = z.object({
  alert: Alert,
  adjustment: z.object({ feature: z.string(), threshold_delta: z.number() }).nullable(),
});
export type AlertFeedbackResponse = z.infer<typeof AlertFeedbackResponse>;

export const LearningStatus = z.object({
  mode: z.enum(["warmup", "active", "disabled"]),
  progress: z.number().min(0).max(1),
  started_at: z.string(),
  ends_at: z.string().optional(),
  endpoints_learned: z.number(),
  shapes_learned: z.number().optional(), // CONTRACT-TBD: brief mentions "shape count" but it is not in the type
  sensitivity: z.number().min(0).max(1).optional(), // CONTRACT-TBD: M3, Q16
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

/** Same envelope as the gateway's errors. */
export const ApiError = z.object({
  error: z.object({ code: z.string(), message: z.string() }),
  request_id: z.string().optional(),
});

export const SeverityCounts = z.object({
  critical: z.number(),
  high: z.number(),
  medium: z.number(),
  low: z.number(),
  info: z.number(),
});

// CONTRACT-TBD: M2, Q12. `progress` is coarse until run_scan reports progress.
export const Scan = z.object({
  id: z.string(),
  upstream_id: z.string(),
  status: z.enum(["queued", "running", "done", "failed"]),
  progress: z.number().min(0).max(1),
  started_at: z.string(),
  finished_at: z.string().optional(),
  counts: SeverityCounts,
  api_risk_score: z.number().min(0).max(10).optional(),
  error: z.string().optional(),
});
export type Scan = z.infer<typeof Scan>;

// CONTRACT-TBD: M2, Q13. API-map inventory row.
export const EndpointInventoryItem = z.object({
  method: z.string(),
  path: z.string(),
  source: z.enum(["spec", "observed", "both"]),
  shadow: z.boolean(),
  auth_required: z.boolean(),
  rate_limited: z.boolean(),
  risk_score: z.number().min(0).max(10),
  requests_24h: z.number(),
});
export type EndpointInventoryItem = z.infer<typeof EndpointInventoryItem>;

// CONTRACT-TBD: Admin API (M4). Result of `POST /rules/test`.
export const RuleTestResult = z.object({
  matched: z.boolean(),
  action: Action.nullable(),
  explanation: z.string(),
});
export type RuleTestResult = z.infer<typeof RuleTestResult>;

// CONTRACT-TBD: Admin API (M4).
export const AuditEntry = z.object({
  id: z.string(),
  ts: z.string(),
  actor: z.string(),
  action: z.string(),
  target_type: z.string(),
  target_id: z.string().optional(),
  details: z.record(z.string(), z.unknown()),
});
export type AuditEntry = z.infer<typeof AuditEntry>;

// CONTRACT-TBD: Admin API (M4). Response to `POST /privacy/purge`.
export const PurgeResponse = z.object({ purged_at: z.string(), recent_events: z.number(), aggregate_rows: z.number() });
export type PurgeResponse = z.infer<typeof PurgeResponse>;

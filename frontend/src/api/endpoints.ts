import { z } from "zod";
import { downloadFile, openEventStream, request } from "./client";
import {
  Alert,
  AlertFeedbackResponse,
  AuditEntry,
  EndpointInventoryItem,
  Finding,
  LearningStatus,
  LoginResponse,
  Me,
  MetricsSummary,
  Paged,
  PurgeResponse,
  Rule,
  RuleTestResult,
  Scan,
  Settings,
  Timeseries,
  TrafficEvent,
  Upstream,
  type Range,
} from "./schemas";

// Every data call takes upstream_id as a query param (Admin API decision, CONTRACT_QUESTIONS.md #3).

/** Fields a client may send when creating a rule; the Admin API fills in the rest. */
export type RuleInput = Omit<Rule, "hits_24h" | "created_at" | "created_by" | "name" | "enabled" | "source"> &
  Partial<Pick<Rule, "name" | "enabled" | "source">>;

export type SampleRequest = {
  method: string;
  path: string;
  query?: Record<string, string> | string;
  headers?: Record<string, string>;
  body?: unknown;
  authenticated?: boolean;
};

export const authApi = {
  login: (email: string, password: string) =>
    request("/auth/login", { method: "POST", body: { email, password }, schema: LoginResponse }),
  me: () => request("/me", { schema: Me }),
};

export const metricsApi = {
  summary: (upstreamId: string, range: Range) =>
    request("/metrics/summary", { schema: MetricsSummary, query: { upstream_id: upstreamId, range } }),
  timeseries: (upstreamId: string, range: Range, metric = "requests") =>
    request("/metrics/timeseries", { schema: Timeseries, query: { upstream_id: upstreamId, range, metric } }),
};

export const trafficApi = {
  recent: (upstreamId: string, limit = 100) =>
    request("/traffic/recent", { schema: Paged(TrafficEvent), query: { upstream_id: upstreamId, limit } }),
  /** Live events over SSE; falls back to polling /traffic/recent if the stream fails. Returns a stop function. */
  subscribe: (upstreamId: string, onEvent: (e: TrafficEvent) => void, onModeChange?: (mode: "live" | "polling") => void) =>
    openEventStream({
      path: "/traffic/stream",
      query: { upstream_id: upstreamId },
      event: "traffic",
      schema: TrafficEvent,
      onEvent,
      onModeChange,
      poll: async () => (await trafficApi.recent(upstreamId, 50)).items.slice().reverse(),
      keyOf: (e) => e.req_id,
      pollMs: 2000,
      preferPolling: import.meta.env.VITE_USE_MOCKS === "true",
    }),
};

export const rulesApi = {
  list: (upstreamId: string) => request("/rules", { schema: Paged(Rule), query: { upstream_id: upstreamId } }),
  create: (upstreamId: string, rule: RuleInput) =>
    request("/rules", { method: "POST", body: rule, schema: Rule, query: { upstream_id: upstreamId } }),
  update: (upstreamId: string, id: string, patch: Partial<RuleInput>) =>
    request(`/rules/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: patch,
      schema: Rule,
      query: { upstream_id: upstreamId },
    }),
  remove: (upstreamId: string, id: string) =>
    request(`/rules/${encodeURIComponent(id)}`, { method: "DELETE", schema: z.null(), query: { upstream_id: upstreamId } }),
  test: (rule: Partial<RuleInput>, sample: SampleRequest) =>
    request("/rules/test", { method: "POST", body: { rule, request: sample }, schema: RuleTestResult }),
};

export const alertsApi = {
  list: (upstreamId: string, params: { status?: string; severity?: string; limit?: number } = {}) =>
    request("/alerts", { schema: Paged(Alert), query: { upstream_id: upstreamId, sort: "rank", ...params } }),
  get: (id: string) => request(`/alerts/${encodeURIComponent(id)}`, { schema: Alert }),
  setStatus: (id: string, status: Alert["status"]) =>
    request(`/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: { status }, schema: AlertFeedbackResponse }),
  promoteToRule: (upstreamId: string, id: string, body: { action?: Rule["action"]; limit?: number; per?: number } = {}) =>
    request(`/alerts/${encodeURIComponent(id)}/promote-to-rule`, {
      method: "POST",
      body,
      schema: Rule,
      query: { upstream_id: upstreamId },
    }),
};

export const learningApi = {
  status: (upstreamId: string) => request("/learning/status", { schema: LearningStatus, query: { upstream_id: upstreamId } }),
  update: (upstreamId: string, patch: { mode?: "active" | "disabled"; sensitivity?: number }) =>
    request("/learning", { method: "PATCH", body: patch, schema: LearningStatus, query: { upstream_id: upstreamId } }),
  reset: (upstreamId: string) =>
    request("/learning/reset", { method: "POST", schema: LearningStatus, query: { upstream_id: upstreamId } }),
};

export const scansApi = {
  list: (upstreamId: string) => request("/scans", { schema: Paged(Scan), query: { upstream_id: upstreamId } }),
  get: (id: string) => request(`/scans/${encodeURIComponent(id)}`, { schema: Scan }),
  start: (body: { upstream_id: string; consent: boolean; safe_mode?: boolean; spec?: string }) =>
    request("/scans", { method: "POST", body, schema: Scan }),
  findings: (id: string) => request(`/scans/${encodeURIComponent(id)}/findings`, { schema: Paged(Finding) }),
  /** For a download link; the report is fetched with the session token by the caller. */
  reportPath: (id: string, format: "json" | "html") => `/scans/${encodeURIComponent(id)}/report?format=${format}`,
  downloadReport: (id: string, format: "json" | "html") =>
    downloadFile(scansApi.reportPath(id, format), `apishield-${id}.${format}`),
  applyRule: (findingId: string) =>
    request(`/findings/${encodeURIComponent(findingId)}/apply-rule`, { method: "POST", schema: Finding }),
};

export const inventoryApi = {
  list: (upstreamId: string) =>
    request("/endpoints", { schema: Paged(EndpointInventoryItem), query: { upstream_id: upstreamId } }),
};

export const settingsApi = {
  get: () => request("/settings", { schema: Settings }),
  update: (patch: Partial<Omit<Settings, "upstreams">>) => request("/settings", { method: "PATCH", body: patch, schema: Settings }),
};

export const auditApi = {
  list: (params: { action?: string; limit?: number; offset?: number } = {}) =>
    request("/audit-log", { schema: Paged(AuditEntry), query: params }),
};

export const privacyApi = {
  purge: (upstreamId: string) =>
    request("/privacy/purge", { method: "POST", schema: PurgeResponse, query: { upstream_id: upstreamId } }),
};

export const upstreamsApi = {
  list: () => request("/upstreams", { schema: z.array(Upstream) }),
};

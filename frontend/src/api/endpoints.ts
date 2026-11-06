import { z } from "zod";
import { request } from "./client";
import {
  Alert,
  LearningStatus,
  LoginResponse,
  Me,
  MetricsSummary,
  Paged,
  Settings,
  Timeseries,
  Upstream,
  type Range,
} from "./schemas";

// Every call takes upstream_id as a query param. CONTRACT-TBD: confirm with backend.

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

export const alertsApi = {
  list: (upstreamId: string, params: { status?: string; severity?: string; limit?: number } = {}) =>
    request("/alerts", { schema: Paged(Alert), query: { upstream_id: upstreamId, sort: "rank", ...params } }),
};

export const learningApi = {
  status: (upstreamId: string) => request("/learning/status", { schema: LearningStatus, query: { upstream_id: upstreamId } }),
};

export const settingsApi = {
  get: () => request("/settings", { schema: Settings }),
};

export const upstreamsApi = {
  list: () => request("/upstreams", { schema: z.array(Upstream) }),
};

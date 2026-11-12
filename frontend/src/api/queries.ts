import { useQuery } from "@tanstack/react-query";
import {
  alertsApi,
  auditApi,
  inventoryApi,
  learningApi,
  metricsApi,
  rulesApi,
  scansApi,
  settingsApi,
  trafficApi,
  upstreamsApi,
} from "./endpoints";
import type { Range } from "./schemas";

export const qk = {
  me: ["me"] as const,
  upstreams: ["upstreams"] as const,
  settings: ["settings"] as const,
  summary: (u: string, r: Range) => ["metrics", "summary", u, r] as const,
  timeseries: (u: string, r: Range) => ["metrics", "timeseries", u, r] as const,
  alerts: (u: string, p: object) => ["alerts", u, p] as const,
  learning: (u: string) => ["learning", "status", u] as const,
  alert: (id: string) => ["alerts", "detail", id] as const,
  traffic: (u: string) => ["traffic", "recent", u] as const,
  rules: (u: string) => ["rules", u] as const,
  scans: (u: string) => ["scans", u] as const,
  scan: (id: string) => ["scans", "detail", id] as const,
  findings: (scanId: string) => ["scans", "findings", scanId] as const,
  inventory: (u: string) => ["endpoints", u] as const,
  audit: (p: object) => ["audit", p] as const,
};

export const useUpstreams = () => useQuery({ queryKey: qk.upstreams, queryFn: upstreamsApi.list });

export const useSettings = () => useQuery({ queryKey: qk.settings, queryFn: settingsApi.get });

export const useSummary = (upstreamId: string | undefined, range: Range) =>
  useQuery({
    queryKey: qk.summary(upstreamId ?? "", range),
    queryFn: () => metricsApi.summary(upstreamId!, range),
    enabled: !!upstreamId,
    refetchInterval: 15_000,
  });

export const useTimeseries = (upstreamId: string | undefined, range: Range) =>
  useQuery({
    queryKey: qk.timeseries(upstreamId ?? "", range),
    queryFn: () => metricsApi.timeseries(upstreamId!, range),
    enabled: !!upstreamId,
    refetchInterval: 15_000,
  });

export const useAlerts = (upstreamId: string | undefined, params: { status?: string; limit?: number } = {}) =>
  useQuery({
    queryKey: qk.alerts(upstreamId ?? "", params),
    queryFn: () => alertsApi.list(upstreamId!, params),
    enabled: !!upstreamId,
    refetchInterval: 10_000,
  });

export const useLearningStatus = (upstreamId: string | undefined) =>
  useQuery({
    queryKey: qk.learning(upstreamId ?? ""),
    queryFn: () => learningApi.status(upstreamId!),
    enabled: !!upstreamId,
    refetchInterval: 30_000,
  });

export const useAlert = (id: string | undefined) =>
  useQuery({ queryKey: qk.alert(id ?? ""), queryFn: () => alertsApi.get(id!), enabled: !!id });

export const useRecentTraffic = (upstreamId: string | undefined, limit = 100) =>
  useQuery({
    queryKey: qk.traffic(upstreamId ?? ""),
    queryFn: () => trafficApi.recent(upstreamId!, limit),
    enabled: !!upstreamId,
  });

export const useRules = (upstreamId: string | undefined) =>
  useQuery({ queryKey: qk.rules(upstreamId ?? ""), queryFn: () => rulesApi.list(upstreamId!), enabled: !!upstreamId });

export const useScans = (upstreamId: string | undefined) =>
  useQuery({ queryKey: qk.scans(upstreamId ?? ""), queryFn: () => scansApi.list(upstreamId!), enabled: !!upstreamId });

/** Polls while the scan is queued or running. */
export const useScan = (id: string | undefined) =>
  useQuery({
    queryKey: qk.scan(id ?? ""),
    queryFn: () => scansApi.get(id!),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data && ["queued", "running"].includes(q.state.data.status) ? 1500 : false),
  });

export const useFindings = (scanId: string | undefined) =>
  useQuery({ queryKey: qk.findings(scanId ?? ""), queryFn: () => scansApi.findings(scanId!), enabled: !!scanId });

export const useEndpointInventory = (upstreamId: string | undefined) =>
  useQuery({ queryKey: qk.inventory(upstreamId ?? ""), queryFn: () => inventoryApi.list(upstreamId!), enabled: !!upstreamId });

export const useAuditLog = (params: { action?: string; limit?: number; offset?: number } = {}) =>
  useQuery({ queryKey: qk.audit(params), queryFn: () => auditApi.list(params) });

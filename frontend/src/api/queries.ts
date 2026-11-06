import { useQuery } from "@tanstack/react-query";
import { alertsApi, learningApi, metricsApi, settingsApi, upstreamsApi } from "./endpoints";
import type { Range } from "./schemas";

export const qk = {
  me: ["me"] as const,
  upstreams: ["upstreams"] as const,
  settings: ["settings"] as const,
  summary: (u: string, r: Range) => ["metrics", "summary", u, r] as const,
  timeseries: (u: string, r: Range) => ["metrics", "timeseries", u, r] as const,
  alerts: (u: string, p: object) => ["alerts", u, p] as const,
  learning: (u: string) => ["learning", "status", u] as const,
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

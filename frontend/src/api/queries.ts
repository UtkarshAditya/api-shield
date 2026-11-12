import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
  type RuleInput,
} from "./endpoints";
import type { Alert, Range, Rule, Settings } from "./schemas";

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

export const useAuditLog = (params: { action?: string; limit?: number; offset?: number } = {}, enabled = true) =>
  useQuery({ queryKey: qk.audit(params), queryFn: () => auditApi.list(params), enabled });

// ---- Mutations. Each one refreshes what it changes, so screens stay consistent. ----

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (patch: Partial<Omit<Settings, "upstreams">>) => settingsApi.update(patch),
    onSuccess: (settings) => {
      qc.setQueryData(qk.settings, settings);
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
  });
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: scansApi.start,
    onSuccess: (scan) => {
      qc.setQueryData(qk.scan(scan.id), scan);
      void qc.invalidateQueries({ queryKey: qk.scans(scan.upstream_id) });
    },
  });
}

export function useApplyRule(upstreamId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (findingId: string) => scansApi.applyRule(findingId),
    onSuccess: (finding) => {
      void qc.invalidateQueries({ queryKey: qk.findings(finding.scan_id) });
      void qc.invalidateQueries({ queryKey: qk.rules(upstreamId ?? "") });
      void qc.invalidateQueries({ queryKey: ["metrics"] });
      void qc.invalidateQueries({ queryKey: ["endpoints"] });
    },
  });
}

export function useRuleMutations(upstreamId: string | undefined) {
  const qc = useQueryClient();
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.rules(upstreamId ?? "") });
    void qc.invalidateQueries({ queryKey: ["endpoints"] });
  };
  return {
    create: useMutation({ mutationFn: (rule: RuleInput) => rulesApi.create(upstreamId!, rule), onSuccess: refresh }),
    update: useMutation({
      mutationFn: ({ id, patch }: { id: string; patch: Partial<RuleInput> }) => rulesApi.update(upstreamId!, id, patch),
      onSuccess: refresh,
    }),
    remove: useMutation({ mutationFn: (id: string) => rulesApi.remove(upstreamId!, id), onSuccess: refresh }),
  };
}

export function useAlertStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: Alert["status"] }) => alertsApi.setStatus(id, status),
    onSuccess: (res) => {
      qc.setQueryData(qk.alert(res.alert.id), res.alert);
      void qc.invalidateQueries({ queryKey: ["alerts"] });
      void qc.invalidateQueries({ queryKey: ["metrics", "summary"] });
    },
  });
}

export function usePromoteAlert(upstreamId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, action }: { id: string; action: Rule["action"] }) =>
      alertsApi.promoteToRule(upstreamId!, id, action === "throttle" ? { action, limit: 10, per: 60 } : { action }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.rules(upstreamId ?? "") }),
  });
}

export function useLearningMutations(upstreamId: string | undefined) {
  const qc = useQueryClient();
  const set = (status: Awaited<ReturnType<typeof learningApi.status>>) => {
    qc.setQueryData(qk.learning(upstreamId ?? ""), status);
    void qc.invalidateQueries({ queryKey: ["audit"] });
  };
  return {
    update: useMutation({
      mutationFn: (patch: { mode?: "active" | "disabled"; sensitivity?: number }) => learningApi.update(upstreamId!, patch),
      onSuccess: set,
    }),
    reset: useMutation({ mutationFn: () => learningApi.reset(upstreamId!), onSuccess: set }),
  };
}

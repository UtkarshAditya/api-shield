import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ChevronRight, Download, Play } from "lucide-react";
import { qk, useApplyRule, useFindings, useScan, useScans, useStartScan } from "@/api/queries";
import { scansApi } from "@/api/endpoints";
import type { Finding, Scan, Severity } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { ActionTag, actionMeaning, matchSummary } from "@/components/domain/ActionBadge";
import { EmptyState } from "@/components/domain/EmptyState";
import { SegmentBar } from "@/components/domain/RiskGauge";
import { SeverityMark, severityEdge, severityForScore } from "@/components/domain/SeverityBadge";
import { Term } from "@/components/domain/Term";
import { Button } from "@/components/ui/Button";
import { CardError } from "@/components/ui/Card";
import { InlineError, Modal } from "@/components/ui/Dialog";
import { Markdown } from "@/components/ui/Markdown";
import { PageHeader, StatusDot } from "@/components/ui/Primitives";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { Tooltip } from "@/components/ui/Tooltip";
import { describeError } from "@/lib/errors";
import { cn } from "@/lib/cn";
import { formatRelative } from "@/lib/format";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

// ---- New scan wizard ---------------------------------------------------------------

function NewScanWizard({ open, onOpenChange, onStarted }: { open: boolean; onOpenChange: (v: boolean) => void; onStarted: (s: Scan) => void }) {
  const { upstreams, upstream } = useWorkspace();
  const [step, setStep] = useState<1 | 2>(1);
  const [target, setTarget] = useState<string | undefined>(upstream?.id);
  const [consent, setConsent] = useState(false);
  const start = useStartScan();
  const chosen = upstreams.find((u) => u.id === (target ?? upstream?.id));

  useEffect(() => {
    if (open) {
      setStep(1);
      setConsent(false);
      setTarget(upstream?.id);
      start.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const submit = async () => {
    if (!chosen) return;
    const scan = await start.mutateAsync({ upstream_id: chosen.id, consent: true, safe_mode: true }).catch(() => null);
    if (scan) {
      onOpenChange(false);
      onStarted(scan);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={(v) => !start.isPending && onOpenChange(v)}
      title={`New scan · step ${step} of 2`}
      description={step === 1 ? "Choose the API to probe for OWASP API Top 10 weaknesses." : "Scans send real test requests. Confirm you are allowed to do that."}
      footer={
        step === 1 ? (
          <>
            <Button variant="secondary" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button onClick={() => setStep(2)} disabled={!chosen}>
              Next
            </Button>
          </>
        ) : (
          <>
            <Button variant="secondary" onClick={() => setStep(1)} disabled={start.isPending}>
              Back
            </Button>
            <Button onClick={submit} disabled={!consent || start.isPending}>
              <Play className="size-3.5" aria-hidden /> {start.isPending ? "Starting…" : "Start scan"}
            </Button>
          </>
        )
      }
    >
      {step === 1 ? (
        <div className="space-y-4">
          <label className="block text-sm">
            <span className="eyebrow mb-1 block">Target API</span>
            <select value={chosen?.id ?? ""} onChange={(e) => setTarget(e.target.value)} className="h-8 w-full rounded-sm border border-border-strong bg-surface px-2 text-sm">
              {upstreams.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.name}
                </option>
              ))}
            </select>
            {chosen && <span className="mt-1 block font-mono text-xs text-muted">{chosen.url}</span>}
          </label>
          <div className="flex items-start justify-between gap-4 border-y border-border py-3">
            <div>
              <p className="text-sm font-medium">Safe mode</p>
              <p className="text-xs leading-relaxed text-muted">Read-only, low-volume probes. Nothing is written or deleted. This scanner version always runs in safe mode.</p>
            </div>
            <Switch checked onCheckedChange={() => undefined} disabled label="Safe mode (always on)" />
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm">
            The scanner sends test requests, including injection payloads, to <span className="font-mono text-xs">{chosen?.url}</span>. It talks to the API directly, not
            through the gateway.
          </p>
          <label className="flex items-start gap-2 border-y border-border py-3 text-sm">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-0.5 size-4 accent-[var(--text)]" />
            <span>I own this API, or have written permission to test it, and I agree to scan it now.</span>
          </label>
          {start.isError && <InlineError message={describeError(start.error)} />}
        </div>
      )}
    </Modal>
  );
}

// ---- Scan list ---------------------------------------------------------------------

function ScanStatus({ status }: { status: Scan["status"] }) {
  if (status === "done") return <StatusDot tone="ok">done</StatusDot>;
  if (status === "failed") return <StatusDot tone="signal">failed</StatusDot>;
  return <StatusDot tone="ink">{status}</StatusDot>;
}

function ScanList({ scans, selected, onSelect }: { scans: Scan[]; selected?: string; onSelect: (id: string) => void }) {
  return (
    <ul aria-label="Scans" className="border-t border-border">
      {scans.map((s) => {
        const total = SEVERITIES.reduce((n, k) => n + s.counts[k], 0);
        const active = s.id === selected;
        return (
          <li key={s.id} className="border-b border-border">
            <button
              type="button"
              onClick={() => onSelect(s.id)}
              aria-current={active ? "true" : undefined}
              className={cn("w-full py-2.5 pr-2 pl-3 text-left transition-colors ease-ui hover:bg-surface-2", active && "bg-surface-2 shadow-[inset_2px_0_0_var(--text)]")}
            >
              <span className="flex items-center gap-2">
                <ScanStatus status={s.status} />
                <span className="ml-auto font-mono text-[11px] text-muted">{formatRelative(s.started_at)}</span>
              </span>
              <span className="mt-1 flex items-baseline gap-3 font-mono text-[11px] text-muted">
                <span>{s.id}</span>
                {s.status === "done" && <span>{total} findings</span>}
                {s.api_risk_score !== undefined && <span className="ml-auto text-[13px] text-fg">{s.api_risk_score.toFixed(1)}</span>}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

// ---- Findings ----------------------------------------------------------------------

function FindingRow({ finding }: { finding: Finding }) {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const apply = useApplyRule(upstreamId);
  const rule = finding.suggested_rule;
  const panelId = `finding-${finding.id}`;
  const appliedOpen = apply.isSuccess && apply.data.status === "open";

  return (
    <li className="border-b border-border/70 last:border-b-0">
      <div className="flex h-10 items-center gap-3 pr-1" style={severityEdge(finding.severity)}>
        <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open} aria-controls={panelId} className="flex min-w-0 flex-1 items-center gap-3 pl-3 text-left text-sm">
          <ChevronRight className={cn("size-3.5 shrink-0 text-muted transition-transform ease-ui", open && "rotate-90")} aria-hidden />
          <span className="w-20 shrink-0">
            <SeverityMark severity={finding.severity} />
          </span>
          <span className="truncate">{finding.title}</span>
        </button>
        <Term
          tip={`Risk ${finding.risk_score.toFixed(1)} of 10 (${severityForScore(finding.risk_score)}) weighs how bad this weakness is (${finding.owasp_cat}) by how exposed the endpoint is. A fix or a mitigating rule lowers the API's overall score.`}
        >
          <span className="font-mono text-[13px]">{finding.risk_score.toFixed(1)}</span>
        </Term>
        <span className={cn("w-24 text-right font-mono text-[11px] tracking-wider uppercase", finding.status === "mitigated" ? "text-ok" : "text-muted")}>{finding.status}</span>
      </div>
      {open && (
        <div id={panelId} className="space-y-4 border-t border-border/70 bg-bg px-4 pt-3 pb-4 sm:pl-12">
          <p className="font-mono text-xs text-muted">{finding.owasp_cat}</p>
          <div>
            <h4 className="eyebrow mb-1 text-fg">
              <Term tip="Secrets, tokens, emails and IPs were masked before the evidence was stored. You see the shape of what happened, not the contents.">Evidence</Term>
            </h4>
            <dl className="grid gap-1 border-y border-border py-2 font-mono text-xs">
              <div className="flex gap-2">
                <dt className="w-16 shrink-0 text-muted">request</dt>
                <dd className="break-all">{finding.evidence.request}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-16 shrink-0 text-muted">response</dt>
                <dd className="break-all">{finding.evidence.response}</dd>
              </div>
            </dl>
          </div>
          {finding.fix && (
            <div>
              <h4 className="eyebrow mb-1 text-fg">How to fix it in your code</h4>
              <Markdown text={finding.fix} />
            </div>
          )}
          {rule ? (
            <div className="border-l-2 border-fg pl-3">
              <div className="flex flex-wrap items-center gap-3">
                <h4 className="eyebrow text-fg">Suggested gateway rule</h4>
                <Term tip={`Until the code is fixed, this rule ${actionMeaning[rule.action]} for ${matchSummary(rule.match).join(", ")}.`}>
                  <ActionTag action={rule.action} />
                </Term>
              </div>
              <p className="mt-1 font-mono text-xs text-muted">{matchSummary(rule.match).join(" · ")}</p>
              {rule.throttle && (
                <p className="mt-0.5 font-mono text-xs text-muted">
                  limit {rule.throttle.limit} requests per {rule.throttle.per} s per caller
                </p>
              )}
              <div className="mt-3 flex flex-wrap items-center gap-3">
                {finding.status === "mitigated" ? (
                  <p className="text-sm">
                    Mitigated by rule{" "}
                    <Link to={`/app/rules?highlight=${encodeURIComponent(rule.id)}`} className="link font-mono text-xs">
                      {rule.id}
                    </Link>
                  </p>
                ) : can("rules.edit") ? (
                  <Button size="sm" onClick={() => apply.mutate(finding.id)} disabled={apply.isPending}>
                    {apply.isPending ? "Applying…" : "Apply suggested rule"}
                  </Button>
                ) : (
                  <p className="text-xs text-muted">Only admins and analysts can apply rules.</p>
                )}
                {appliedOpen && (
                  <p role="status" className="text-xs text-muted">
                    Rule pushed. It only logs, so the finding stays open until the code is fixed.
                  </p>
                )}
              </div>
              {apply.isError && <InlineError message={describeError(apply.error)} />}
            </div>
          ) : (
            <p className="text-xs text-muted">No gateway rule can stop this one; it needs a code or configuration fix.</p>
          )}
        </div>
      )}
    </li>
  );
}

function Findings({ scanId }: { scanId: string }) {
  const findings = useFindings(scanId);
  const groups = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings.data?.items ?? []) {
      const key = `${f.method} ${f.endpoint}`;
      map.set(key, [...(map.get(key) ?? []), f]);
    }
    return [...map.entries()].map(([endpoint, items]) => ({ endpoint, items, risk: Math.max(...items.map((f) => f.risk_score)) })).sort((a, b) => b.risk - a.risk);
  }, [findings.data]);

  if (findings.isError) return <CardError onRetry={() => findings.refetch()} />;
  if (!findings.data) return <Skeleton className="h-40" />;
  if (groups.length === 0) return <p className="py-6 font-mono text-sm text-muted">0 findings in this scan.</p>;

  return (
    <div className="space-y-5">
      {groups.map((g) => (
        <section key={g.endpoint} aria-label={`Findings for ${g.endpoint}`}>
          <header className="flex items-baseline gap-3 border-b border-fg pb-1.5">
            <h3 className="font-mono text-[13px] font-medium">{g.endpoint}</h3>
            <span className="font-mono text-[11px] text-muted">
              {g.items.length} finding{g.items.length === 1 ? "" : "s"}
            </span>
            <span className="ml-auto flex items-baseline gap-2">
              <span className="font-mono text-[13px]">{g.risk.toFixed(1)}</span>
              <SeverityMark severity={severityForScore(g.risk)} />
            </span>
          </header>
          <ul>
            {g.items.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

function ScanDetail({ scanId }: { scanId: string }) {
  const { upstreamId } = useWorkspace();
  const qc = useQueryClient();
  const scan = useScan(scanId);
  const [exportError, setExportError] = useState<string | null>(null);
  const status = scan.data?.status;

  // When a scan finishes, refresh the list, the risk score and the API map.
  useEffect(() => {
    if (status === "done" || status === "failed") {
      void qc.invalidateQueries({ queryKey: qk.scans(upstreamId ?? "") });
      void qc.invalidateQueries({ queryKey: ["metrics"] });
      void qc.invalidateQueries({ queryKey: ["endpoints"] });
    }
  }, [status, qc, upstreamId]);

  if (scan.isError) return <CardError onRetry={() => scan.refetch()} />;
  const s = scan.data;
  if (!s) return <Skeleton className="h-60" />;

  const exportReport = async (format: "json" | "html") => {
    setExportError(null);
    try {
      await scansApi.downloadReport(s.id, format);
    } catch (err) {
      setExportError(describeError(err));
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center gap-3 border-b border-border pb-2">
        <span className="eyebrow">Scan</span>
        <span className="font-mono text-[13px]">{s.id}</span>
        {s.finished_at && <span className="font-mono text-xs text-muted">finished {formatRelative(s.finished_at)}</span>}
        {s.status === "done" && (
          <span className="ml-auto flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => exportReport("json")}>
              <Download className="size-3.5" aria-hidden /> JSON
            </Button>
            <Button size="sm" variant="secondary" onClick={() => exportReport("html")}>
              <Download className="size-3.5" aria-hidden /> HTML report
            </Button>
          </span>
        )}
      </header>
      {exportError && <InlineError message={exportError} />}

      {s.status === "queued" || s.status === "running" ? (
        <div className="space-y-2">
          <p className="text-sm">{s.status === "queued" ? "Waiting to start." : "Scanning in safe mode: read-only probes against each endpoint."}</p>
          <div role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(s.progress * 100)} className="h-1.5 bg-surface-2">
            <div className="h-full bg-fg transition-[width] duration-500" style={{ width: `${Math.max(5, s.progress * 100)}%` }} />
          </div>
          <p className="font-mono text-xs text-muted">started {formatRelative(s.started_at)} · updates by itself</p>
        </div>
      ) : s.status === "failed" ? (
        <InlineError message={`The scan failed: ${s.error ?? "unknown error"}`} />
      ) : (
        <div className="grid gap-6 sm:grid-cols-[minmax(0,320px)_1fr]">
          {s.api_risk_score !== undefined && (
            <div className="space-y-3">
              <p className="eyebrow">
                <Term tip="The scanner scores each endpoint from its findings (severity and exposure) and reports the API's overall risk. Mitigated findings lower the live score on the Overview.">
                  API risk
                </Term>
              </p>
              <div className="flex items-baseline gap-3">
                <span className="font-mono text-[56px] leading-none font-medium tracking-tight">{s.api_risk_score.toFixed(1)}</span>
                <span className="font-mono text-sm text-muted">/ 10</span>
                <SeverityMark severity={severityForScore(s.api_risk_score)} className="ml-auto" />
              </div>
              <SegmentBar value={s.api_risk_score} color={`var(--sev-${severityForScore(s.api_risk_score)})`} label={`API risk ${s.api_risk_score.toFixed(1)} of 10`} />
            </div>
          )}
          <div>
            <p className="eyebrow mb-2">Findings by severity</p>
            <ul className="grid grid-cols-5 border-y border-border" aria-label="Findings by severity">
              {SEVERITIES.map((k) => (
                <li key={k} className="border-l border-border px-3 py-2 first:border-l-0 first:pl-0">
                  <span className={cn("block font-mono text-2xl", s.counts[k] === 0 && "text-muted")}>{s.counts[k]}</span>
                  <SeverityMark severity={k} />
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
      {s.status === "done" && <Findings scanId={s.id} />}
    </div>
  );
}

export default function ScansPage() {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const scans = useScans(upstreamId);
  const [params, setParams] = useSearchParams();
  const [wizard, setWizard] = useState(false);
  const items = scans.data?.items ?? [];
  const selected = params.get("scan") ?? items[0]?.id;
  const select = (id: string) => setParams({ scan: id }, { replace: true });

  const newScan = can("scans.run") ? (
    <Button onClick={() => setWizard(true)}>New scan</Button>
  ) : (
    <Tooltip content="Only admins and analysts can start scans.">
      <span tabIndex={0}>
        <Button disabled>New scan</Button>
      </span>
    </Tooltip>
  );

  return (
    <div className="space-y-6">
      <PageHeader title="Scans & reports" description="Probe the API for OWASP API Top 10 weaknesses, then turn the fixes into gateway rules." actions={newScan} />

      {scans.isError ? (
        <CardError onRetry={() => scans.refetch()} />
      ) : scans.isLoading ? (
        <Skeleton className="h-80" />
      ) : items.length === 0 ? (
        <div className="border-y border-border">
          <EmptyState title="0 scans" body="Run a scan to find weaknesses such as SQL injection or a login with no rate limit." action={newScan} />
        </div>
      ) : (
        <div className="grid gap-x-10 gap-y-6 lg:grid-cols-[260px_minmax(0,1fr)]">
          <section className="self-start">
            <h2 className="eyebrow mb-2 text-fg">History</h2>
            <ScanList scans={items} selected={selected} onSelect={select} />
          </section>
          <div className="min-w-0">{selected && <ScanDetail key={selected} scanId={selected} />}</div>
        </div>
      )}

      <NewScanWizard open={wizard} onOpenChange={setWizard} onStarted={(s) => select(s.id)} />
    </div>
  );
}

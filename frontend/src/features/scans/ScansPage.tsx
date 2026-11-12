import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, ChevronDown, ChevronRight, Download, Loader2, Play, ScanSearch, ShieldCheck, XCircle } from "lucide-react";
import { qk, useApplyRule, useFindings, useScan, useScans, useStartScan } from "@/api/queries";
import { scansApi } from "@/api/endpoints";
import type { Finding, Scan, Severity } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { ActionBadge, actionMeaning, matchSummary } from "@/components/domain/ActionBadge";
import { EmptyState } from "@/components/domain/EmptyState";
import { SeverityBadge, severityForScore } from "@/components/domain/SeverityBadge";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Button } from "@/components/ui/Button";
import { Card, CardError, CardHeader } from "@/components/ui/Card";
import { InlineError, Modal } from "@/components/ui/Dialog";
import { Markdown } from "@/components/ui/Markdown";
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
            <span className="mb-1 block font-medium">Target API</span>
            <select
              value={chosen?.id ?? ""}
              onChange={(e) => setTarget(e.target.value)}
              className="h-9 w-full rounded-md border border-border bg-surface-2 px-2 text-sm"
            >
              {upstreams.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.name}
                </option>
              ))}
            </select>
            {chosen && <span className="mt-1 block font-mono text-xs text-muted">{chosen.url}</span>}
          </label>
          <div className="flex items-start justify-between gap-4 rounded-lg border border-border bg-surface-2 p-3">
            <div>
              <p className="text-sm font-medium">Safe mode</p>
              <p className="text-xs leading-relaxed text-muted">
                Read-only, low-volume probes. Nothing is written or deleted. This version of the scanner always runs in safe mode.
              </p>
            </div>
            <Switch checked onCheckedChange={() => undefined} disabled label="Safe mode (always on)" />
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm">
            The scanner will send test requests, including injection payloads, to{" "}
            <span className="font-mono text-xs">{chosen?.url}</span>. It talks to the API directly, not through the gateway.
          </p>
          <label className="flex items-start gap-2 rounded-lg border border-border bg-surface-2 p-3 text-sm">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} className="mt-0.5 size-4 accent-[var(--accent)]" />
            <span>I own this API, or have written permission to test it, and I agree to scan it now.</span>
          </label>
          {start.isError && <InlineError message={describeError(start.error)} />}
        </div>
      )}
    </Modal>
  );
}

// ---- Scan list ---------------------------------------------------------------------

function StatusIcon({ status }: { status: Scan["status"] }) {
  if (status === "done") return <CheckCircle2 className="size-4 text-act-allow" aria-hidden />;
  if (status === "failed") return <XCircle className="size-4 text-sev-critical" aria-hidden />;
  return <Loader2 className="size-4 animate-spin text-accent" aria-hidden />;
}

function ScanList({ scans, selected, onSelect }: { scans: Scan[]; selected?: string; onSelect: (id: string) => void }) {
  return (
    <ul className="space-y-1 px-2 pb-3" aria-label="Scans">
      {scans.map((s) => {
        const total = SEVERITIES.reduce((n, k) => n + s.counts[k], 0);
        return (
          <li key={s.id}>
            <button
              type="button"
              onClick={() => onSelect(s.id)}
              aria-current={s.id === selected ? "true" : undefined}
              className={cn(
                "w-full rounded-lg px-3 py-2 text-left hover:bg-surface-2",
                s.id === selected && "bg-accent-soft hover:bg-accent-soft",
              )}
            >
              <span className="flex items-center gap-2 text-sm">
                <StatusIcon status={s.status} />
                <span className="font-medium capitalize">{s.status}</span>
                <span className="ml-auto text-[11px] text-muted">{formatRelative(s.started_at)}</span>
              </span>
              <span className="mt-0.5 block font-mono text-[11px] text-muted">
                {s.id}
                {s.status === "done" && ` · ${total} findings`}
                {s.api_risk_score !== undefined && ` · risk ${s.api_risk_score.toFixed(1)}`}
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
    <li className="border-t border-border/60 first:border-t-0">
      <div className="flex flex-wrap items-center gap-2 px-4 py-2.5">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={panelId}
          className="flex min-w-0 flex-1 items-center gap-2 text-left text-sm"
        >
          {open ? <ChevronDown className="size-4 shrink-0 text-muted" aria-hidden /> : <ChevronRight className="size-4 shrink-0 text-muted" aria-hidden />}
          <SeverityBadge severity={finding.severity} />
          <span className="truncate">{finding.title}</span>
        </button>
        <span className="inline-flex items-center gap-1 text-xs text-muted tabular-nums">
          risk {finding.risk_score.toFixed(1)}
          <WhyTooltip label={`Why is the risk ${finding.risk_score.toFixed(1)}?`}>
            Risk {finding.risk_score.toFixed(1)} of 10 ({severityForScore(finding.risk_score)}) weighs how bad this weakness is ({finding.owasp_cat}) by how
            exposed the endpoint is. Applying a fix or a mitigating rule lowers the API's overall score.
          </WhyTooltip>
        </span>
        {finding.status === "mitigated" ? (
          <span className="inline-flex items-center gap-1 rounded-full border border-act-allow/30 bg-act-allow/12 px-2 py-0.5 text-xs font-medium text-act-allow">
            <ShieldCheck className="size-3" aria-hidden /> Mitigated
          </span>
        ) : (
          <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted capitalize">{finding.status}</span>
        )}
      </div>
      {open && (
        <div id={panelId} className="space-y-4 bg-surface-2/40 px-4 pt-1 pb-4 sm:pl-10">
          <p className="text-xs text-muted">{finding.owasp_cat}</p>
          <div>
            <h4 className="mb-1 flex items-center gap-1 text-xs font-semibold text-muted">
              Evidence
              <WhyTooltip label="About this evidence">
                Secrets, tokens, emails and IPs were masked before the evidence was stored. You see the shape of what happened, not the contents.
              </WhyTooltip>
            </h4>
            <dl className="grid gap-1 rounded-md border border-border bg-surface p-3 font-mono text-xs">
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
              <h4 className="mb-1 text-xs font-semibold text-muted">How to fix it in your code</h4>
              <Markdown text={finding.fix} />
            </div>
          )}
          {rule ? (
            <div className="rounded-lg border border-border bg-surface p-3">
              <div className="flex flex-wrap items-center gap-2">
                <h4 className="text-xs font-semibold text-muted">Suggested gateway rule</h4>
                <ActionBadge action={rule.action} />
                <WhyTooltip label="What would this rule do?">
                  Until the code is fixed, this rule {actionMeaning[rule.action]} for {matchSummary(rule.match).join(", ")}.
                </WhyTooltip>
              </div>
              <p className="mt-1 font-mono text-xs text-muted">{matchSummary(rule.match).join(" · ")}</p>
              {rule.throttle && (
                <p className="mt-0.5 text-xs text-muted">
                  Limit: {rule.throttle.limit} requests per {rule.throttle.per} s per caller
                </p>
              )}
              <div className="mt-3 flex flex-wrap items-center gap-3">
                {finding.status === "mitigated" ? (
                  <p className="text-sm">
                    Mitigated by rule{" "}
                    <Link to={`/app/rules?highlight=${encodeURIComponent(rule.id)}`} className="font-mono text-xs text-accent hover:underline">
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
    return [...map.entries()]
      .map(([endpoint, items]) => ({ endpoint, items, risk: Math.max(...items.map((f) => f.risk_score)) }))
      .sort((a, b) => b.risk - a.risk);
  }, [findings.data]);

  if (findings.isError) return <CardError onRetry={() => findings.refetch()} />;
  if (!findings.data) return <Skeleton className="mx-4 h-40" />;
  if (groups.length === 0) return <p className="px-5 py-8 text-center text-sm text-muted">No findings. This scan found nothing to fix.</p>;

  return (
    <div className="space-y-3 px-4 pb-4">
      {groups.map((g) => (
        <section key={g.endpoint} className="overflow-hidden rounded-lg border border-border" aria-label={`Findings for ${g.endpoint}`}>
          <header className="flex items-center gap-2 bg-surface-2 px-4 py-2">
            <h3 className="font-mono text-xs font-semibold">{g.endpoint}</h3>
            <span className="text-xs text-muted">
              {g.items.length} finding{g.items.length === 1 ? "" : "s"}
            </span>
            <SeverityBadge severity={severityForScore(g.risk)} className="ml-auto" />
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
  if (!s) return <Skeleton className="m-5 h-60" />;

  const exportReport = async (format: "json" | "html") => {
    setExportError(null);
    try {
      await scansApi.downloadReport(s.id, format);
    } catch (err) {
      setExportError(describeError(err));
    }
  };

  return (
    <>
      <CardHeader
        title={<span className="font-mono">{s.id}</span>}
        action={
          s.status === "done" && (
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" onClick={() => exportReport("json")}>
                <Download className="size-3.5" aria-hidden /> JSON
              </Button>
              <Button size="sm" variant="secondary" onClick={() => exportReport("html")}>
                <Download className="size-3.5" aria-hidden /> HTML report
              </Button>
            </div>
          )
        }
      />
      {exportError && (
        <div className="px-5">
          <InlineError message={exportError} />
        </div>
      )}
      <div className="px-5 pb-4">
        {s.status === "queued" || s.status === "running" ? (
          <div className="space-y-2 py-6">
            <p className="text-sm">{s.status === "queued" ? "Waiting to start…" : "Scanning in safe mode: read-only probes against each endpoint…"}</p>
            <div
              role="progressbar"
              aria-label="Scan progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(s.progress * 100)}
              className="h-2 overflow-hidden rounded-full bg-surface-2"
            >
              <div className="h-full rounded-full bg-accent transition-[width] duration-500" style={{ width: `${Math.max(5, s.progress * 100)}%` }} />
            </div>
            <p className="text-xs text-muted">Started {formatRelative(s.started_at)}. This page updates by itself.</p>
          </div>
        ) : s.status === "failed" ? (
          <InlineError message={`The scan failed: ${s.error ?? "unknown error"}`} />
        ) : (
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            {s.api_risk_score !== undefined && (
              <div className="flex items-center gap-2">
                <span className="text-2xl font-semibold tabular-nums">{s.api_risk_score.toFixed(1)}</span>
                <span className="text-xs text-muted">/ 10 API risk</span>
                <SeverityBadge severity={severityForScore(s.api_risk_score)} />
                <WhyTooltip label="How is the API risk computed?">
                  The scanner scores each endpoint from its findings (severity and how exposed the endpoint is) and reports the API's overall risk.
                  Mitigated findings lower the live score on the Overview.
                </WhyTooltip>
              </div>
            )}
            <ul className="flex flex-wrap gap-2" aria-label="Findings by severity">
              {SEVERITIES.filter((k) => s.counts[k] > 0).map((k) => (
                <li key={k} className="flex items-center gap-1 text-sm tabular-nums">
                  <SeverityBadge severity={k} /> {s.counts[k]}
                </li>
              ))}
            </ul>
            {s.finished_at && <span className="text-xs text-muted">Finished {formatRelative(s.finished_at)}</span>}
          </div>
        )}
      </div>
      {s.status === "done" && <Findings scanId={s.id} />}
    </>
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
    <Button onClick={() => setWizard(true)}>
      <ScanSearch className="size-4" aria-hidden /> New scan
    </Button>
  ) : (
    <Tooltip content="Only admins and analysts can start scans.">
      <span tabIndex={0}>
        <Button disabled>
          <ScanSearch className="size-4" aria-hidden /> New scan
        </Button>
      </span>
    </Tooltip>
  );

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Scans & reports</h1>
          <p className="text-sm text-muted">Probe your API for OWASP API Top 10 weaknesses, then turn the fixes into gateway rules.</p>
        </div>
        {newScan}
      </div>

      {scans.isError ? (
        <Card>
          <CardError onRetry={() => scans.refetch()} />
        </Card>
      ) : scans.isLoading ? (
        <Skeleton className="h-80" />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState icon={ScanSearch} title="No scans yet" body="Run your first scan to find weaknesses like SQL injection or a login without a rate limit." action={newScan} />
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
          <Card className="self-start">
            <CardHeader title="History" />
            <ScanList scans={items} selected={selected} onSelect={select} />
          </Card>
          <Card>{selected && <ScanDetail key={selected} scanId={selected} />}</Card>
        </div>
      )}

      <NewScanWizard open={wizard} onOpenChange={setWizard} onStarted={(s) => select(s.id)} />
    </div>
  );
}

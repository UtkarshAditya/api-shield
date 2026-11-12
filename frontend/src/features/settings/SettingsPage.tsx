import { useEffect, useState } from "react";
import { Check, Trash2, X } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuditLog, useSettings, useUpdateSettings } from "@/api/queries";
import { privacyApi } from "@/api/endpoints";
import type { AuditEntry } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { ModeBadge } from "@/components/domain/ModeBadge";
import { ModeSwitchDialog } from "@/components/domain/ModeControl";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Button } from "@/components/ui/Button";
import { Card, CardError, CardHeader } from "@/components/ui/Card";
import { ConfirmDialog, InlineError } from "@/components/ui/Dialog";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { describeError } from "@/lib/errors";
import { formatRelative } from "@/lib/format";

const STORED = [
  "Request metadata: time, method, endpoint template, status, latency, sizes",
  "Payload shapes: field names and types, as a hash",
  "Callers as pseudonyms (key fingerprints, keyed hashes of IPs and user ids)",
  "Per-minute counts for charts, kept for the retention period",
  "Rules, scan findings (with masked evidence), alerts and this audit log",
];
const NOT_STORED = [
  "Request or response bodies and query values",
  "Raw IP addresses, user ids, API keys or tokens",
  "Passwords, emails, card numbers and other redacted fields",
  "The gateway's admin token (it never leaves the server)",
];

function detailsText(d: AuditEntry["details"]) {
  return Object.entries(d)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

function AuditLog() {
  const { can } = useAuth();
  const allowed = can("settings.edit");
  const log = useAuditLog({ limit: 50 }, allowed);
  return (
    <Card>
      <CardHeader title="Audit log" hint={<WhyTooltip label="What is audited?">Rule, mode, scan, alert feedback, learning and purge actions, with who did them and when.</WhyTooltip>} />
      {!allowed ? (
        <p className="px-5 pb-5 text-sm text-muted">Only admins can view the audit log.</p>
      ) : log.isError ? (
        <CardError onRetry={() => log.refetch()} />
      ) : !log.data ? (
        <Skeleton className="mx-5 mb-5 h-40" />
      ) : log.data.items.length === 0 ? (
        <p className="px-5 pb-5 text-sm text-muted">Nothing yet.</p>
      ) : (
        <div className="max-h-96 overflow-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">Audit log, newest first</caption>
            <thead className="sticky top-0 bg-surface">
              <tr className="text-left text-[11px] text-muted uppercase">
                <th scope="col" className="px-4 py-2 font-medium">When</th>
                <th scope="col" className="px-4 py-2 font-medium">Who</th>
                <th scope="col" className="px-4 py-2 font-medium">Action</th>
                <th scope="col" className="px-4 py-2 font-medium">Target</th>
                <th scope="col" className="px-4 py-2 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              {log.data.items.map((a) => (
                <tr key={a.id} className="border-t border-border/60 align-top">
                  <td className="px-4 py-2 text-xs whitespace-nowrap text-muted" title={new Date(a.ts).toLocaleString()}>
                    {formatRelative(a.ts)}
                  </td>
                  <td className="px-4 py-2 text-xs">{a.actor}</td>
                  <td className="px-4 py-2 font-mono text-xs">{a.action}</td>
                  <td className="px-4 py-2 font-mono text-xs">
                    {a.target_type}
                    {a.target_id && <span className="text-muted"> {a.target_id}</span>}
                  </td>
                  <td className="px-4 py-2 text-xs text-muted">{detailsText(a.details)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export default function SettingsPage() {
  const { can } = useAuth();
  const { upstreamId, upstream } = useWorkspace();
  const settings = useSettings();
  const update = useUpdateSettings();
  const qc = useQueryClient();
  const [modeOpen, setModeOpen] = useState(false);
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [purged, setPurged] = useState<string | null>(null);
  const [retention, setRetention] = useState(14);
  const s = settings.data;
  const admin = can("settings.edit");

  useEffect(() => {
    if (s) setRetention(s.retention_days);
  }, [s]);

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Settings & privacy</h1>
        <p className="text-sm text-muted">How the gateway behaves, what APIShield keeps, and who changed what.</p>
      </div>

      {settings.isError ? (
        <Card>
          <CardError onRetry={() => settings.refetch()} />
        </Card>
      ) : !s ? (
        <Skeleton className="h-64" />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader title="Protection" />
            <div className="space-y-5 px-5 pb-5 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="font-medium">Gateway mode</p>
                  <p className="text-xs text-muted">MONITOR logs what would be blocked. ENFORCE blocks it.</p>
                </div>
                <div className="flex items-center gap-2">
                  <ModeBadge mode={s.mode} />
                  {can("mode.switch") && (
                    <Button size="sm" variant="secondary" onClick={() => setModeOpen(true)}>
                      Switch to {s.mode === "enforce" ? "MONITOR" : "ENFORCE"}
                    </Button>
                  )}
                </div>
              </div>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-medium">Fail open</p>
                  <p className="text-xs text-muted">If a check itself breaks, let traffic through instead of rejecting it. Saved here; the gateway's own config file decides at runtime.</p>
                </div>
                <Switch checked={s.fail_open} disabled={!admin || update.isPending} label="Fail open" onCheckedChange={(v) => update.mutate({ fail_open: v })} />
              </div>
              <div className="flex flex-wrap items-end justify-between gap-3">
                <label className="block">
                  <span className="font-medium">Retention</span>
                  <span className="block text-xs text-muted">Days of per-minute traffic counts to keep.</span>
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={retention}
                    disabled={!admin}
                    onChange={(e) => setRetention(Number(e.target.value))}
                    className="mt-1 h-8 w-24 rounded-md border border-border bg-surface-2 px-2 text-sm"
                  />
                </label>
                {admin && (
                  <Button size="sm" variant="secondary" onClick={() => update.mutate({ retention_days: retention })} disabled={update.isPending || retention === s.retention_days || retention < 1}>
                    Save retention
                  </Button>
                )}
              </div>
              {!admin && <p className="text-xs text-muted">Only admins can change settings.</p>}
              {update.isError && <InlineError message={describeError(update.error)} />}
            </div>
          </Card>

          <Card>
            <CardHeader title="Protected APIs" />
            <ul className="space-y-2 px-5 pb-5">
              {s.upstreams.map((u) => (
                <li key={u.id} className="rounded-lg border border-border px-3 py-2">
                  <p className="text-sm font-medium">{u.name}</p>
                  <p className="font-mono text-xs text-muted">{u.url}</p>
                </li>
              ))}
            </ul>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader title="Privacy" hint={<WhyTooltip label="Why this design?">APIShield learns the shape of your traffic, not its contents, so a breach of APIShield does not leak your users' data.</WhyTooltip>} />
            <div className="grid gap-6 px-5 pb-5 md:grid-cols-2">
              <div>
                <h3 className="mb-2 text-xs font-semibold text-muted">Stored</h3>
                <ul className="space-y-1.5 text-sm">
                  {STORED.map((t) => (
                    <li key={t} className="flex gap-2">
                      <Check className="mt-0.5 size-4 shrink-0 text-act-allow" aria-hidden />
                      {t}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 className="mb-2 text-xs font-semibold text-muted">Never stored</h3>
                <ul className="space-y-1.5 text-sm">
                  {NOT_STORED.map((t) => (
                    <li key={t} className="flex gap-2">
                      <X className="mt-0.5 size-4 shrink-0 text-sev-critical" aria-hidden />
                      {t}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="md:col-span-2">
                <h3 className="mb-2 text-xs font-semibold text-muted">Redacted fields (masked in scan evidence and responses)</h3>
                <ul className="flex flex-wrap gap-1.5" aria-label="Redaction patterns">
                  {s.redaction_patterns.map((p) => (
                    <li key={p} className="rounded border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs">
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
              {can("data.purge") && (
                <div className="flex flex-wrap items-center gap-3 md:col-span-2">
                  <Button variant="danger" size="sm" onClick={() => setPurgeOpen(true)}>
                    <Trash2 className="size-3.5" aria-hidden /> Purge traffic data
                  </Button>
                  {purged && (
                    <p role="status" className="text-xs text-muted">
                      {purged}
                    </p>
                  )}
                </div>
              )}
            </div>
          </Card>
        </div>
      )}

      <AuditLog />

      {s && <ModeSwitchDialog open={modeOpen} onOpenChange={setModeOpen} target={s.mode === "enforce" ? "monitor" : "enforce"} />}
      <ConfirmDialog
        open={purgeOpen}
        onOpenChange={setPurgeOpen}
        title={`Purge traffic data for ${upstream?.name ?? "this API"}?`}
        tone="danger"
        confirmLabel="Purge data"
        description="Deletes stored traffic counts and buffered events. Rules, scans, alerts and the audit log are kept. This cannot be undone."
        onConfirm={async () => {
          const r = await privacyApi.purge(upstreamId!);
          setPurged(`Purged ${r.recent_events} buffered events and ${r.aggregate_rows} stored rows.`);
          void qc.invalidateQueries();
        }}
      />
    </div>
  );
}

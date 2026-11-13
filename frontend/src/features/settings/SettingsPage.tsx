import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuditLog, useSettings, useUpdateSettings } from "@/api/queries";
import { privacyApi } from "@/api/endpoints";
import type { AuditEntry } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { ModeBadge } from "@/components/domain/ModeBadge";
import { ModeSwitchDialog } from "@/components/domain/ModeControl";
import { Term } from "@/components/domain/Term";
import { Button } from "@/components/ui/Button";
import { CardError } from "@/components/ui/Card";
import { DataTable, PageHeader, Section, Td, Th, THead, Tr } from "@/components/ui/Primitives";
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
    <Section title={<Term tip="Rule, mode, scan, alert feedback, learning and purge actions, with who did them and when.">Audit log</Term>}>
      {!allowed ? (
        <p className="text-sm text-muted">Only admins can view the audit log.</p>
      ) : log.isError ? (
        <CardError onRetry={() => log.refetch()} />
      ) : !log.data ? (
        <Skeleton className="h-40" />
      ) : log.data.items.length === 0 ? (
        <p className="font-mono text-sm text-muted">0 audited actions.</p>
      ) : (
        <DataTable caption="Audit log, newest first" maxHeight="24rem">
          <THead>
            <Th className="first:pl-0">When</Th>
            <Th>Who</Th>
            <Th>Action</Th>
            <Th>Target</Th>
            <Th>Details</Th>
          </THead>
          <tbody>
            {log.data.items.map((a) => (
              <Tr key={a.id}>
                <Td mono className="text-xs whitespace-nowrap text-muted first:pl-0" title={new Date(a.ts).toLocaleString()}>
                  {formatRelative(a.ts)}
                </Td>
                <Td className="font-mono text-xs">{a.actor}</Td>
                <Td mono className="text-xs">
                  {a.action}
                </Td>
                <Td mono className="text-xs">
                  {a.target_type}
                  {a.target_id && <span className="text-muted"> {a.target_id}</span>}
                </Td>
                <Td className="text-xs text-muted">{detailsText(a.details)}</Td>
              </Tr>
            ))}
          </tbody>
        </DataTable>
      )}
    </Section>
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
    <div className="max-w-6xl space-y-8">
      <PageHeader title="Settings & privacy" description="How the gateway behaves, what APIShield keeps, and who changed what." />

      {settings.isError ? (
        <CardError onRetry={() => settings.refetch()} />
      ) : !s ? (
        <Skeleton className="h-64" />
      ) : (
        <div className="grid gap-x-10 gap-y-8 lg:grid-cols-2">
          <Section title="Protection">
            <div className="space-y-5 text-sm">
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
              <div className="flex items-center justify-between gap-3 border-t border-border pt-4">
                <div>
                  <p className="font-medium">
                    Fail open <span className="ml-2 font-mono text-[11px] tracking-wider text-muted uppercase">Not enforced yet</span>
                  </p>
                  <p className="text-xs text-muted">
                    If a check itself breaks, let traffic through instead of rejecting it. The gateway reads this from its own configuration
                    (APISHIELD_FAIL_OPEN); a change here would not reach it, so the switch is disabled.
                  </p>
                </div>
                <Switch checked={s.fail_open} disabled label="Fail open" onCheckedChange={() => undefined} />
              </div>
              <div className="flex flex-wrap items-end justify-between gap-3 border-t border-border pt-4">
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
                    className="mt-1 h-8 w-24 rounded-sm border border-border-strong bg-surface px-2 font-mono text-sm"
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
          </Section>

          <Section title="Protected APIs">
            <ul className="border-t border-border">
              {s.upstreams.map((u) => (
                <li key={u.id} className="border-b border-border py-2">
                  <p className="text-sm font-medium">{u.name}</p>
                  <p className="font-mono text-xs text-muted">{u.url}</p>
                </li>
              ))}
            </ul>
          </Section>

          <Section
            className="lg:col-span-2"
            title={<Term tip="APIShield learns the shape of your traffic, not its contents, so a breach of APIShield does not leak your users' data.">Privacy</Term>}
          >
            <div className="grid gap-x-10 gap-y-6 md:grid-cols-2">
              <div>
                <h3 className="eyebrow mb-2">Stored</h3>
                <ul className="border-t border-border text-sm">
                  {STORED.map((t) => (
                    <li key={t} className="flex gap-3 border-b border-border py-1.5">
                      <span aria-hidden className="mt-1.5 inline-block size-2 shrink-0 bg-ok" />
                      {t}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 className="eyebrow mb-2">Never stored</h3>
                <ul className="border-t border-border text-sm">
                  {NOT_STORED.map((t) => (
                    <li key={t} className="flex gap-3 border-b border-border py-1.5">
                      <span aria-hidden className="mt-1.5 inline-block size-2 shrink-0 border border-signal-mark" />
                      {t}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="md:col-span-2">
                <h3 className="eyebrow mb-2">Redacted fields (masked in scan evidence and responses)</h3>
                <ul className="flex flex-wrap gap-1.5" aria-label="Redaction patterns">
                  {s.redaction_patterns.map((p) => (
                    <li key={p} className="border border-border px-1.5 font-mono text-xs">
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
              {can("data.purge") && (
                <div className="flex flex-wrap items-center gap-3 md:col-span-2">
                  <Button variant="danger" size="sm" onClick={() => setPurgeOpen(true)}>
                    Purge traffic data
                  </Button>
                  {purged && (
                    <p role="status" className="text-xs text-muted">
                      {purged}
                    </p>
                  )}
                </div>
              )}
            </div>
          </Section>
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

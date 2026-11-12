import { useEffect, useRef, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { Plus, SlidersHorizontal, Trash2 } from "lucide-react";
import { useRuleMutations, useRules } from "@/api/queries";
import type { RuleInput } from "@/api/endpoints";
import type { Action, Rule } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { ActionBadge, actionMeaning, matchSummary, SourceBadge } from "@/components/domain/ActionBadge";
import { EmptyState } from "@/components/domain/EmptyState";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Button } from "@/components/ui/Button";
import { Card, CardError } from "@/components/ui/Card";
import { ConfirmDialog, InlineError, Modal } from "@/components/ui/Dialog";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { Tooltip } from "@/components/ui/Tooltip";
import { describeError } from "@/lib/errors";
import { cn } from "@/lib/cn";
import { formatNumber } from "@/lib/format";

const SIGNATURES = ["", "sqli", "nosqli", "xss", "path_traversal", "bad_user_agent"] as const;
const ACTIONS: Action[] = ["log", "block", "throttle", "challenge", "allow"];
const inputCls = "h-9 w-full rounded-md border border-border bg-surface-2 px-2 text-sm";

function CreateRuleDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const { upstreamId } = useWorkspace();
  const { create } = useRuleMutations(upstreamId);
  const [form, setForm] = useState({ id: "", name: "", path: "", methods: "", signature: "", action: "log" as Action, limit: 10, per: 60 });
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));

  useEffect(() => {
    if (open) {
      setForm({ id: "", name: "", path: "", methods: "", signature: "", action: "log", limit: 10, per: 60 });
      create.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const methods = form.methods
    .split(/[,\s]+/)
    .map((m) => m.trim().toUpperCase())
    .filter(Boolean);
  const match: Rule["match"] = {};
  if (form.path.trim()) match.path = form.path.trim();
  if (methods.length) match.method = methods.length === 1 ? methods[0] : methods;
  if (form.signature) match.signature = form.signature;
  const idValid = /^[A-Za-z0-9._-]{1,128}$/.test(form.id);
  const hasCondition = Object.keys(match).length > 0;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const rule: RuleInput = { id: form.id, name: form.name || undefined, match, action: form.action, source: "analyst" };
    if (form.action === "throttle") rule.throttle = { limit: form.limit, per: form.per };
    await create.mutateAsync(rule).then(() => onOpenChange(false), () => undefined);
  };

  return (
    <Modal open={open} onOpenChange={(v) => !create.isPending && onOpenChange(v)} title="New rule" description="Rules are validated by the gateway and take effect within seconds. Block, throttle and challenge only bite in ENFORCE mode.">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Rule id</span>
            <input required value={form.id} onChange={(e) => set("id", e.target.value)} placeholder="block-export" className={cn(inputCls, "font-mono")} aria-invalid={!!form.id && !idValid} />
            <span className="mt-1 block text-xs text-muted">Letters, digits, dot, dash, underscore.</span>
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Name (optional)</span>
            <input value={form.name} onChange={(e) => set("name", e.target.value)} className={inputCls} />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Path</span>
            <input value={form.path} onChange={(e) => set("path", e.target.value)} placeholder="/search or /admin/*" className={cn(inputCls, "font-mono")} />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Methods</span>
            <input value={form.methods} onChange={(e) => set("methods", e.target.value)} placeholder="GET, POST" className={cn(inputCls, "font-mono")} />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Attack signature</span>
            <select value={form.signature} onChange={(e) => set("signature", e.target.value)} className={inputCls}>
              {SIGNATURES.map((s) => (
                <option key={s} value={s}>
                  {s || "none"}
                </option>
              ))}
            </select>
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Action</span>
            <select value={form.action} onChange={(e) => set("action", e.target.value as Action)} className={inputCls}>
              {ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </label>
          {form.action === "throttle" && (
            <>
              <label className="block text-sm">
                <span className="mb-1 block font-medium">Limit (requests)</span>
                <input type="number" min={1} value={form.limit} onChange={(e) => set("limit", Number(e.target.value))} className={inputCls} />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium">Per (seconds)</span>
                <input type="number" min={1} value={form.per} onChange={(e) => set("per", Number(e.target.value))} className={inputCls} />
              </label>
            </>
          )}
        </div>
        <p className="rounded-md bg-surface-2 px-3 py-2 text-xs text-muted">
          This rule {actionMeaning[form.action]} for: <span className="font-mono">{matchSummary(match).join(" · ")}</span>
        </p>
        {!hasCondition && <p className="text-xs text-sev-high">Add at least a path, a method or a signature, or the rule matches every request.</p>}
        {create.isError && <InlineError message={describeError(create.error)} />}
        <div className="flex justify-end gap-2 pt-1">
          <Button variant="secondary" onClick={() => onOpenChange(false)} disabled={create.isPending}>
            Cancel
          </Button>
          <Button type="submit" disabled={!idValid || !hasCondition || create.isPending}>
            {create.isPending ? "Creating…" : "Create rule"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function RuleRow({ rule, highlighted }: { rule: Rule; highlighted: boolean }) {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const { update, remove } = useRuleMutations(upstreamId);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLTableRowElement>(null);
  const readOnly = rule.source === "builtin";
  const editable = can("rules.edit") && !readOnly;

  useEffect(() => {
    if (highlighted) ref.current?.scrollIntoView?.({ block: "center" });
  }, [highlighted]);

  const toggle = (enabled: boolean) => {
    setError(null);
    update.mutate({ id: rule.id, patch: { enabled } }, { onError: (err) => setError(describeError(err)) });
  };

  return (
    <tr ref={ref} className={cn("border-t border-border/60 align-top", highlighted && "bg-accent-soft")}>
      <td className="px-4 py-2.5">
        <p className="font-medium">{rule.name}</p>
        {rule.name !== rule.id && <p className="font-mono text-[11px] text-muted">{rule.id}</p>}
        {error && <InlineError message={error} />}
      </td>
      <td className="px-4 py-2.5">
        <SourceBadge source={rule.source} />
      </td>
      <td className="px-4 py-2.5">
        <ul className="space-y-0.5 font-mono text-xs">
          {matchSummary(rule.match).map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
        {rule.throttle && (
          <p className="mt-0.5 text-xs text-muted">
            {rule.throttle.limit} per {rule.throttle.per} s
          </p>
        )}
      </td>
      <td className="px-4 py-2.5">
        <span className="inline-flex items-center gap-1">
          <ActionBadge action={rule.action} />
          <WhyTooltip label={`What does ${rule.action} do?`}>This rule {actionMeaning[rule.action]}.</WhyTooltip>
        </span>
      </td>
      <td className="px-4 py-2.5 text-right tabular-nums">{formatNumber(rule.hits_24h)}</td>
      <td className="px-4 py-2.5">
        {readOnly ? (
          <Tooltip content="Built-in rules live in the gateway's rule files. Edit them there.">
            <span tabIndex={0} className="inline-flex">
              <Switch checked={rule.enabled} onCheckedChange={() => undefined} disabled label={`${rule.name} enabled (read-only)`} />
            </span>
          </Tooltip>
        ) : (
          <Switch checked={rule.enabled} onCheckedChange={toggle} disabled={!editable || update.isPending} label={`${rule.name} enabled`} />
        )}
      </td>
      <td className="px-2 py-2 text-right">
        {editable && (
          <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(true)} aria-label={`Delete rule ${rule.id}`}>
            <Trash2 className="size-4" aria-hidden />
          </Button>
        )}
        <ConfirmDialog
          open={confirmDelete}
          onOpenChange={setConfirmDelete}
          title={`Delete rule "${rule.name}"?`}
          description="The gateway stops applying it immediately. This cannot be undone, but you can create it again."
          confirmLabel="Delete rule"
          tone="danger"
          onConfirm={() => remove.mutateAsync(rule.id)}
        />
      </td>
    </tr>
  );
}

export default function RulesPage() {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const rules = useRules(upstreamId);
  const [params] = useSearchParams();
  const [creating, setCreating] = useState(false);
  const highlight = params.get("highlight");
  const items = rules.data?.items ?? [];

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Rules</h1>
          <p className="text-sm text-muted">Built-in, scanner, analyst and learner rules, in the order the gateway checks them.</p>
        </div>
        {can("rules.edit") && (
          <Button onClick={() => setCreating(true)}>
            <Plus className="size-4" aria-hidden /> New rule
          </Button>
        )}
      </div>

      <Card>
        {rules.isError ? (
          <CardError onRetry={() => rules.refetch()} />
        ) : rules.isLoading ? (
          <Skeleton className="m-5 h-60" />
        ) : items.length === 0 ? (
          <EmptyState icon={SlidersHorizontal} title="No rules yet" body="Apply a suggested rule from a scan, or create one here." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <caption className="sr-only">Gateway rules</caption>
              <thead>
                <tr className="text-left text-[11px] text-muted uppercase">
                  <th scope="col" className="px-4 py-2 font-medium">Rule</th>
                  <th scope="col" className="px-4 py-2 font-medium">Source</th>
                  <th scope="col" className="px-4 py-2 font-medium">Matches</th>
                  <th scope="col" className="px-4 py-2 font-medium">Action</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">
                    <span className="inline-flex items-center gap-1">
                      Hits 24 h
                      <WhyTooltip label="What counts as a hit?">Requests in the last 24 hours that matched this rule, whatever the mode.</WhyTooltip>
                    </span>
                  </th>
                  <th scope="col" className="px-4 py-2 font-medium">Enabled</th>
                  <th scope="col" className="px-2 py-2">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <RuleRow key={r.id} rule={r} highlighted={r.id === highlight} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <CreateRuleDialog open={creating} onOpenChange={setCreating} />
    </div>
  );
}

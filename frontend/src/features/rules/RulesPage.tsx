import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type SyntheticEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { ChevronRight, Plus, Trash2 } from "lucide-react";
import { useRuleMutations, useRules } from "@/api/queries";
import type { RuleInput } from "@/api/endpoints";
import type { Action, Rule } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { ActionTag, actionMeaning, matchSummary, sourceLabel } from "@/components/domain/ActionBadge";
import { EmptyState } from "@/components/domain/EmptyState";
import { Term } from "@/components/domain/Term";
import { Button } from "@/components/ui/Button";
import { CardError } from "@/components/ui/Card";
import { ConfirmDialog, InlineError, Modal } from "@/components/ui/Dialog";
import { DataTable, PageHeader, Td, Th, THead, Tr } from "@/components/ui/Primitives";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { Tooltip } from "@/components/ui/Tooltip";
import { describeError } from "@/lib/errors";
import { cn } from "@/lib/cn";
import { formatNumber } from "@/lib/format";
import { RuleDrawer, RulePanel, useWidePanel } from "./RuleDetail";

const SIGNATURES = ["", "sqli", "nosqli", "xss", "path_traversal", "bad_user_agent"] as const;
const ACTIONS: Action[] = ["log", "block", "throttle", "challenge", "allow"];
const GROUPS: Rule["source"][] = ["builtin", "scanner", "analyst", "learner"];
const inputCls = "h-8 w-full rounded-sm border border-border-strong bg-surface px-2 text-sm";
const COLS = 8;

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

  const field = "block text-sm";
  const lab = "mb-1 block eyebrow";
  return (
    <Modal open={open} onOpenChange={(v) => !create.isPending && onOpenChange(v)} title="New rule" description="The gateway validates rules and applies them within seconds. Block, throttle and challenge take effect only in ENFORCE.">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className={field}>
            <span className={lab}>Rule id</span>
            <input required value={form.id} onChange={(e) => set("id", e.target.value)} placeholder="block-export" className={cn(inputCls, "font-mono")} aria-invalid={!!form.id && !idValid} />
            <span className="mt-1 block text-xs text-muted">Letters, digits, dot, dash, underscore.</span>
          </label>
          <label className={field}>
            <span className={lab}>Name (optional)</span>
            <input value={form.name} onChange={(e) => set("name", e.target.value)} className={inputCls} />
          </label>
          <label className={field}>
            <span className={lab}>Path</span>
            <input value={form.path} onChange={(e) => set("path", e.target.value)} placeholder="/search or /admin/*" className={cn(inputCls, "font-mono")} />
          </label>
          <label className={field}>
            <span className={lab}>Methods</span>
            <input value={form.methods} onChange={(e) => set("methods", e.target.value)} placeholder="GET, POST" className={cn(inputCls, "font-mono")} />
          </label>
          <label className={field}>
            <span className={lab}>Attack signature</span>
            <select value={form.signature} onChange={(e) => set("signature", e.target.value)} className={inputCls}>
              {SIGNATURES.map((s) => (
                <option key={s} value={s}>
                  {s || "none"}
                </option>
              ))}
            </select>
          </label>
          <label className={field}>
            <span className={lab}>Action</span>
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
              <label className={field}>
                <span className={lab}>Limit (requests)</span>
                <input type="number" min={1} value={form.limit} onChange={(e) => set("limit", Number(e.target.value))} className={inputCls} />
              </label>
              <label className={field}>
                <span className={lab}>Per (seconds)</span>
                <input type="number" min={1} value={form.per} onChange={(e) => set("per", Number(e.target.value))} className={inputCls} />
              </label>
            </>
          )}
        </div>
        <p className="border-l-2 border-border-strong py-1 pl-3 text-xs text-muted">
          This rule {actionMeaning[form.action]} for: <span className="font-mono text-fg">{matchSummary(match).join(" · ")}</span>
        </p>
        {!hasCondition && <p className="text-xs text-signal">Add a path, a method or a signature; otherwise the rule matches every request.</p>}
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

function RuleRow({ rule, position, highlighted, selected, onOpen, compact }: { rule: Rule; position: number; highlighted: boolean; selected: boolean; onOpen: (id: string, el: HTMLElement | null) => void; compact: boolean }) {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const { update, remove } = useRuleMutations(upstreamId);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLTableRowElement>(null);
  const chevron = useRef<HTMLButtonElement>(null);
  const readOnly = rule.source === "builtin";
  const editable = can("rules.edit") && !readOnly;

  useEffect(() => {
    if (highlighted) ref.current?.scrollIntoView?.({ block: "center" });
  }, [highlighted]);

  const toggle = (enabled: boolean) => {
    setError(null);
    update.mutate({ id: rule.id, patch: { enabled } }, { onError: (err) => setError(describeError(err)) });
  };
  const stop = (e: SyntheticEvent) => e.stopPropagation();

  return (
    <Tr
      ref={ref}
      active={selected || highlighted}
      onClick={() => onOpen(rule.id, chevron.current)}
      className={cn("cursor-pointer", !rule.enabled && "text-muted")}
      data-rule={rule.id}
    >
      <Td mono className="w-10 text-muted">{String(position).padStart(2, "0")}</Td>
      <Td className="py-2">
        <p className="font-medium">{rule.name}</p>
        {rule.name !== rule.id && <p className="font-mono text-[11px] text-muted">{rule.id}</p>}
        {error && <InlineError message={error} />}
      </Td>
      {!compact && (
        <Td>
          <span className="font-mono text-xs whitespace-nowrap text-muted">{sourceLabel[rule.source]}</span>
        </Td>
      )}
      <Td>
        <ul className="space-y-0.5 font-mono text-xs">
          {matchSummary(rule.match).map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
        {rule.throttle && (
          <p className="mt-0.5 font-mono text-xs text-muted">
            {rule.throttle.limit} per {rule.throttle.per} s
          </p>
        )}
      </Td>
      <Td>
        <Term tip={`This rule ${actionMeaning[rule.action]}.`}>
          <ActionTag action={rule.action} />
        </Term>
      </Td>
      <Td align="right" mono>
        {formatNumber(rule.hits_24h)}
      </Td>
      <Td onClick={stop}>
        {readOnly ? (
          <Tooltip content="Built-in rules live in the gateway's rule files. Edit them there.">
            <span tabIndex={0} className="inline-flex">
              <Switch checked={rule.enabled} onCheckedChange={() => undefined} disabled label={`${rule.name} enabled (read-only)`} />
            </span>
          </Tooltip>
        ) : (
          <Switch checked={rule.enabled} onCheckedChange={toggle} disabled={!editable || update.isPending} label={`${rule.name} enabled`} />
        )}
      </Td>
      <Td align="right" onClick={stop} className="w-20 whitespace-nowrap">
        {editable && (
          <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(true)} aria-label={`Delete rule ${rule.id}`}>
            <Trash2 className="size-3.5" aria-hidden />
          </Button>
        )}
        <Button ref={chevron} variant="ghost" size="sm" onClick={() => onOpen(rule.id, chevron.current)} aria-label={`Details for ${rule.name}`} aria-expanded={selected}>
          <ChevronRight className="size-3.5" aria-hidden />
        </Button>
        <ConfirmDialog
          open={confirmDelete}
          onOpenChange={setConfirmDelete}
          title={`Delete rule "${rule.name}"?`}
          description="The gateway stops applying it immediately. This cannot be undone, but you can create it again."
          confirmLabel="Delete rule"
          tone="danger"
          onConfirm={() => remove.mutateAsync(rule.id)}
        />
      </Td>
    </Tr>
  );
}

export default function RulesPage() {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const rules = useRules(upstreamId);
  const [params, setParams] = useSearchParams();
  const [creating, setCreating] = useState(false);
  const wide = useWidePanel();
  const opener = useRef<HTMLElement | null>(null);
  const highlight = params.get("highlight");
  // ?rule= opens the panel; a ?highlight= link (from a scan finding) opens it too.
  const selectedId = params.get("rule") ?? highlight;

  // Evaluation order: priority ascending (gateway default 100), ties as the Admin API lists them.
  const ordered = useMemo(() => {
    const items = rules.data?.items ?? [];
    return items.map((r, i) => ({ r, i })).sort((a, b) => (a.r.priority ?? 100) - (b.r.priority ?? 100) || a.i - b.i).map((x) => x.r);
  }, [rules.data]);
  const position = useMemo(() => new Map(ordered.map((r, i) => [r.id, i + 1])), [ordered]);
  const groups = GROUPS.map((g) => ({ source: g, rules: ordered.filter((r) => r.source === g) })).filter((g) => g.rules.length);
  const selected = selectedId ? ordered.find((r) => r.id === selectedId) : undefined;
  // Inline panel open: the group headers already name the source, so that column is hidden.
  const split = wide && !!selectedId;

  const open = useCallback(
    (id: string, el: HTMLElement | null) => {
      opener.current = el;
      setParams((p) => {
        const next = new URLSearchParams(p);
        next.set("rule", id);
        return next;
      });
    },
    [setParams],
  );
  const close = useCallback(() => {
    setParams((p) => {
      const next = new URLSearchParams(p);
      next.delete("rule");
      next.delete("highlight");
      return next;
    });
    requestAnimationFrame(() => opener.current?.focus());
  }, [setParams]);

  const panel = selectedId && !rules.isLoading && (
    wide ? (
      <RulePanel rule={selected} ruleId={selectedId} position={position.get(selectedId) ?? 0} total={ordered.length} onClose={close} />
    ) : (
      <RuleDrawer rule={selected} ruleId={selectedId} position={position.get(selectedId) ?? 0} total={ordered.length} onClose={close} />
    )
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Rules"
        description="Numbered in the gateway's evaluation order: lower priority runs first, and the first rule that would stop a request ends evaluation. Rules with equal priority are listed by id. Select a rule to see what it catches."
        actions={
          can("rules.edit") && (
            <Button onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden /> New rule
            </Button>
          )
        }
      />

      <div className={cn("grid gap-6", wide && selectedId && "grid-cols-[minmax(0,1fr)_minmax(380px,460px)]")}>
        <div className="min-w-0 border-y border-border">
          {rules.isError ? (
            <CardError onRetry={() => rules.refetch()} />
          ) : rules.isLoading ? (
            <Skeleton className="my-4 h-60" />
          ) : ordered.length === 0 ? (
            <EmptyState title="0 rules" body="Apply a suggested rule from a scan, or create one." />
          ) : (
            <DataTable caption="Gateway rules">
              <THead>
                <Th>#</Th>
                <Th>Rule</Th>
                {!split && <Th>Source</Th>}
                <Th>Matches</Th>
                <Th>Action</Th>
                <Th align="right">
                  <Term tip="Requests in the last 24 hours that matched this rule, in either mode.">Hits 24 h</Term>
                </Th>
                <Th>Enabled</Th>
                <Th>
                  <span className="sr-only">Actions</span>
                </Th>
              </THead>
              {groups.map((g) => (
                <tbody key={g.source}>
                  <tr>
                    <th colSpan={split ? COLS - 1 : COLS} scope="colgroup" className="eyebrow h-8 border-b border-border bg-bg px-4 text-left">
                      {sourceLabel[g.source]} <span className="ml-1 text-fg">{g.rules.length}</span>
                    </th>
                  </tr>
                  {g.rules.map((r) => (
                    <RuleRow key={r.id} rule={r} position={position.get(r.id)!} highlighted={r.id === highlight} selected={r.id === selectedId} onOpen={open} compact={split} />
                  ))}
                </tbody>
              ))}
            </DataTable>
          )}
        </div>
        {wide && panel}
      </div>
      {!wide && panel}
      <CreateRuleDialog open={creating} onOpenChange={setCreating} />
    </div>
  );
}

import { useEffect, useMemo, useRef, useState, type ReactNode, type Ref } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { trafficApi } from "@/api/endpoints";
import { useRuleMutations } from "@/api/queries";
import type { Rule, TrafficEvent } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { ActionTag, matchSummary, sourceLabel } from "@/components/domain/ActionBadge";
import { InlineError, Sheet } from "@/components/ui/Dialog";
import { Skeleton } from "@/components/ui/Skeleton";
import { Switch } from "@/components/ui/Switch";
import { describeError } from "@/lib/errors";
import { formatNumber, formatRelative } from "@/lib/format";
import { docFor, EVALUATION_NOTE, MODE_BEHAVIOR, PAYLOAD_CAP, type RuleDoc } from "./builtinRuleDocs";

const ACTIVITY_SAMPLE = 500;

function useMediaQuery(query: string): boolean {
  const get = () => (typeof window !== "undefined" && window.matchMedia ? window.matchMedia(query).matches : false);
  const [matches, setMatches] = useState(get);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    if (!mq) return;
    const on = () => setMatches(mq.matches);
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, [query]);
  return matches;
}

export const useWidePanel = () => useMediaQuery("(min-width: 1280px)");

function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-border pt-3">
      <h3 className="eyebrow mb-2 text-fg">{title}</h3>
      <div className="space-y-2 text-sm leading-relaxed">{children}</div>
    </section>
  );
}

/** Rule activity from the Admin API's recent-event buffer: counts only, never payloads. */
function useRuleActivity(upstreamId: string | undefined, ruleId: string) {
  const recent = useQuery({
    queryKey: ["traffic", "recent", upstreamId ?? "", "rule-activity", ACTIVITY_SAMPLE],
    queryFn: () => trafficApi.recent(upstreamId!, ACTIVITY_SAMPLE),
    enabled: !!upstreamId,
    staleTime: 10_000,
  });
  const stats = useMemo(() => {
    const items: TrafficEvent[] = recent.data?.items ?? [];
    const hits = items.filter((e) => e.rule_hits.includes(ruleId));
    const top = (key: (e: TrafficEvent) => string) => {
      const counts = new Map<string, number>();
      for (const e of hits) counts.set(key(e), (counts.get(key(e)) ?? 0) + 1);
      return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
    };
    return {
      sample: items.length,
      count: hits.length,
      last: hits.reduce<string | undefined>((m, e) => (!m || e.ts > m ? e.ts : m), undefined),
      endpoints: top((e) => `${e.method} ${e.path_template}`),
      callers: top((e) => e.caller),
    };
  }, [recent.data, ruleId]);
  return { ...stats, loading: recent.isLoading, error: recent.isError };
}

function DocBlocks({ doc, rule }: { doc: RuleDoc; rule: Rule }) {
  const constraints = matchSummary(rule.match).filter((m) => !m.startsWith("signature"));
  return (
    <>
      <Block title="What it catches">
        <p>{doc.catches}</p>
      </Block>
      <Block title="Why it matters">
        <p>{doc.why}</p>
        {doc.refs && <p className="font-mono text-xs text-muted">{doc.refs.join(" · ")}</p>}
      </Block>
      <Block title="How it matches">
        <p>{doc.how.summary}</p>
        {constraints.length > 0 && rule.match.signature && (
          <p>
            This rule also requires: <span className="font-mono text-[13px]">{constraints.join(" · ")}</span>
          </p>
        )}
        <div>
          <p className="eyebrow mb-1">Inspects</p>
          <ul className="list-disc space-y-0.5 pl-4 text-[13px]">
            {doc.how.inspects.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
          {doc.how.inspects.length > 1 && <p className="mt-1 text-xs text-muted">{PAYLOAD_CAP}</p>}
        </div>
        <div>
          <p className="eyebrow mb-1">Pattern families</p>
          <ul className="list-disc space-y-0.5 pl-4 text-[13px]">
            {doc.how.families.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </div>
        <div>
          <p className="eyebrow mb-1">Example strings (inert)</p>
          <ul className="flex flex-wrap gap-1.5">
            {doc.how.examples.map((x) => (
              <li key={x} className="border border-border bg-surface-2 px-1.5 font-mono text-xs">
                {x}
              </li>
            ))}
          </ul>
        </div>
      </Block>
    </>
  );
}

function RuleDetailBody({ rule, position, total, headingRef }: { rule: Rule; position: number; total: number; headingRef?: Ref<HTMLHeadingElement> }) {
  const { upstreamId } = useWorkspace();
  const { can } = useAuth();
  const { update } = useRuleMutations(upstreamId);
  const [error, setError] = useState<string | null>(null);
  const doc = docFor(rule);
  const readOnly = rule.source === "builtin";
  const editable = can("rules.edit") && !readOnly;
  const activity = useRuleActivity(upstreamId, rule.id);
  const behavior = MODE_BEHAVIOR[rule.action];
  const fromAlert = rule.id.startsWith("alert-") ? rule.id.slice("alert-".length) : null;

  const toggle = (enabled: boolean) => {
    setError(null);
    update.mutate({ id: rule.id, patch: { enabled } }, { onError: (err) => setError(describeError(err)) });
  };

  return (
    <div className="space-y-4">
      <header className="space-y-2">
        <p className="eyebrow">
          {sourceLabel[rule.source]} · position {position} of {total} · priority {rule.priority ?? 100}
        </p>
        <h2 ref={headingRef} tabIndex={-1} className="text-xl font-semibold tracking-tight focus:outline-none focus-visible:outline-none">
          {rule.name}
        </h2>
        <p className="font-mono text-xs text-muted">{rule.id}</p>
        <div className="flex flex-wrap items-center gap-4 pt-1">
          <ActionTag action={rule.action} />
          {rule.throttle && (
            <span className="font-mono text-xs text-muted">
              {rule.throttle.limit} per {rule.throttle.per} s
            </span>
          )}
          <label className="ml-auto inline-flex items-center gap-2 text-sm">
            <span className="text-muted">{readOnly ? "Enabled (read-only)" : "Enabled"}</span>
            <Switch
              checked={rule.enabled}
              onCheckedChange={toggle}
              disabled={!editable || update.isPending}
              label={`${rule.name} enabled, details panel${readOnly ? " (read-only)" : ""}`}
            />
          </label>
        </div>
        {readOnly && <p className="text-xs text-muted">Built-in rules live in the gateway's rule files (gateway/rules/builtin.yaml).</p>}
        {error && <InlineError message={error} />}
      </header>

      {doc ? (
        <DocBlocks doc={doc} rule={rule} />
      ) : (
        <Block title="How it matches">
          <p>Every condition must hold:</p>
          <ul className="space-y-0.5 font-mono text-[13px]">
            {matchSummary(rule.match).map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
          <p className="text-xs text-muted">No written explanation for this rule; the match above is exactly what the gateway checks.</p>
        </Block>
      )}

      <Block title="Behavior by mode">
        <table className="w-full text-[13px]">
          <caption className="sr-only">What {rule.action} does in each gateway mode</caption>
          <tbody>
            <tr className="border-b border-border/70 align-top">
              <th scope="row" className="eyebrow w-24 py-1.5 pr-3 text-left">Monitor</th>
              <td className="py-1.5">{behavior.monitor}</td>
            </tr>
            <tr className="align-top">
              <th scope="row" className="eyebrow py-1.5 pr-3 text-left">Enforce</th>
              <td className="py-1.5">{behavior.enforce}</td>
            </tr>
          </tbody>
        </table>
        <p className="text-xs text-muted">{EVALUATION_NOTE}</p>
      </Block>

      {doc && (
        <Block title="Known limits">
          <ul className="list-disc space-y-1 pl-4 text-[13px]">
            {doc.limits.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </Block>
      )}

      <Block title="Activity">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[13px]">
          <dt className="text-muted">Hits, last 24 h</dt>
          <dd className="text-right font-mono">{formatNumber(rule.hits_24h)}</dd>
          <dt className="text-muted">Last hit</dt>
          <dd className="text-right font-mono">{activity.loading ? "…" : activity.last ? formatRelative(activity.last) : "none in buffer"}</dd>
        </dl>
        {activity.loading ? (
          <Skeleton className="h-16" />
        ) : activity.error ? (
          <p className="text-xs text-muted">Recent traffic is unavailable.</p>
        ) : activity.count === 0 ? (
          <p className="text-xs text-muted">
            No hits in the last {formatNumber(activity.sample)} buffered requests.
          </p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <p className="eyebrow mb-1">Top endpoints</p>
              <ul className="space-y-0.5 font-mono text-xs">
                {activity.endpoints.map(([k, n]) => (
                  <li key={k} className="flex justify-between gap-2">
                    <span className="truncate">{k}</span>
                    <span className="text-muted">{n}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="eyebrow mb-1">Top callers</p>
              <ul className="space-y-0.5 font-mono text-xs">
                {activity.callers.map(([k, n]) => (
                  <li key={k} className="flex justify-between gap-2">
                    <span className="truncate">{k}</span>
                    <span className="text-muted">{n}</span>
                  </li>
                ))}
              </ul>
            </div>
            <p className="text-xs text-muted sm:col-span-2">
              From {formatNumber(activity.count)} hits in the last {formatNumber(activity.sample)} buffered requests. Callers are pseudonyms; payloads are never stored.
            </p>
          </div>
        )}
      </Block>

      {(rule.source === "scanner" || fromAlert) && (
        <Block title="Related">
          <ul className="space-y-1 text-[13px]">
            {rule.source === "scanner" && (
              <li>
                Suggested by a scan finding: <Link className="link" to="/app/scans">Scans &amp; reports</Link>
              </li>
            )}
            {fromAlert && (
              <li>
                Promoted from alert <Link className="link font-mono" to={`/app/alerts/${fromAlert}`}>{fromAlert}</Link>
              </li>
            )}
          </ul>
        </Block>
      )}
    </div>
  );
}

type PanelProps = { rule: Rule | undefined; ruleId: string; position: number; total: number; onClose: () => void };

function NotFound({ ruleId }: { ruleId: string }) {
  return (
    <div className="space-y-2">
      <h2 className="text-xl font-semibold tracking-tight">Rule not found</h2>
      <p className="text-sm text-muted">
        No rule with id <span className="font-mono text-fg">{ruleId}</span> on this upstream. It may have been deleted.
      </p>
    </div>
  );
}

/** Inline right-hand panel on wide screens; Escape closes it. */
export function RulePanel({ rule, ruleId, position, total, onClose }: PanelProps) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    heading.current?.focus();
  }, [ruleId]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !document.querySelector("[role=dialog]")) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <aside aria-label="Rule details" className="sticky top-[calc(var(--topbar-h)+16px)] max-h-[calc(100vh-var(--topbar-h)-32px)] overflow-y-auto border-l border-border pl-6">
      <div className="mb-2 flex justify-end">
        <button type="button" onClick={onClose} aria-label="Close rule details" className="rounded-sm p-1 text-muted hover:bg-surface-2 hover:text-fg">
          <X className="size-4" aria-hidden />
        </button>
      </div>
      {rule ? <RuleDetailBody rule={rule} position={position} total={total} headingRef={heading} /> : <NotFound ruleId={ruleId} />}
    </aside>
  );
}

/** Drawer version for narrow screens (Radix: focus trap, Escape, focus return). */
export function RuleDrawer({ rule, ruleId, position, total, onClose }: PanelProps) {
  return (
    <Sheet open onOpenChange={(v) => !v && onClose()} title={rule ? "Rule details" : "Rule not found"} description={rule ? rule.name : undefined}>
      {rule ? <RuleDetailBody rule={rule} position={position} total={total} /> : <NotFound ruleId={ruleId} />}
    </Sheet>
  );
}

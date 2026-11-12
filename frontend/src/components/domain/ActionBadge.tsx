import { Ban, CheckCircle2, FileText, KeyRound, Timer, type LucideIcon } from "lucide-react";
import type { Action, Rule } from "@/api/schemas";
import { cn } from "@/lib/cn";

const config: Record<Action, { label: string; icon: LucideIcon; cls: string }> = {
  allow: { label: "Allow", icon: CheckCircle2, cls: "text-act-allow bg-act-allow/12 border-act-allow/30" },
  log: { label: "Log", icon: FileText, cls: "text-act-log bg-act-log/12 border-act-log/30" },
  block: { label: "Block", icon: Ban, cls: "text-act-block bg-act-block/12 border-act-block/30" },
  throttle: { label: "Throttle", icon: Timer, cls: "text-act-throttle bg-act-throttle/12 border-act-throttle/30" },
  challenge: { label: "Challenge", icon: KeyRound, cls: "text-act-challenge bg-act-challenge/12 border-act-challenge/30" },
};

/** Gateway action as color + icon + text. */
export function ActionBadge({ action, className }: { action: Action; className?: string }) {
  const c = config[action];
  const Icon = c.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium", c.cls, className)}>
      <Icon className="size-3" aria-hidden />
      {c.label}
    </span>
  );
}

export const actionMeaning: Record<Action, string> = {
  allow: "lets the request through and skips the remaining rules",
  log: "records the match and lets the request through",
  block: "rejects the request with 403 (in ENFORCE mode)",
  throttle: "rate-limits the caller and answers 429 over the limit (in ENFORCE mode)",
  challenge: "asks for credentials (401) unless the caller is authenticated (in ENFORCE mode)",
};

const sourceLabel: Record<Rule["source"], string> = {
  builtin: "Built-in",
  scanner: "Scanner",
  analyst: "Analyst",
  learner: "Learner",
};

export function SourceBadge({ source }: { source: Rule["source"] }) {
  return (
    <span className="inline-flex items-center rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[11px] font-medium text-muted">
      {sourceLabel[source]}
    </span>
  );
}

const list = (v: string | string[]) => ([] as string[]).concat(v);

/** Read-only, one-line description of what a rule matches. Handles list-valued method and ip. */
export function matchSummary(match: Rule["match"]): string[] {
  const parts: string[] = [];
  if (match.method !== undefined) parts.push(`method ${list(match.method).join(" | ")}`);
  if (match.path) parts.push(`path ${match.path}`);
  if (match.signature) parts.push(`signature ${match.signature}`);
  if (match.ip !== undefined) {
    const ips = list(match.ip);
    parts.push(`IP range ${ips.slice(0, 2).join(", ")}${ips.length > 2 ? ` +${ips.length - 2}` : ""}`);
  }
  if (match.header) parts.push(`header ${Object.keys(match.header).join(", ")}`);
  if (match.condition) parts.push(`condition ${match.condition}`);
  return parts.length ? parts : ["every request"];
}

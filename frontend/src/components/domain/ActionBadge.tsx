import type { Action, Rule } from "@/api/schemas";
import { cn } from "@/lib/cn";

const label: Record<Action, string> = { allow: "Allow", log: "Log", block: "Block", throttle: "Throttle", challenge: "Challenge" };

/** A small mark per action: filled for actions that stop a request in ENFORCE, hollow for pass-through. */
const mark: Record<Action, string> = {
  block: "bg-act-block border-act-block",
  throttle: "bg-act-throttle border-act-throttle",
  challenge: "bg-act-challenge border-act-challenge",
  log: "border-act-log bg-transparent",
  allow: "border-act-allow bg-transparent rounded-full",
};

/** Gateway action as text plus a mark. No pill, no icon. */
export function ActionTag({ action, className }: { action: Action; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap", className)}>
      <span aria-hidden className={cn("inline-block size-2 shrink-0 border", mark[action])} />
      <span className={action === "block" ? "font-medium text-act-block" : "text-fg"}>{label[action]}</span>
    </span>
  );
}

/** Kept for existing imports: same component. */
export const ActionBadge = ActionTag;

export const actionMeaning: Record<Action, string> = {
  allow: "lets the request through and skips the remaining rules",
  log: "records the match and lets the request through",
  block: "rejects the request with 403 (in ENFORCE mode)",
  throttle: "rate-limits the caller and answers 429 over the limit (in ENFORCE mode)",
  challenge: "asks for credentials (401) unless the caller is authenticated (in ENFORCE mode)",
};

export const sourceLabel: Record<Rule["source"], string> = {
  builtin: "Built-in",
  scanner: "Scanner",
  analyst: "Analyst",
  learner: "Learner",
};

export function SourceBadge({ source }: { source: Rule["source"] }) {
  return <span className="font-mono text-xs text-muted">{sourceLabel[source]}</span>;
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

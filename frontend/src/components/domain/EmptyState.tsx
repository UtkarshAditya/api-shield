import type { ReactNode } from "react";

/** One plain line of fact, an optional next step, and an optional action. No illustration. */
export function EmptyState({ title, body, action }: { title: string; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-8">
      <div className="space-y-1">
        <p className="font-mono text-sm text-fg">{title}</p>
        {body && <div className="text-sm text-muted">{body}</div>}
      </div>
      {action}
    </div>
  );
}

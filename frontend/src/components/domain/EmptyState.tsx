import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function EmptyState({ icon: Icon, title, body, action }: { icon: LucideIcon; title: string; body: ReactNode; action?: ReactNode }) {
  return (
    <div className="mx-auto flex max-w-md flex-col items-center gap-3 py-20 text-center">
      <div className="grid size-12 place-items-center rounded-xl border border-border bg-surface-2">
        <Icon className="size-6 text-accent" aria-hidden />
      </div>
      <h2 className="text-lg font-semibold">{title}</h2>
      <div className="text-sm leading-relaxed text-muted">{body}</div>
      {action}
    </div>
  );
}

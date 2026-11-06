import type { HTMLAttributes, ReactNode } from "react";
import { AlertTriangle, RotateCw } from "lucide-react";
import { cn } from "@/lib/cn";
import { Button } from "./Button";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <section className={cn("rounded-xl border border-border bg-surface", className)} {...props} />;
}

export function CardHeader({ title, action, hint }: { title: ReactNode; action?: ReactNode; hint?: ReactNode }) {
  return (
    <header className="flex items-center justify-between gap-3 px-5 pt-4 pb-3">
      <div className="flex items-center gap-1.5">
        <h2 className="text-sm font-semibold text-fg">{title}</h2>
        {hint}
      </div>
      {action}
    </header>
  );
}

export function CardError({ onRetry, message = "Couldn't load this panel." }: { onRetry: () => void; message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-5 py-10 text-center text-sm text-muted" role="alert">
      <AlertTriangle className="size-5 text-sev-high" aria-hidden />
      <p>{message}</p>
      <Button size="sm" variant="secondary" onClick={onRetry}>
        <RotateCw className="size-3.5" aria-hidden /> Retry
      </Button>
    </div>
  );
}

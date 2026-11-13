import type { HTMLAttributes, ReactNode } from "react";
import { RotateCw } from "lucide-react";
import { cn } from "@/lib/cn";
import { Button } from "./Button";

/** A framed container: only for what needs framing (tables, charts, lists). Flat, hairline, 4 px. */
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <section className={cn("rounded-lg border border-border bg-surface", className)} {...props} />;
}

/** Header strip of a framed container: mono caps label, hairline beneath. */
export function CardHeader({ title, action, hint }: { title: ReactNode; action?: ReactNode; hint?: ReactNode }) {
  return (
    <header className="flex min-h-10 items-center justify-between gap-3 border-b border-border px-4 py-2">
      <div className="flex items-center gap-1.5">
        <h2 className="eyebrow text-fg">{title}</h2>
        {hint}
      </div>
      {action}
    </header>
  );
}

export function CardError({ onRetry, message = "This panel did not load." }: { onRetry: () => void; message?: string }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-6 text-sm" role="alert">
      <p>
        <span className="mr-2 inline-block size-2 bg-signal-mark align-middle" aria-hidden />
        {message}
      </p>
      <Button size="sm" variant="secondary" onClick={onRetry}>
        <RotateCw className="size-3.5" aria-hidden /> Retry
      </Button>
    </div>
  );
}

import { forwardRef, type HTMLAttributes, type ReactNode, type TdHTMLAttributes, type ThHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

/** Page header: large title left, actions right, one muted line of description beneath. */
export function PageHeader({ title, description, actions, meta }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; meta?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3 pb-1">
      <div className="min-w-0 space-y-1.5">
        {meta && <div className="eyebrow">{meta}</div>}
        <h1 className="text-title font-semibold">{title}</h1>
        {description && <p className="max-w-3xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

/** A section on the page surface: mono caps header with a hairline beneath. No box. */
export function Section({ title, action, children, className, id, description }: {
  title: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
  description?: ReactNode;
}) {
  return (
    <section className={cn("min-w-0", className)} aria-labelledby={id}>
      <header className="mb-3 flex min-h-8 items-end justify-between gap-3 border-b border-border pb-2">
        <div className="min-w-0">
          <h2 id={id} className="eyebrow text-fg">
            {title}
          </h2>
          {description && <p className="mt-1 text-xs text-muted">{description}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

export function Mono({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("font-mono text-[13px]", className)} {...props} />;
}

/* ---- DataTable: one compact density, 40 px rows, sticky header, ink bar on row hover ---- */

export function DataTable({ caption, children, className, maxHeight }: { caption: string; children: ReactNode; className?: string; maxHeight?: string }) {
  return (
    <div className={cn("overflow-auto", className)} style={maxHeight ? { maxHeight } : undefined}>
      <table className="w-full border-collapse text-sm">
        <caption className="sr-only">{caption}</caption>
        {children}
      </table>
    </div>
  );
}

/** Sticky header; `framed` when the table sits in a bordered surface container. */
export function THead({ children, framed }: { children: ReactNode; framed?: boolean }) {
  return (
    <thead className={cn("sticky top-0 z-10", framed ? "bg-surface" : "bg-bg")}>
      <tr className="text-left">{children}</tr>
    </thead>
  );
}

export function Th({ className, align, ...props }: ThHTMLAttributes<HTMLTableCellElement> & { align?: "right" }) {
  return (
    <th
      scope="col"
      className={cn("eyebrow h-9 border-b border-border px-3 font-medium whitespace-nowrap first:pl-4 last:pr-4", align === "right" && "text-right", className)}
      {...props}
    />
  );
}

export const Tr = forwardRef<HTMLTableRowElement, HTMLAttributes<HTMLTableRowElement> & { active?: boolean; "data-rule"?: string }>(function Tr({ className, active, ...props }, ref) {
  return (
    <tr
      ref={ref}
      className={cn(
        "h-10 border-b border-border/70 transition-shadow ease-ui last:border-b-0 hover:shadow-[inset_2px_0_0_var(--text)]",
        active && "bg-surface-2 shadow-[inset_2px_0_0_var(--text)]",
        className,
      )}
      {...props}
    />
  );
});

export function Td({ className, align, mono, ...props }: TdHTMLAttributes<HTMLTableCellElement> & { align?: "right"; mono?: boolean }) {
  return (
    <td
      className={cn("px-3 py-1.5 align-middle first:pl-4 last:pr-4", align === "right" && "text-right", mono && "font-mono text-[13px]", className)}
      {...props}
    />
  );
}

/** Inline status dot + mono text (e.g. "Learning active"). */
export function StatusDot({ tone = "muted", children, className }: { tone?: "ok" | "signal" | "muted" | "ink"; children: ReactNode; className?: string }) {
  const color = { ok: "bg-ok", signal: "bg-signal-mark", muted: "bg-border-strong", ink: "bg-fg" }[tone];
  return (
    <span className={cn("inline-flex items-center gap-1.5 font-mono text-xs", className)}>
      <span aria-hidden className={cn("inline-block size-1.5 rounded-full", color)} />
      {children}
    </span>
  );
}

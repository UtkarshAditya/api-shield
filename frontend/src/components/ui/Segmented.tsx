import { cn } from "@/lib/cn";

type Props<T extends string> = { value: T; options: readonly T[]; onChange: (v: T) => void; label: string };

export function Segmented<T extends string>({ value, options, onChange, label }: Props<T>) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-md border border-border bg-surface-2 p-0.5">
      {options.map((o) => (
        <button
          key={o}
          role="radio"
          aria-checked={o === value}
          onClick={() => onChange(o)}
          className={cn(
            "rounded px-2.5 py-1 text-xs font-medium transition-colors",
            o === value ? "bg-surface text-fg shadow-sm" : "text-muted hover:text-fg",
          )}
        >
          {o}
        </button>
      ))}
    </div>
  );
}

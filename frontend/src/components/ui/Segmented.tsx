import { cn } from "@/lib/cn";

type Props<T extends string> = { value: T; options: readonly T[]; onChange: (v: T) => void; label: string };

/** Hairline segmented control; the active segment is ink-filled. */
export function Segmented<T extends string>({ value, options, onChange, label }: Props<T>) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex border border-border-strong">
      {options.map((o, i) => (
        <button
          key={o}
          type="button"
          role="radio"
          aria-checked={o === value}
          onClick={() => onChange(o)}
          className={cn(
            "h-7 px-2.5 font-mono text-xs transition-colors ease-ui",
            i > 0 && "border-l border-border-strong",
            o === value ? "bg-accent text-accent-fg" : "text-muted hover:text-fg",
          )}
        >
          {o}
        </button>
      ))}
    </div>
  );
}

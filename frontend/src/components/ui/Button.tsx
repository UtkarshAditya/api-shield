import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

/** Primary = ink-filled; secondary = hairline outline; danger = the signal color. No teal, no shadows. */
const variants: Record<Variant, string> = {
  primary: "bg-accent text-accent-fg border border-accent hover:bg-accent/85",
  secondary: "bg-transparent text-fg border border-border-strong hover:border-fg",
  ghost: "text-muted border border-transparent hover:text-fg hover:bg-surface-2",
  danger: "bg-signal-mark text-surface border border-signal-mark hover:bg-signal",
};

const sizes: Record<Size, string> = {
  sm: "h-7 px-2.5 text-[13px] gap-1.5",
  md: "h-8 px-3.5 text-sm gap-2",
  lg: "h-10 px-5 text-sm gap-2",
};

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size };

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "primary", size = "md", type = "button", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(
        "inline-flex items-center justify-center rounded-sm font-medium whitespace-nowrap transition-colors ease-ui disabled:pointer-events-none disabled:opacity-45",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  );
});

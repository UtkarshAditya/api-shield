import { cn } from "@/lib/cn";

/** Flat loading block; the pulse is disabled by prefers-reduced-motion (tokens.css). */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("animate-pulse rounded-sm bg-surface-2", className)} />;
}

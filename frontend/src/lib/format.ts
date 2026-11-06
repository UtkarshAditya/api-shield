const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const full = new Intl.NumberFormat("en");
const pct = new Intl.NumberFormat("en", { style: "percent", maximumFractionDigits: 1 });

export const formatCompact = (n: number) => compact.format(n);
export const formatNumber = (n: number) => full.format(n);
export const formatPercent = (ratio: number) => pct.format(ratio);
export const formatMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${Math.round(ms)} ms`);

export function formatDelta(ratio: number) {
  const sign = ratio > 0 ? "+" : ratio < 0 ? "−" : "±";
  return `${sign}${pct.format(Math.abs(ratio))}`;
}

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

export function formatRelative(iso: string, now = Date.now()) {
  const diffSec = Math.round((new Date(iso).getTime() - now) / 1000);
  const abs = Math.abs(diffSec);
  if (abs < 60) return rtf.format(diffSec, "second");
  if (abs < 3600) return rtf.format(Math.round(diffSec / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diffSec / 3600), "hour");
  return rtf.format(Math.round(diffSec / 86400), "day");
}

export function formatTimeTick(iso: string, range: "1h" | "24h" | "7d") {
  const d = new Date(iso);
  if (range === "7d") return d.toLocaleDateString("en", { weekday: "short" });
  return d.toLocaleTimeString("en", { hour: "2-digit", minute: "2-digit", hour12: false });
}

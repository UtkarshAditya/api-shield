import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, type TooltipProps } from "recharts";
import type { Range, Timeseries } from "@/api/schemas";
import { formatCompact, formatNumber, formatTimeTick } from "@/lib/format";

const series = [
  { key: "allowed", label: "Allowed", color: "var(--chart-allowed)" },
  { key: "blocked", label: "Blocked", color: "var(--chart-blocked)" },
] as const;

const axisTick = { fill: "var(--text-muted)", fontSize: 11, fontFamily: "var(--font-mono)" };

/** Headroom above the highest point so a spike and its axis label are never clipped. */
function niceMax(max: number) {
  if (max <= 0) return 10;
  const padded = max * 1.12;
  const mag = 10 ** Math.floor(Math.log10(padded));
  return Math.ceil(padded / mag) * mag;
}

function ChartTooltip({ active, payload, label, range }: TooltipProps<number, string> & { range: Range }) {
  if (!active || !payload?.length) return null;
  const d = new Date(String(label));
  return (
    <div className="rounded-sm bg-fg px-2.5 py-2 font-mono text-xs text-bg">
      <p className="mb-1 opacity-70">
        {range === "7d" ? d.toLocaleString("en", { weekday: "short", hour: "2-digit", minute: "2-digit" }) : d.toLocaleTimeString("en", { hour: "2-digit", minute: "2-digit" })}
      </p>
      {series.map((s) => (
        <p key={s.key} className="flex gap-4">
          <span>{s.label}</span>
          <span className="ml-auto">{formatNumber(payload.find((p) => p.dataKey === s.key)?.value ?? 0)}</span>
        </p>
      ))}
    </div>
  );
}

export function TrafficLegend() {
  return (
    <ul className="flex items-center gap-4 font-mono text-[11px] text-muted" aria-label="Legend">
      {series.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <span className="h-0.5 w-4" style={{ background: s.color }} aria-hidden />
          {s.label}
        </li>
      ))}
    </ul>
  );
}

/** Crisp lines, no fills: allowed in ink, blocked in vermilion, hairline grid, mono axes. */
export function TrafficChart({ data, range }: { data: Timeseries; range: Range }) {
  const totalBlocked = data.points.reduce((s, p) => s + p.blocked, 0);
  const total = data.points.reduce((s, p) => s + p.allowed + p.blocked, 0);
  const top = niceMax(Math.max(0, ...data.points.map((p) => Math.max(p.allowed, p.blocked))));
  return (
    <figure className="h-72 w-full">
      <ResponsiveContainer>
        <LineChart data={data.points} margin={{ top: 12, right: 28, left: 4, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
          <XAxis dataKey="t" tickFormatter={(v) => formatTimeTick(v, range)} tick={axisTick} axisLine={{ stroke: "var(--border)" }} tickLine={false} minTickGap={48} />
          <YAxis tickFormatter={formatCompact} tick={axisTick} axisLine={false} tickLine={false} width={48} domain={[0, top]} allowDecimals={false} />
          <Tooltip content={<ChartTooltip range={range} />} cursor={{ stroke: "var(--border-strong)" }} />
          {series.map((s) => (
            <Line
              key={s.key}
              type="linear"
              dataKey={s.key}
              stroke={s.color}
              strokeWidth={s.key === "blocked" ? 1.75 : 1.5}
              dot={false}
              activeDot={{ r: 3, stroke: "var(--surface)", strokeWidth: 1.5, fill: s.color }}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
      <figcaption className="sr-only">
        Requests over the last {range}: {formatNumber(total)} total, {formatNumber(totalBlocked)} blocked.
      </figcaption>
    </figure>
  );
}

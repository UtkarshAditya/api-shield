import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, type TooltipProps } from "recharts";
import type { Range, Timeseries } from "@/api/schemas";
import { formatCompact, formatNumber, formatTimeTick } from "@/lib/format";

const series = [
  { key: "allowed", label: "Allowed", color: "var(--chart-allowed)" },
  { key: "blocked", label: "Blocked", color: "var(--chart-blocked)" },
] as const;

function ChartTooltip({ active, payload, label, range }: TooltipProps<number, string> & { range: Range }) {
  if (!active || !payload?.length) return null;
  const d = new Date(String(label));
  return (
    <div className="rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs shadow-xl">
      <p className="mb-1.5 text-muted">
        {range === "7d" ? d.toLocaleString("en", { weekday: "short", hour: "2-digit", minute: "2-digit" }) : d.toLocaleTimeString("en", { hour: "2-digit", minute: "2-digit" })}
      </p>
      {series.map((s) => {
        const v = payload.find((p) => p.dataKey === s.key)?.value ?? 0;
        return (
          <p key={s.key} className="flex items-center gap-2 tabular-nums">
            <span className="size-2 rounded-full" style={{ background: s.color }} aria-hidden />
            <span className="text-muted">{s.label}</span>
            <span className="ml-auto pl-4 font-medium text-fg">{formatNumber(v)}</span>
          </p>
        );
      })}
    </div>
  );
}

export function TrafficLegend() {
  return (
    <ul className="flex items-center gap-4 text-xs text-muted" aria-label="Legend">
      {series.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <span className="h-0.5 w-3 rounded" style={{ background: s.color }} aria-hidden />
          {s.label}
        </li>
      ))}
    </ul>
  );
}

export function TrafficChart({ data, range }: { data: Timeseries; range: Range }) {
  const totalBlocked = data.points.reduce((s, p) => s + p.blocked, 0);
  const total = data.points.reduce((s, p) => s + p.allowed + p.blocked, 0);
  return (
    <figure className="h-80 w-full">
      <ResponsiveContainer>
        <AreaChart data={data.points} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <defs>
            {series.map((s) => (
              <linearGradient key={s.key} id={`fill-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={s.color} stopOpacity={0.28} />
                <stop offset="100%" stopColor={s.color} stopOpacity={0.02} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
          <XAxis
            dataKey="t"
            tickFormatter={(v) => formatTimeTick(v, range)}
            tick={{ fill: "var(--text-muted)", fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            minTickGap={40}
          />
          <YAxis tickFormatter={formatCompact} tick={{ fill: "var(--text-muted)", fontSize: 11 }} axisLine={false} tickLine={false} width={44} />
          <Tooltip content={<ChartTooltip range={range} />} cursor={{ stroke: "var(--text-muted)", strokeDasharray: "3 3" }} />
          {series.map((s) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              stroke={s.color}
              strokeWidth={2}
              fill={`url(#fill-${s.key})`}
              activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
      <figcaption className="sr-only">
        Requests over the last {range}: {formatNumber(total)} total, {formatNumber(totalBlocked)} blocked.
      </figcaption>
    </figure>
  );
}

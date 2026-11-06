import { severityForScore, SeverityBadge } from "./SeverityBadge";

/** Semicircle gauge 0–10. Color reinforces the severity badge below it. */
export function RiskGauge({ score }: { score: number }) {
  const sev = severityForScore(score);
  const r = 80;
  const len = Math.PI * r;
  const frac = Math.min(1, Math.max(0, score / 10));
  const color = `var(--sev-${sev})`;
  const angle = Math.PI * (1 - frac);
  const nx = 100 + r * Math.cos(angle);
  const ny = 100 - r * Math.sin(angle);

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 200 116" className="w-full max-w-[240px]" role="img" aria-label={`API risk score ${score.toFixed(1)} out of 10, ${sev}`}>
        <defs>
          <linearGradient id="gauge-track" x1="0" x2="1">
            <stop offset="0%" stopColor="var(--sev-low)" stopOpacity="0.25" />
            <stop offset="50%" stopColor="var(--sev-medium)" stopOpacity="0.25" />
            <stop offset="100%" stopColor="var(--sev-critical)" stopOpacity="0.25" />
          </linearGradient>
        </defs>
        <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="url(#gauge-track)" strokeWidth="14" strokeLinecap="round" />
        <path
          d="M20 100 A80 80 0 0 1 180 100"
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={len}
          strokeDashoffset={len * (1 - frac)}
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(.2,.8,.2,1)" }}
        />
        <circle cx={nx} cy={ny} r="6" fill="var(--surface)" stroke={color} strokeWidth="3" />
        <text x="100" y="92" textAnchor="middle" className="fill-[var(--text)] font-semibold" fontSize="34">
          {score.toFixed(1)}
        </text>
        <text x="100" y="110" textAnchor="middle" className="fill-[var(--text-muted)]" fontSize="10">
          out of 10
        </text>
      </svg>
      <SeverityBadge severity={sev} className="-mt-1" />
    </div>
  );
}

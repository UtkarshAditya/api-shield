/**
 * The vault scene, built as stacked layers so each can be animated independently:
 *   1. back:    wall glow, frame ring, hinges, the light behind the door
 *   2. door:    its own <svg> in a div so it can swing open with a CSS 3D rotation
 *   3. overlay: tools, scanner beam, weak-spot markers, keys, the "stranger"
 *   4. HTML:    labels, rule chips, counter, alert card (real text, legible at any size)
 * Elements carry `v-*` class names that the GSAP timeline targets.
 * The default markup is the calm, locked state, which is what reduced-motion users see.
 */
import { EyeOff } from "lucide-react";

const C = 400; // centre of the 800×800 viewBox
const KEYHOLE = { x: 400, y: 574 };
const HINGE = { x: 110, y: 295 };
const boltAngles = [0, 45, 90, 135, 180, 225, 270, 315];

function polar(r: number, deg: number) {
  const a = (deg * Math.PI) / 180;
  return { x: C + r * Math.cos(a), y: C + r * Math.sin(a) };
}

function BackLayer() {
  return (
    <svg viewBox="0 0 800 800" className="absolute inset-0 size-full overflow-visible" aria-hidden>
      <defs>
        <radialGradient id="v-rim" cx="50%" cy="50%" r="50%">
          <stop offset="60%" stopColor="#4f9a89" stopOpacity="0" />
          <stop offset="78%" stopColor="#4f9a89" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#4f9a89" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="v-metal" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#3b4857" />
          <stop offset="45%" stopColor="#1c2530" />
          <stop offset="100%" stopColor="#2c3846" />
        </linearGradient>
        <radialGradient id="v-interior" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#e7e5df" />
          <stop offset="45%" stopColor="#9fd0c3" />
          <stop offset="100%" stopColor="#0d9488" stopOpacity="0.6" />
        </radialGradient>
      </defs>
      <circle className="v-rim" cx={C} cy={C} r={390} fill="url(#v-rim)" style={{ opacity: 0.5 }} />
      <circle cx={C} cy={C} r={300} fill="none" stroke="url(#v-metal)" strokeWidth={46} />
      <circle cx={C} cy={C} r={324} fill="none" stroke="#33404e" strokeWidth={1.5} />
      <circle cx={C} cy={C} r={277} fill="none" stroke="#0a0f15" strokeWidth={3} />
      <circle cx={C} cy={C} r={276} fill="#030508" />
      <circle className="v-light" cx={C} cy={C} r={276} fill="url(#v-interior)" style={{ opacity: 0 }} />
      {[255, 465].map((y) => (
        <g key={y}>
          <rect x={86} y={y} width={48} height={82} rx={9} fill="url(#v-metal)" stroke="#475668" strokeWidth={2} />
          <rect x={98} y={y + 10} width={24} height={62} rx={5} fill="#141b24" />
        </g>
      ))}
    </svg>
  );
}

function DoorLayer() {
  return (
    <div className="v-door absolute inset-0" style={{ transformStyle: "preserve-3d" }}>
      <svg viewBox="0 0 800 800" className="absolute inset-0 size-full overflow-visible" aria-hidden>
        <defs>
          <radialGradient id="v-door" cx="42%" cy="38%" r="70%">
            <stop offset="0%" stopColor="#334253" />
            <stop offset="60%" stopColor="#1a232e" />
            <stop offset="100%" stopColor="#10161e" />
          </radialGradient>
          <linearGradient id="v-bolt" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#b8c4d0" />
            <stop offset="100%" stopColor="#5d6b7a" />
          </linearGradient>
          <radialGradient id="v-hub" cx="40%" cy="35%" r="70%">
            <stop offset="0%" stopColor="#7d8d9e" />
            <stop offset="100%" stopColor="#2a3542" />
          </radialGradient>
        </defs>

        {/* bolts sit under the door body and slide out into the frame */}
        {boltAngles.map((a) => (
          <g key={a} transform={`rotate(${a} ${C} ${C})`}>
            <rect className="v-bolt" x={640} y={387} width={72} height={26} rx={6} fill="url(#v-bolt)" stroke="#4b5968" />
          </g>
        ))}

        <circle cx={C} cy={C} r={270} fill="url(#v-door)" stroke="#3f4d5d" strokeWidth={3} />
        <circle cx={C} cy={C} r={256} fill="none" stroke="#0b1016" strokeWidth={2} />
        {Array.from({ length: 72 }, (_, i) => {
          const a = polar(228, i * 5);
          const b = polar(i % 6 === 0 ? 244 : 238, i * 5);
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#3a4757" strokeWidth={i % 6 === 0 ? 2.5 : 1.2} />;
        })}
        {Array.from({ length: 24 }, (_, i) => {
          const p = polar(250, i * 15 + 7.5);
          return <circle key={i} cx={p.x} cy={p.y} r={4} fill="#44525f" stroke="#0c1117" />;
        })}
        <circle cx={C} cy={C} r={192} fill="none" stroke="#202a36" strokeWidth={20} />
        <circle className="v-door-rim" cx={C} cy={C} r={192} fill="none" stroke="#6db3a2" strokeWidth={1.5} style={{ opacity: 0.15 }} />

        {/* keyhole plate */}
        <rect x={370} y={546} width={60} height={78} rx={11} fill="#18212c" stroke="#4c5b6b" strokeWidth={2} />
        <circle cx={KEYHOLE.x} cy={KEYHOLE.y} r={9} fill="#010203" />
        <path d="M394 578 L391 606 L409 606 L406 578Z" fill="#010203" />

        {/* wheel handle */}
        <g className="v-wheel">
          {[0, 60, 120].map((a) => {
            const p1 = polar(128, a);
            const p2 = polar(128, a + 180);
            return (
              <g key={a}>
                <line x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y} stroke="#6f7f90" strokeWidth={12} strokeLinecap="round" />
                <circle cx={p1.x} cy={p1.y} r={13} fill="#9aa9b8" stroke="#3b4856" strokeWidth={2} />
                <circle cx={p2.x} cy={p2.y} r={13} fill="#9aa9b8" stroke="#3b4856" strokeWidth={2} />
              </g>
            );
          })}
          <circle cx={C} cy={C} r={100} fill="none" stroke="#56677a" strokeWidth={9} />
          <circle cx={C} cy={C} r={38} fill="url(#v-hub)" stroke="#8796a6" strokeWidth={3} />
          <circle className="v-hub-light" cx={C} cy={C} r={10} fill="#6db3a2" />
        </g>
      </svg>
    </div>
  );
}

const keyStarts = Array.from({ length: 30 }, (_, i) => {
  // deterministic scatter so the scene is identical on every load
  const r1 = (Math.sin(i * 12.9898) * 43758.5453) % 1;
  const r2 = (Math.sin(i * 78.233) * 12345.678) % 1;
  return { i, sx: 560 + Math.abs(r1) * 300, sy: -80 + Math.abs(r2) * 360, ex: 460 + Math.abs(r2) * 360, ey: 660 + Math.abs(r1) * 220, rot: r1 * 540 };
});
export { keyStarts };

function OverlayLayer() {
  return (
    <svg viewBox="0 0 800 800" className="absolute inset-0 size-full overflow-visible" aria-hidden>
      <defs>
        <clipPath id="v-door-clip">
          <circle cx={C} cy={C} r={270} />
        </clipPath>
        <linearGradient id="v-beam" x1="0" x2="1">
          <stop offset="0%" stopColor="#6db3a2" stopOpacity="0" />
          <stop offset="50%" stopColor="#9fd0c3" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#6db3a2" stopOpacity="0" />
        </linearGradient>
        <symbol id="v-key" viewBox="0 0 40 16">
          <circle cx="7" cy="8" r="5.5" fill="none" stroke="currentColor" strokeWidth="2.5" />
          <path d="M12.5 8H38M31 8v5M36 8v4" stroke="currentColor" strokeWidth="2.5" fill="none" strokeLinecap="round" />
        </symbol>
        <filter id="v-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="4" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* scanner beam + grid, clipped to the door */}
      <g clipPath="url(#v-door-clip)">
        <rect className="v-beam" x={0} y={100} width={90} height={600} fill="url(#v-beam)" style={{ opacity: 0 }} />
        <g className="v-scangrid" style={{ opacity: 0 }}>
          {Array.from({ length: 14 }, (_, i) => (
            <line key={i} x1={130 + i * 40} y1={100} x2={130 + i * 40} y2={700} stroke="#6db3a2" strokeOpacity={0.12} />
          ))}
        </g>
      </g>

      {/* weak spots (red) and their fixed state (verdigris) */}
      {[
        { cls: "v-weak1", fix: "v-fixed1", ...KEYHOLE },
        { cls: "v-weak2", fix: "v-fixed2", ...HINGE },
      ].map((w) => (
        <g key={w.cls}>
          <g className={w.cls} style={{ opacity: 0 }}>
            <circle cx={w.x} cy={w.y} r={24} fill="#f0623c" fillOpacity={0.18} stroke="#f0623c" strokeWidth={2.5} />
            <circle cx={w.x} cy={w.y} r={24} fill="none" stroke="#f0623c" strokeWidth={2} className="origin-center animate-ping [transform-box:fill-box]" />
          </g>
          <g className={w.fix} style={{ opacity: 0 }}>
            <circle cx={w.x} cy={w.y} r={24} fill="#4f9a89" fillOpacity={0.2} stroke="#6db3a2" strokeWidth={2.5} />
            <path d={`M${w.x - 9} ${w.y} l6 6 l12 -12`} stroke="#9fd0c3" strokeWidth={3.5} fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </g>
        </g>
      ))}

      {/* lockpick: tip at the keyhole, body angled down-right */}
      <g transform={`translate(${KEYHOLE.x} ${KEYHOLE.y}) rotate(32)`}>
        <g className="v-pick" style={{ opacity: 0 }}>
          <path d="M0 0 q-3 -10 8 -12" stroke="#cfd8e2" strokeWidth={3} fill="none" strokeLinecap="round" />
          <line x1={0} y1={0} x2={180} y2={0} stroke="#cfd8e2" strokeWidth={3.5} strokeLinecap="round" />
          <rect x={176} y={-10} width={96} height={20} rx={10} fill="#d8431f" />
        </g>
      </g>

      {/* crowbar: tip at the upper hinge, coming in from the left */}
      <g transform={`translate(${HINGE.x + 6} ${HINGE.y}) rotate(196)`}>
        <g className="v-crowbar" style={{ opacity: 0 }}>
          <path d="M0 0 C -4 -16, -22 -20, -32 -10" stroke="#a3adb8" strokeWidth={10} fill="none" strokeLinecap="round" />
          <line x1={0} y1={0} x2={280} y2={0} stroke="#a3adb8" strokeWidth={11} strokeLinecap="round" />
          <rect x={210} y={-8} width={76} height={16} rx={8} fill="#b93716" />
        </g>
      </g>

      <g className="v-sparks" transform={`translate(${HINGE.x + 4} ${HINGE.y})`} style={{ opacity: 0 }}>
        {Array.from({ length: 12 }, (_, i) => {
          const a = (i * 30 * Math.PI) / 180;
          return <line key={i} x1={Math.cos(a) * 12} y1={Math.sin(a) * 12} x2={Math.cos(a) * (28 + (i % 3) * 10)} y2={Math.sin(a) * (28 + (i % 3) * 10)} stroke="#e0954a" strokeWidth={2.5} strokeLinecap="round" />;
        })}
      </g>

      {/* the flood of keys */}
      <g>
        {keyStarts.map((k) => (
          <use key={k.i} href="#v-key" className="v-key" width={34} height={14} style={{ opacity: 0, color: "#c8ad5e" }} />
        ))}
      </g>

      {/* the stranger: a payload *shape*, never its contents */}
      <g className="v-visitor" transform="translate(655 330)" style={{ opacity: 0 }}>
        <rect x={-110} y={-130} width={230} height={330} rx={18} fill="#0a0e13" fillOpacity={0.88} stroke="#243040" />
        <text x={-92} y={-102} fill="#94a3b4" fontSize={14} fontFamily="JetBrains Mono, monospace">
          shape #a91f
        </text>
        <ellipse cx={0} cy={10} rx={86} ry={96} fill="none" stroke="#94a3b4" strokeOpacity={0.5} strokeDasharray="5 6" />
        <text x={-38} y={124} fill="#94a3b4" fillOpacity={0.8} fontSize={12}>
          baseline
        </text>
        <g stroke="#6db3a2" strokeWidth={2}>
          <line x1={0} y1={-60} x2={-45} y2={-5} />
          <line x1={0} y1={-60} x2={45} y2={-5} />
          <line x1={-45} y1={-5} x2={-65} y2={55} />
          <line x1={-45} y1={-5} x2={-22} y2={55} />
          <line x1={45} y1={-5} x2={22} y2={55} />
          <line x1={45} y1={-5} x2={65} y2={55} />
        </g>
        {[
          [0, -60],
          [-45, -5],
          [45, -5],
          [-65, 55],
          [-22, 55],
          [22, 55],
          [65, 55],
        ].map(([x, y], i) => (
          <circle key={i} cx={x} cy={y} r={7} fill="#0a0e13" stroke="#6db3a2" strokeWidth={2.5} />
        ))}
        <g className="v-odd" stroke="#f0623c" strokeWidth={2.5} style={{ opacity: 0 }}>
          <line x1={65} y1={55} x2={88} y2={110} />
          <line x1={88} y1={110} x2={62} y2={160} />
          <line x1={88} y1={110} x2={100} y2={170} />
          <circle cx={88} cy={110} r={7} fill="#0a0e13" />
          <circle cx={62} cy={160} r={7} fill="#0a0e13" />
          <circle cx={100} cy={170} r={7} fill="#0a0e13" />
        </g>
      </g>

      {/* the legitimate key */}
      <g className="v-goodkey" style={{ opacity: 0 }} filter="url(#v-glow)">
        <line x1={KEYHOLE.x} y1={KEYHOLE.y} x2={KEYHOLE.x} y2={KEYHOLE.y + 70} stroke="#9fd0c3" strokeWidth={7} strokeLinecap="round" />
        <path d={`M${KEYHOLE.x} ${KEYHOLE.y + 14} h12 M${KEYHOLE.x} ${KEYHOLE.y + 28} h8`} stroke="#9fd0c3" strokeWidth={6} strokeLinecap="round" />
        <circle cx={KEYHOLE.x} cy={KEYHOLE.y + 92} r={22} fill="none" stroke="#9fd0c3" strokeWidth={7} />
      </g>
    </svg>
  );
}

const chip = "absolute rounded-lg border px-2.5 py-1.5 font-mono text-[10px] leading-tight shadow-lg backdrop-blur sm:text-xs";

function HtmlOverlays() {
  return (
    <div className="pointer-events-none absolute inset-0">
      <div className={`v-label1 ${chip} top-[76%] left-[56%] border-sev-critical/40 bg-bg/85 text-sev-critical`} style={{ opacity: 0 }}>
        GET /search · SQL injection
      </div>
      <div className={`v-label2 ${chip} top-[24%] left-[1%] border-sev-critical/40 bg-bg/85 text-sev-critical`} style={{ opacity: 0 }}>
        POST /login · no rate limit
      </div>

      <div className={`v-rule1 ${chip} top-[2%] left-[2%] border-accent/40 bg-bg/90 text-fg`} style={{ opacity: 0 }}>
        <span className="text-accent">✓ rule applied</span> block sqli on /search
        <span className="mt-0.5 block text-muted">source: scanner</span>
      </div>
      <div className={`v-rule2 ${chip} top-[13%] left-[2%] border-accent/40 bg-bg/90 text-fg`} style={{ opacity: 0 }}>
        <span className="text-accent">✓ rule applied</span> throttle /login 10/min
        <span className="mt-0.5 block text-muted">source: scanner</span>
      </div>

      <div className={`v-counter ${chip} top-[2%] right-[2%] min-w-[11rem] border-act-throttle/40 bg-bg/90 text-fg`} style={{ opacity: 0 }}>
        <span className="block text-muted">POST /login · last 60s</span>
        <span className="block">
          <span className="v-count tabular-nums">0</span> attempts
        </span>
        <span className="block text-act-throttle">
          <span className="v-throttled tabular-nums">0</span> throttled
        </span>
      </div>

      <div
        className="v-alert absolute bottom-[2%] left-[2%] w-[64%] rounded-xl border border-sev-critical/40 bg-bg/92 p-3 text-[10px] shadow-2xl backdrop-blur sm:text-xs"
        style={{ opacity: 0 }}
      >
        <div className="flex items-center gap-2">
          <span className="rounded-full border border-sev-critical/40 bg-sev-critical/12 px-1.5 py-px font-semibold text-sev-critical">#1 Critical</span>
          <span className="font-mono text-muted">caller key_9f3a••••</span>
        </div>
        <p className="mt-1.5 leading-snug text-fg">Unusual payload shape on GET /search, 14× faster than this caller's baseline.</p>
        <div className="mt-2 space-y-1">
          {[
            ["Request rate", 0.92],
            ["New shape", 0.7],
            ["Error ratio", 0.55],
          ].map(([label, w]) => (
            <div key={label as string} className="flex items-center gap-2">
              <span className="w-20 shrink-0 text-muted">{label}</span>
              <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                <span className="v-bar block h-full origin-left rounded-full bg-sev-critical" style={{ width: `${(w as number) * 100}%` }} />
              </span>
            </div>
          ))}
        </div>
        <p className="mt-2 inline-flex items-center gap-1 rounded border border-dashed border-border px-1.5 py-0.5 font-mono text-muted">
          <EyeOff className="size-3" aria-hidden /> q = redacted
        </p>
      </div>
    </div>
  );
}

export function VaultStage({ className }: { className?: string }) {
  return (
    <div className={`v-stage relative aspect-square ${className ?? ""}`} style={{ perspective: "1600px" }}>
      <BackLayer />
      <DoorLayer />
      <OverlayLayer />
      <HtmlOverlays />
    </div>
  );
}

export const VAULT = { KEYHOLE, HINGE, C };

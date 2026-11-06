import { useCallback, useRef, useState, useSyncExternalStore } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, ChevronDown, Brain, EyeOff, HardDrive, Lock, Pause, Play, ScanSearch, ShieldCheck, Timer } from "lucide-react";
import { cn } from "@/lib/cn";
import { chapters } from "./story";
import { useVaultTimeline } from "./useVaultTimeline";
import { VaultStage } from "./VaultStage";

function usePrefersReducedMotion() {
  return useSyncExternalStore(
    (cb) => {
      const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
      mq.addEventListener("change", cb);
      return () => mq.removeEventListener("change", cb);
    },
    () => window.matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
}

const MOTION_KEY = "apishield.landingMotion";

/** OS preference wins by default; the visitor can override it for this page. */
function useLandingMotion() {
  const osReduced = usePrefersReducedMotion();
  const [override, setOverride] = useState<"on" | "off" | null>(() => {
    try {
      const v = localStorage.getItem(MOTION_KEY);
      return v === "on" || v === "off" ? v : null;
    } catch {
      return null;
    }
  });
  const motion = override ? override === "on" : !osReduced;
  const toggle = () => {
    const next = motion ? "off" : "on";
    setOverride(next);
    try {
      localStorage.setItem(MOTION_KEY, next);
    } catch {
      /* ignore */
    }
    window.scrollTo(0, 0);
  };
  return { motion, toggle };
}

function TopNav({ motion, onToggleMotion }: { motion: boolean; onToggleMotion: () => void }) {
  return (
    <header className="fixed inset-x-0 top-0 z-40 flex h-16 items-center justify-between px-5 md:px-10">
      <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
        <ShieldCheck className="size-6 text-accent" aria-hidden />
        APIShield
      </Link>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onToggleMotion}
          aria-pressed={motion}
          className="inline-flex h-9 items-center gap-1.5 rounded-full px-3 text-xs text-muted hover:text-fg"
        >
          {motion ? <Pause className="size-3.5" aria-hidden /> : <Play className="size-3.5" aria-hidden />}
          {motion ? "Reduce motion" : "Play story"}
        </button>
        <Link
          to="/login"
          className="inline-flex h-9 items-center gap-1.5 rounded-full border border-border bg-bg/70 px-4 text-sm font-medium backdrop-blur hover:border-accent/60"
        >
          Sign in <ArrowRight className="size-3.5" aria-hidden />
        </Link>
      </div>
    </header>
  );
}

function Caption({ i, className }: { i: number; className?: string }) {
  const c = chapters[i];
  const hero = i === 0;
  return (
    <div className={className}>
      <p className={cn("mb-3 font-mono text-xs tracking-widest uppercase", hero ? "text-accent" : "text-accent/90")}>{c.eyebrow}</p>
      {hero ? (
        <h1 className="text-4xl leading-[1.05] font-semibold tracking-tight text-balance sm:text-6xl">{c.title}</h1>
      ) : (
        <h2 className="text-3xl leading-tight font-semibold tracking-tight text-balance sm:text-5xl">{c.title}</h2>
      )}
      <p className="mt-4 max-w-md text-base leading-relaxed text-muted sm:text-lg">{c.body}</p>
      {c.points && (
        <ul className="mt-5 flex flex-wrap gap-2">
          {c.points.map((p) => (
            <li key={p} className="rounded-full border border-border bg-surface/70 px-3 py-1 text-xs text-fg">
              {p}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AnimatedStory() {
  const root = useRef<HTMLElement>(null);
  const [active, setActive] = useState(0);
  const onChapter = useCallback((i: number) => setActive((prev) => (prev === i ? prev : i)), []);
  useVaultTimeline(root, true, onChapter);

  return (
    <section ref={root} className="relative h-screen overflow-hidden" aria-label="How APIShield protects your API">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_70%_45%,rgba(20,184,166,0.10),transparent_60%)]" />
      <div className="mx-auto flex h-full max-w-7xl flex-col items-center justify-center gap-6 px-5 pt-16 md:px-10 lg:flex-row lg:gap-12">
        <div className="relative order-2 h-[38vh] w-full max-w-xl lg:order-1 lg:h-auto lg:min-h-88 lg:flex-1">
          {chapters.map((_, i) => (
            <Caption key={i} i={i} className={`v-cap v-cap-${i} absolute inset-x-0 top-0 lg:top-1/2 lg:-translate-y-1/2`} />
          ))}
        </div>
        <VaultStage className="order-1 w-[min(86vw,46vh)] shrink-0 lg:order-2 lg:w-[min(78vh,46vw)]" />
      </div>

      <nav aria-label="Story chapters" className="v-chapters absolute top-1/2 right-4 hidden -translate-y-1/2 flex-col gap-3 md:flex">
        {chapters.map((c, i) => (
          <span key={c.id} className="group flex items-center justify-end gap-2" aria-current={active === i ? "step" : undefined}>
            <span className={cn("text-[10px] font-mono tracking-wider uppercase transition-opacity", active === i ? "text-fg opacity-100" : "opacity-0")}>
              {c.eyebrow.replace(/^\d+ · /, "")}
            </span>
            <span className={cn("block h-2 rounded-full transition-all", active === i ? "w-6 bg-accent" : "w-2 bg-border")} />
          </span>
        ))}
      </nav>

      <div className="v-scrollcue absolute bottom-6 left-1/2 flex -translate-x-1/2 flex-col items-center gap-1 text-xs text-muted">
        Scroll to begin
        <ChevronDown className="size-4 animate-bounce" aria-hidden />
      </div>
    </section>
  );
}

/** Reduced-motion version: the same story as stacked panels, nothing moves. */
function StaticStory() {
  return (
    <section className="mx-auto max-w-5xl space-y-16 px-5 pt-28 pb-10 md:px-10" aria-label="How APIShield protects your API">
      <div className="grid items-center gap-10 md:grid-cols-2">
        <Caption i={0} />
        <VaultStage className="w-full max-w-md justify-self-center" />
      </div>
      {chapters.slice(1).map((c, i) => (
        <Caption key={c.id} i={i + 1} className="border-l-2 border-accent/40 pl-6" />
      ))}
    </section>
  );
}

const pillars = [
  { icon: ScanSearch, title: "Scan", body: "Probe for the OWASP API Top 10. Get a risk-scored report with a fix and a suggested rule for every finding." },
  { icon: ShieldCheck, title: "Protect", body: "Auth checks, schema validation, rate limits and rules. Monitor first, enforce when you're ready." },
  { icon: Brain, title: "Learn", body: "Baselines your traffic's shape and flags what's new, ranked by endpoint risk and explained in plain English." },
];

const privacy = [
  { icon: HardDrive, title: "Self-hosted", body: "Runs next to your API. No third-party calls." },
  { icon: EyeOff, title: "Values redacted", body: "Payload values are masked at the edge." },
  { icon: Lock, title: "Shapes, not contents", body: "The learner only sees structure and rates." },
  { icon: Timer, title: "Retention you set", body: "Purge anytime. Default 14 days." },
];

function Closing() {
  return (
    <section className="relative z-10 border-t border-border bg-bg">
      <div className="mx-auto max-w-6xl px-5 py-24 md:px-10">
        <p className="font-mono text-xs tracking-widest text-accent uppercase">The loop</p>
        <h2 className="mt-3 max-w-2xl text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
          Findings become rules. Rules feed the learner. The learner knows which doors matter most.
        </h2>
        <div className="mt-12 grid gap-4 md:grid-cols-3">
          {pillars.map((p, i) => (
            <div key={p.title} className="relative rounded-2xl border border-border bg-surface p-6">
              <span className="absolute top-6 right-6 font-mono text-xs text-muted">0{i + 1}</span>
              <p.icon className="size-6 text-accent" aria-hidden />
              <h3 className="mt-4 text-lg font-semibold">{p.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">{p.body}</p>
            </div>
          ))}
        </div>

        <div className="mt-6 grid gap-px overflow-hidden rounded-2xl border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
          {privacy.map((p) => (
            <div key={p.title} className="flex gap-3 bg-surface-2 p-5">
              <p.icon className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden />
              <div>
                <p className="text-sm font-medium">{p.title}</p>
                <p className="mt-0.5 text-xs leading-relaxed text-muted">{p.body}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-20 flex flex-col items-center gap-5 text-center">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Step inside.</h2>
          <p className="max-w-md text-muted">See the demo: a scan, a one-click fix, an attack burst, and the alert that explains it.</p>
          <Link
            to="/login"
            className="inline-flex h-12 items-center gap-2 rounded-full bg-accent px-7 text-base font-semibold text-accent-fg shadow-[0_0_40px_-8px_var(--accent)] transition hover:brightness-110"
          >
            Enter dashboard <ArrowRight className="size-4" aria-hidden />
          </Link>
        </div>
      </div>
      <footer className="border-t border-border px-5 py-6 text-center text-xs text-muted">APIShield · self-hosted API security for small teams</footer>
    </section>
  );
}

export default function LandingPage() {
  const { motion, toggle } = useLandingMotion();
  return (
    <div className="dark min-h-screen overflow-x-clip bg-bg text-fg">
      <TopNav motion={motion} onToggleMotion={toggle} />
      {motion ? <AnimatedStory key="animated" /> : <StaticStory />}
      <Closing />
    </div>
  );
}

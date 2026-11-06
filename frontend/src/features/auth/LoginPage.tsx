import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, Loader2, ShieldCheck } from "lucide-react";
import { HttpError } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { roleLabel } from "@/auth/roles";
import type { Role } from "@/api/schemas";
import { Button } from "@/components/ui/Button";

const demoAccounts: { role: Role; email: string; blurb: string }[] = [
  { role: "admin", email: "admin@demo.local", blurb: "Everything, including enforce mode" },
  { role: "analyst", email: "analyst@demo.local", blurb: "Triage alerts, edit rules, run scans" },
  { role: "viewer", email: "viewer@demo.local", blurb: "Read-only" },
];

const input =
  "h-10 w-full rounded-md border border-border bg-surface-2 px-3 text-sm text-fg placeholder:text-muted focus:border-accent focus:outline-none";

function VaultMotif() {
  return (
    <svg viewBox="0 0 200 200" className="w-56 opacity-90" aria-hidden>
      <circle cx="100" cy="100" r="92" fill="none" stroke="var(--border)" strokeWidth="10" />
      <circle cx="100" cy="100" r="78" fill="var(--surface-2)" stroke="var(--border)" strokeWidth="2" />
      {Array.from({ length: 36 }, (_, i) => {
        const a = (i * 10 * Math.PI) / 180;
        return <line key={i} x1={100 + Math.cos(a) * 66} y1={100 + Math.sin(a) * 66} x2={100 + Math.cos(a) * 72} y2={100 + Math.sin(a) * 72} stroke="var(--border)" strokeWidth="1.5" />;
      })}
      <g className="origin-center animate-[spin_40s_linear_infinite]">
        {[0, 60, 120].map((d) => (
          <line key={d} x1="100" y1="58" x2="100" y2="142" stroke="var(--text-muted)" strokeWidth="5" strokeLinecap="round" transform={`rotate(${d} 100 100)`} />
        ))}
        <circle cx="100" cy="100" r="36" fill="none" stroke="var(--text-muted)" strokeWidth="4" />
      </g>
      <circle cx="100" cy="100" r="13" fill="var(--surface)" stroke="var(--accent)" strokeWidth="3" />
      <circle cx="100" cy="100" r="4" fill="var(--accent)" />
    </svg>
  );
}

export default function LoginPage() {
  const { login, status } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const redirectTo = (location.state as { from?: string } | null)?.from ?? "/app/overview";
  if (status === "authenticated") return <Navigate to={redirectTo} replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      navigate(redirectTo, { replace: true });
    } catch (err) {
      setError(err instanceof HttpError ? err.message : "Couldn't reach the server. Is the Admin API running?");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <aside className="relative hidden flex-col justify-between overflow-hidden border-r border-border bg-surface p-10 lg:flex">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_45%,color-mix(in_oklab,var(--accent)_14%,transparent),transparent_60%)]" />
        <Link to="/" className="relative inline-flex items-center gap-1.5 text-sm text-muted hover:text-fg">
          <ArrowLeft className="size-4" aria-hidden /> Back to the story
        </Link>
        <div className="relative flex flex-col items-center gap-8 text-center">
          <VaultMotif />
          <div>
            <p className="text-2xl font-semibold tracking-tight">The door opens for the right key.</p>
            <p className="mt-2 text-sm text-muted">APIShield learns your traffic's shape, never its contents.</p>
          </div>
        </div>
        <p className="relative text-xs text-muted">Self-hosted · nothing leaves your network</p>
      </aside>

      <main className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2">
            <ShieldCheck className="size-7 text-accent" aria-hidden />
            <span className="text-xl font-semibold tracking-tight">APIShield</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
          <p className="mt-1 text-sm text-muted">to your gateway dashboard</p>

          <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
            <div className="space-y-1.5">
              <label htmlFor="email" className="text-sm font-medium">
                Email
              </label>
              <input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} className={input} placeholder="you@company.com" />
            </div>
            <div className="space-y-1.5">
              <label htmlFor="password" className="text-sm font-medium">
                Password
              </label>
              <input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} className={input} />
            </div>
            {error && (
              <p role="alert" className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
                {error}
              </p>
            )}
            <Button type="submit" size="lg" className="w-full" disabled={submitting || !email || !password}>
              {submitting && <Loader2 className="size-4 animate-spin" aria-hidden />}
              Sign in
            </Button>
          </form>

          {import.meta.env.VITE_USE_MOCKS === "true" && (
            <div className="mt-8 rounded-xl border border-dashed border-border p-4">
              <p className="text-xs font-semibold tracking-wider text-muted uppercase">Demo accounts</p>
              <p className="mt-1 text-xs text-muted">
                Password for all: <code className="font-mono text-fg">demo</code>
              </p>
              <div className="mt-3 space-y-1.5">
                {demoAccounts.map((a) => (
                  <button
                    key={a.role}
                    type="button"
                    onClick={() => {
                      setEmail(a.email);
                      setPassword("demo");
                    }}
                    className="flex w-full items-center justify-between rounded-md px-2.5 py-2 text-left text-sm hover:bg-surface-2"
                  >
                    <span>
                      <span className="font-medium">{roleLabel[a.role]}</span>
                      <span className="block text-xs text-muted">{a.blurb}</span>
                    </span>
                    <span className="font-mono text-[11px] text-muted">{a.email}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

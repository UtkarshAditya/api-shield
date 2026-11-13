import { PageHeader } from "@/components/ui/Primitives";

const steps = [
  { title: "Add an upstream", body: "Point APIShield at the API to protect." },
  { title: "Run the first scan", body: "Safe, read-only probes for the OWASP API Top 10. Safe mode is on by default." },
  { title: "Start in MONITOR", body: "Nothing is blocked yet; rule matches are logged." },
  { title: "Let it learn", body: "The learner studies traffic shapes, never values, and flags what is unusual." },
];

export function Onboarding() {
  return (
    <div className="max-w-2xl space-y-6">
      <PageHeader title="Set up APIShield" description="No upstream is configured yet. Four steps." />
      <ol className="border-t border-border">
        {steps.map((s, i) => (
          <li key={s.title} className="grid grid-cols-[3rem_1fr] border-b border-border py-3">
            <span className="font-mono text-sm text-muted">{String(i + 1).padStart(2, "0")}</span>
            <div>
              <p className="font-medium">{s.title}</p>
              <p className="text-sm text-muted">{s.body}</p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

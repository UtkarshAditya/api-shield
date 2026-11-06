import { CheckCircle2, Circle } from "lucide-react";
import { Card } from "@/components/ui/Card";

const steps = [
  { title: "Add an upstream", body: "Point APIShield at the API you want to protect.", done: false },
  { title: "Run your first scan", body: "Find weaknesses before attackers do. Safe mode is on by default.", done: false },
  { title: "Start in monitor mode", body: "Nothing is blocked yet. See what would be blocked first.", done: false },
  { title: "Enable learning", body: "The learner studies traffic shapes (never values) and flags what's unusual.", done: false },
];

export function Onboarding() {
  return (
    <Card className="mx-auto max-w-xl p-6">
      <h1 className="text-xl font-semibold">Welcome to APIShield</h1>
      <p className="mt-1 text-sm text-muted">Four steps to a protected API. Most teams finish in under 15 minutes.</p>
      <ol className="mt-6 space-y-4">
        {steps.map((s, i) => (
          <li key={s.title} className="flex gap-3">
            {s.done ? <CheckCircle2 className="mt-0.5 size-5 text-accent" aria-hidden /> : <Circle className="mt-0.5 size-5 text-muted" aria-hidden />}
            <div>
              <p className="font-medium">
                {i + 1}. {s.title}
              </p>
              <p className="text-sm text-muted">{s.body}</p>
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}

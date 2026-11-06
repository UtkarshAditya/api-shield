import { Activity, Bell, Brain, Map, ScanSearch, Settings, SlidersHorizontal, type LucideIcon } from "lucide-react";
import { EmptyState } from "@/components/domain/EmptyState";

function placeholder(icon: LucideIcon, title: string, week: number, body: string) {
  return function Placeholder() {
    return (
      <EmptyState
        icon={icon}
        title={title}
        body={
          <>
            <p>{body}</p>
            <p className="mt-3 inline-block rounded-full border border-border px-2.5 py-0.5 text-xs">Coming in week {week}</p>
          </>
        }
      />
    );
  };
}

export const TrafficPage = placeholder(Activity, "Live traffic", 2, "A streaming view of every request through the gateway, with filters and rule hits. Payload values are never shown.");
export const RulesPage = placeholder(SlidersHorizontal, "Rules", 2, "Builtin, scanner, analyst and learner rules in one place, with a tester for sample requests.");
export const InventoryPage = placeholder(Map, "API map", 2, "Every endpoint from your spec and from observed traffic, with shadow endpoints flagged.");
export const AlertsPage = placeholder(Bell, "Alerts", 3, "A ranked queue of anomalies with plain-language explanations. Your feedback tunes the thresholds.");
export const ScansPage = placeholder(ScanSearch, "Scans & reports", 3, "Probe your API for OWASP API Top 10 weaknesses, then apply the suggested fixes as rules in one click.");
export const LearningPage = placeholder(Brain, "Learning", 3, "See what the learner has picked up (endpoints and payload shapes, never values) and tune its sensitivity.");
export const SettingsPage = placeholder(Settings, "Settings & privacy", 4, "Monitor/enforce mode, retention, redaction patterns, upstreams, users and the audit log.");

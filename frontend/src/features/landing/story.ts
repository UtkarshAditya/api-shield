export type Chapter = {
  id: string;
  eyebrow: string;
  title: string;
  body: string;
  points?: string[];
  /** Timeline position (0–100) where this chapter becomes active. */
  at: number;
};

export const chapters: Chapter[] = [
  {
    id: "hero",
    eyebrow: "APIShield",
    title: "Your API is a vault.",
    body: "Somebody's always trying the door. Scroll to watch a break-in fail.",
    at: 0,
  },
  {
    id: "scan",
    eyebrow: "01 · Scan",
    title: "Find the weak pins first.",
    body: "APIShield probes your API the way an attacker would, across the OWASP API Top 10, then tells you in plain English what's weak and how to fix it.",
    points: ["Risk-scored findings", "Fix guidance per endpoint", "Safe mode on by default"],
    at: 9,
  },
  {
    id: "protect",
    eyebrow: "02 · Protect",
    title: "Turn findings into locks.",
    body: "One click turns a finding into a gateway rule. Start in monitor mode to see what would be blocked, and switch to enforce once you trust it.",
    points: ["Auth checks", "Schema validation", "Rule-based blocking"],
    at: 29,
  },
  {
    id: "flood",
    eyebrow: "03 · Rate limit",
    title: "A thousand keys, one keyhole.",
    body: "Credential stuffing and scraping arrive as floods. Rate limits throttle the flood without slowing down your real users.",
    points: ["Per caller, per endpoint", "Throttle or challenge, not just block"],
    at: 49,
  },
  {
    id: "learn",
    eyebrow: "04 · Learn",
    title: "Notice the stranger.",
    body: "The learner studies your traffic's shape (which endpoints, how often, what structure) and flags anything new. Every alert is ranked and explained. It never reads the values.",
    points: ["Shapes, never contents", "Ranked by endpoint risk", "Your feedback tunes it"],
    at: 65,
  },
  {
    id: "open",
    eyebrow: "05 · Welcome in",
    title: "The right key still works.",
    body: "Built for small teams with no WAF and no security person. Self-hosted, explainable, and quiet until something actually matters.",
    at: 84,
  },
];

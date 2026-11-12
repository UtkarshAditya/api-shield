/**
 * Deterministic demo data that tells the APIShield story:
 * a vulnerable demo shop API, scanner findings on /login and /search,
 * a warmed-up learner, and a ranked alert burst.
 */
import type { Alert, AuditEntry, EndpointInventoryItem, Finding, LearningStatus, Me, Rule, Scan, Settings, Upstream } from "@/api/schemas";

/** Small seeded PRNG (mulberry32) so the demo looks identical on every load. */
export function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const demoUsers: (Me & { password: string })[] = [
  { id: "u_admin", email: "admin@demo.local", name: "Ada Admin", role: "admin", password: "demo" },
  { id: "u_analyst", email: "analyst@demo.local", name: "Sam Analyst", role: "analyst", password: "demo" },
  { id: "u_viewer", email: "viewer@demo.local", name: "Vic Viewer", role: "viewer", password: "demo" },
];

export const upstreams: Upstream[] = [
  { id: "up_shop", name: "Demo Shop API", url: "http://demo-api:8080" },
  { id: "up_pay", name: "Payments API", url: "http://payments:9000" },
];

export const settings: Settings = {
  mode: "monitor",
  fail_open: true,
  retention_days: 14,
  redaction_patterns: ["authorization", "password", "card_number", "email", "ssn"],
  upstreams,
};

export type EndpointProfile = { method: string; path_template: string; weight: number; blockRate: number; risk: number };

export const endpointProfiles: Record<string, EndpointProfile[]> = {
  up_shop: [
    { method: "GET", path_template: "/products", weight: 0.31, blockRate: 0.002, risk: 2.1 },
    { method: "GET", path_template: "/search", weight: 0.22, blockRate: 0.061, risk: 9.1 },
    { method: "POST", path_template: "/login", weight: 0.14, blockRate: 0.048, risk: 8.2 },
    { method: "GET", path_template: "/orders/{id}", weight: 0.12, blockRate: 0.012, risk: 7.4 },
    { method: "POST", path_template: "/cart/items", weight: 0.1, blockRate: 0.004, risk: 3.0 },
    { method: "GET", path_template: "/users/{id}", weight: 0.07, blockRate: 0.009, risk: 6.3 },
    { method: "POST", path_template: "/checkout", weight: 0.04, blockRate: 0.003, risk: 4.8 },
  ],
  up_pay: [
    { method: "POST", path_template: "/charges", weight: 0.45, blockRate: 0.006, risk: 4.2 },
    { method: "GET", path_template: "/charges/{id}", weight: 0.3, blockRate: 0.002, risk: 3.1 },
    { method: "POST", path_template: "/refunds", weight: 0.15, blockRate: 0.01, risk: 5.5 },
    { method: "GET", path_template: "/health", weight: 0.1, blockRate: 0, risk: 0.5 },
  ],
};

/** Requests per minute baseline per upstream. */
export const baseRpm: Record<string, number> = { up_shop: 1450, up_pay: 380 };

/** Caller IDs as the Admin API returns them: `key_` is the gateway's key hash, `ip_`/`user_` are pseudonymized. */
export const callers: Record<string, string[]> = {
  up_shop: ["key_4c1e7b20", "key_9f3a1c2e", "key_a07b93d4", "key_d2e85f01", "ip_5be03a71", "key_77c0e6aa"],
  up_pay: ["key_e1a40c55", "key_7d02bb19", "key_b33f6a80"],
};

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

export function seedAlerts(): Record<string, Alert[]> {
  const shop: Alert[] = [
    {
      id: "al_1001",
      ts: minutesAgo(2),
      caller: "key_9f3a1c2e",
      endpoint: "GET /search",
      score: 0.97,
      rank: 1,
      severity: "critical",
      reasons: [
        { feature: "Request rate", observed: "412 req/min", baseline: "28 req/min", z: 14.2 },
        { feature: "New payload shape", observed: "query.q: string(len 180+)", baseline: "string(len ≤ 40)", z: 9.1 },
        { feature: "Error ratio", observed: "38% 5xx", baseline: "0.4% 5xx", z: 7.7 },
      ],
      explanation:
        "This caller is hitting /search 14× faster than usual with a query shape we've never seen, and a third of the responses are server errors. That pattern usually means automated injection probing.",
      status: "new",
      group_id: "grp_9f3a",
      timeline: Array.from({ length: 12 }, (_, i) => ({ ts: minutesAgo(12 - i), count: i < 8 ? 25 + (i % 3) : 380 + i * 8 })),
    },
    {
      id: "al_1002",
      ts: minutesAgo(4),
      caller: "ip_5be03a71",
      endpoint: "POST /login",
      score: 0.91,
      rank: 2,
      severity: "high",
      reasons: [
        { feature: "Failed logins", observed: "96 in 5 min", baseline: "2 in 5 min", z: 11.3 },
        { feature: "Distinct usernames", observed: "88", baseline: "1", z: 10.4 },
      ],
      explanation:
        "One IP tried 88 different usernames on /login in five minutes, almost all failing. This looks like credential stuffing. /login has no rate limit yet (see scan finding).",
      status: "new",
      group_id: "grp_203",
    },
    {
      id: "al_1003",
      ts: minutesAgo(9),
      caller: "key_a07b93d4",
      endpoint: "GET /orders/{id}",
      score: 0.78,
      rank: 3,
      severity: "high",
      reasons: [
        { feature: "Distinct IDs requested", observed: "640 / 10 min", baseline: "6 / 10 min", z: 8.8 },
        { feature: "Sequential ID access", observed: "yes", baseline: "no" },
      ],
      explanation:
        "This key is walking order IDs in sequence, far more than any normal customer would. It may be scraping other people's orders (broken object-level authorization).",
      status: "acknowledged",
      group_id: "grp_a07b",
    },
    {
      id: "al_1004",
      ts: minutesAgo(22),
      caller: "key_d2e85f01",
      endpoint: "POST /cart/items",
      score: 0.52,
      rank: 4,
      severity: "medium",
      reasons: [{ feature: "Payload size", observed: "48 KB", baseline: "0.6 KB", z: 5.2 }],
      explanation: "Cart requests from this key are about 80× larger than normal. It could be a client bug or an attempt to overload the endpoint.",
      status: "new",
      group_id: "grp_d2e8",
    },
    {
      id: "al_1005",
      ts: minutesAgo(41),
      caller: "key_9f3a1c2e",
      endpoint: "GET /users/{id}",
      score: 0.44,
      rank: 5,
      severity: "medium",
      reasons: [{ feature: "Off-hours activity", observed: "03:12 local", baseline: "09:00–19:00" }],
      explanation: "This key is usually active during business hours and is now calling /users at 3 a.m. On its own this is low risk, but the same key is also behind the top alert.",
      status: "new",
      group_id: "grp_9f3a",
    },
    {
      id: "al_1006",
      ts: minutesAgo(75),
      caller: "key_77c0e6aa",
      endpoint: "GET /products",
      score: 0.21,
      rank: 6,
      severity: "low",
      reasons: [{ feature: "New user agent family", observed: "python-requests", baseline: "browser" }],
      explanation: "A key that normally comes from browsers is now using a script client. Often harmless (for example, a new integration).",
      status: "false_positive",
      group_id: "grp_77c0",
    },
  ];
  const pay: Alert[] = [
    {
      id: "al_2001",
      ts: minutesAgo(18),
      caller: "key_b33f6a80",
      endpoint: "POST /refunds",
      score: 0.63,
      rank: 1,
      severity: "high",
      reasons: [{ feature: "Refund volume", observed: "31 / hour", baseline: "2 / hour", z: 6.4 }],
      explanation: "Refund requests from this key are 15× above its normal hourly rate.",
      status: "new",
      group_id: "grp_b33f",
    },
  ];
  return { up_shop: shop, up_pay: pay };
}

export function seedLearning(): Record<string, LearningStatus> {
  return {
    up_shop: {
      mode: "active",
      progress: 1,
      started_at: minutesAgo(60 * 24 * 3),
      ends_at: minutesAgo(60 * 24 * 2),
      endpoints_learned: 7,
      shapes_learned: 23,
    },
    up_pay: {
      mode: "warmup",
      progress: 0.62,
      started_at: minutesAgo(60 * 15),
      ends_at: new Date(Date.now() + 9 * 3600_000).toISOString(),
      endpoints_learned: 4,
      shapes_learned: 9,
    },
  };
}

export function seedFindings(): Record<string, Finding[]> {
  const rule = (r: Omit<Rule, "enabled" | "hits_24h">): Rule => ({ ...r, enabled: false, hits_24h: 0 });
  return {
    up_shop: [
      {
        id: "fd_01",
        scan_id: "sc_001",
        endpoint: "/search",
        method: "GET",
        owasp_cat: "API8:2023 Security Misconfiguration",
        title: "SQL injection in query parameter q",
        severity: "critical",
        risk_score: 9.1,
        evidence: { request: "GET /search?q=' OR 1=1 --", response: "500 · syntax error near ••••" },
        fix: "Use parameterized queries for the search handler.",
        suggested_rule: rule({ id: "rule-block-sqli-q", name: "rule block sqli q", match: { path: "/search", method: "GET", signature: "sqli" }, action: "block", source: "scanner", priority: 100 }),
        status: "open",
      },
      {
        id: "fd_02",
        scan_id: "sc_001",
        endpoint: "/login",
        method: "POST",
        owasp_cat: "API4:2023 Unrestricted Resource Consumption",
        title: "No rate limit on login",
        severity: "high",
        risk_score: 8.2,
        evidence: { request: "POST /login ×500 in 10s", response: "200/401, never 429" },
        fix: "Add a per-IP and per-username rate limit.",
        suggested_rule: rule({
          id: "rule-ratelimit-login",
          name: "rule ratelimit login",
          match: { path: "/login", method: "POST" },
          action: "throttle",
          throttle: { limit: 5, per: 60 },
          source: "scanner",
          priority: 100,
        }),
        status: "open",
      },
      {
        id: "fd_03",
        scan_id: "sc_001",
        endpoint: "/orders/{id}",
        method: "GET",
        owasp_cat: "API1:2023 Broken Object Level Authorization",
        title: "Orders readable by any authenticated user",
        severity: "high",
        risk_score: 7.4,
        evidence: { request: "GET /orders/1002 (as user B)", response: "200 · { owner: ••••, total: •••• }" },
        fix: "Check that the order belongs to the caller before returning it.",
        status: "open",
      },
    ],
    up_pay: [],
  };
}

export function seedRules(): Record<string, Rule[]> {
  return {
    up_shop: [
      {
        id: "builtin-sqli",
        name: "SQL injection signatures",
        enabled: true,
        match: { signature: "sqli" },
        action: "block",
        source: "builtin",
        priority: 10,
        hits_24h: 214,
      },
      {
        id: "block-admin-writes",
        name: "Block writes to /admin",
        enabled: true,
        match: { path: "/admin/*", method: ["POST", "PUT", "DELETE"] },
        action: "block",
        source: "analyst",
        priority: 50,
        hits_24h: 3,
        created_at: minutesAgo(60 * 26),
        created_by: "admin@demo.local",
      },
      {
        id: "log-scanner-agents",
        name: "Log known scanner user agents",
        enabled: true,
        match: { signature: "bad_user_agent", ip: ["203.0.113.0/24", "198.51.100.0/24"] },
        action: "log",
        source: "analyst",
        priority: 100,
        hits_24h: 41,
        created_at: minutesAgo(60 * 50),
        created_by: "analyst@demo.local",
      },
    ],
    up_pay: [],
  };
}

export function seedScans(): Record<string, Scan[]> {
  return {
    up_shop: [
      {
        id: "sc_001",
        upstream_id: "up_shop",
        status: "done",
        progress: 1,
        started_at: minutesAgo(95),
        finished_at: minutesAgo(94),
        counts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
        api_risk_score: 8.2,
      },
    ],
    up_pay: [],
  };
}

export function seedInventory(): Record<string, EndpointInventoryItem[]> {
  const row = (method: string, path: string, risk: number, extra: Partial<EndpointInventoryItem> = {}): EndpointInventoryItem => ({
    method,
    path,
    source: "both",
    shadow: false,
    auth_required: false,
    rate_limited: false,
    risk_score: risk,
    requests_24h: 0,
    ...extra,
  });
  return {
    up_shop: [
      row("GET", "/products", 2.1, { requests_24h: 64210 }),
      row("GET", "/search", 9.1, { requests_24h: 45560 }),
      row("POST", "/login", 8.2, { requests_24h: 28990 }),
      row("GET", "/orders/{id}", 7.4, { auth_required: true, requests_24h: 24850 }),
      row("POST", "/cart/items", 3.0, { auth_required: true, requests_24h: 20700 }),
      row("GET", "/users/{id}", 6.3, { auth_required: true, requests_24h: 14500 }),
      row("POST", "/checkout", 4.8, { auth_required: true, requests_24h: 8280 }),
      row("GET", "/debug", 0, { source: "observed", shadow: true, requests_24h: 37 }),
    ],
    up_pay: [],
  };
}

export function seedAudit(): AuditEntry[] {
  return [
    {
      id: "au_0002",
      ts: minutesAgo(94),
      actor: "analyst@demo.local",
      action: "scan.start",
      target_type: "scan",
      target_id: "sc_001",
      details: { upstream_id: "up_shop", safe_mode: true },
    },
    {
      id: "au_0001",
      ts: minutesAgo(60 * 26),
      actor: "admin@demo.local",
      action: "rule.create",
      target_type: "rule",
      target_id: "block-admin-writes",
      details: { action: "block" },
    },
  ];
}

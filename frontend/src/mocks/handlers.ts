import { delay, http, HttpResponse } from "msw";
import { API_BASE } from "@/api/client";
import type { Alert, Range, Rule, Scan } from "@/api/schemas";
import { can, type Permission } from "@/auth/roles";
import { audit, buildRecentTraffic, buildSummary, buildTimeseries, db } from "./db";
import { demoUsers } from "./seed";

const url = (p: string) => `${API_BASE}${p}`;
const latency = () => delay(150 + Math.random() * 250);
const error = (status: number, code: string, message: string) =>
  HttpResponse.json({ error: { code, message }, request_id: `mock_${Date.now().toString(16)}` }, { status });

function userFromRequest(req: Request) {
  const token = req.headers.get("Authorization")?.replace("Bearer ", "");
  return demoUsers.find((u) => token === `mock.${u.id}`);
}

/** Returns the user if they hold the permission, or an error response to return as-is. */
function authorize(req: Request, permission?: Permission) {
  const user = userFromRequest(req);
  if (!user) return { denied: error(401, "unauthorized", "Session expired.") };
  if (permission && !can(user.role, permission)) return { denied: error(403, "forbidden", "Your role cannot do this.") };
  return { user };
}

const parseRange = (v: string | null): Range => (v === "1h" || v === "7d" ? v : "24h");
const upstreamOf = (req: Request) => new URL(req.url).searchParams.get("upstream_id") ?? "up_shop";
const paged = <T,>(items: T[], req: Request) => {
  const q = new URL(req.url).searchParams;
  const limit = Number(q.get("limit") ?? 50);
  const offset = Number(q.get("offset") ?? 0);
  return HttpResponse.json({ items: items.slice(offset, offset + limit), total: items.length });
};

function findAlert(id: string): Alert | undefined {
  return Object.values(db.alerts)
    .flat()
    .find((a) => a.id === id);
}

/** Mock scans advance with wall-clock time: queued for 1s, running for 5s, then done. */
const scanStarted = new Map<string, number>();
function scanView(scan: Scan): Scan {
  const started = scanStarted.get(scan.id);
  if (started === undefined) return scan;
  const elapsed = Date.now() - started;
  if (elapsed < 1000) return { ...scan, status: "queued", progress: 0 };
  if (elapsed < 6000) return { ...scan, status: "running", progress: Math.min(0.95, (elapsed - 1000) / 5000) };
  return { ...scan, status: "done", progress: 1, finished_at: new Date(started + 6000).toISOString() };
}

function ruleMatches(rule: Rule, method: string, path: string) {
  const methods = rule.match.method === undefined ? undefined : ([] as string[]).concat(rule.match.method);
  if (methods && !methods.map((m) => m.toUpperCase()).includes(method.toUpperCase())) return false;
  if (rule.match.path) {
    const pattern = new RegExp(
      "^" + rule.match.path.replace(/\*$/, ".*").replace(/\{[^}]+\}/g, "[^/]+") + "$",
    );
    if (!pattern.test(path)) return false;
  }
  return true;
}

export const handlers = [
  http.post(url("/auth/login"), async ({ request }) => {
    await latency();
    const { email, password } = (await request.json()) as { email?: string; password?: string };
    const user = demoUsers.find((u) => u.email === email?.trim().toLowerCase());
    if (!user || password !== user.password) return error(401, "invalid_credentials", "Email or password is incorrect.");
    const { password: _pw, ...me } = user;
    return HttpResponse.json({ token: `mock.${user.id}`, user: me });
  }),

  http.get(url("/me"), async ({ request }) => {
    await latency();
    const user = userFromRequest(request);
    if (!user) return error(401, "unauthorized", "Session expired.");
    const { password: _pw, ...me } = user;
    return HttpResponse.json(me);
  }),

  http.get(url("/upstreams"), async () => {
    await latency();
    return HttpResponse.json(db.upstreams);
  }),

  http.get(url("/settings"), async () => {
    await latency();
    return HttpResponse.json({ ...db.settings, upstreams: db.upstreams });
  }),

  http.patch(url("/settings"), async ({ request }) => {
    await latency();
    const patch = (await request.json()) as Partial<typeof db.settings>;
    const { user, denied } = authorize(request, patch.mode !== undefined ? "mode.switch" : "settings.edit");
    if (denied) return denied;
    if (patch.mode !== undefined && patch.mode !== db.settings.mode) {
      audit(user.email, "mode.change", "settings", undefined, { from: db.settings.mode, to: patch.mode });
    }
    const { upstreams: _u, ...rest } = patch;
    Object.assign(db.settings, rest);
    return HttpResponse.json({ ...db.settings, upstreams: db.upstreams });
  }),

  http.get(url("/metrics/summary"), async ({ request }) => {
    await latency();
    const q = new URL(request.url).searchParams;
    return HttpResponse.json(buildSummary(q.get("upstream_id") ?? "up_shop", parseRange(q.get("range"))));
  }),

  http.get(url("/metrics/timeseries"), async ({ request }) => {
    await latency();
    const q = new URL(request.url).searchParams;
    return HttpResponse.json(buildTimeseries(q.get("upstream_id") ?? "up_shop", parseRange(q.get("range"))));
  }),

  http.get(url("/traffic/recent"), async ({ request }) => {
    await latency();
    const limit = Number(new URL(request.url).searchParams.get("limit") ?? 100);
    const items = buildRecentTraffic(upstreamOf(request), limit);
    return HttpResponse.json({ items, total: items.length });
  }),

  // ---- Rules ----

  http.get(url("/rules"), async ({ request }) => {
    await latency();
    return paged(db.rules[upstreamOf(request)] ?? [], request);
  }),

  http.post(url("/rules"), async ({ request }) => {
    await latency();
    const { user, denied } = authorize(request, "rules.edit");
    if (denied) return denied;
    const body = (await request.json()) as Partial<Rule>;
    const list = (db.rules[upstreamOf(request)] ??= []);
    if (!body.id || list.some((r) => r.id === body.id)) return error(409, "rule_exists", "A rule with this id already exists.");
    const rule: Rule = {
      enabled: true,
      source: "analyst",
      match: {},
      action: "log",
      ...body,
      id: body.id,
      name: body.name || body.id,
      hits_24h: 0,
      created_at: new Date().toISOString(),
      created_by: user.email,
    };
    list.push(rule);
    audit(user.email, "rule.create", "rule", rule.id, { action: rule.action });
    return HttpResponse.json(rule, { status: 201 });
  }),

  http.patch(url("/rules/:id"), async ({ request, params }) => {
    await latency();
    const { user, denied } = authorize(request, "rules.edit");
    if (denied) return denied;
    const rule = (db.rules[upstreamOf(request)] ?? []).find((r) => r.id === params.id);
    if (!rule) return error(404, "not_found", "Rule not found.");
    const { id: _id, hits_24h: _h, created_at: _c, created_by: _b, ...patch } = (await request.json()) as Partial<Rule>;
    Object.assign(rule, patch);
    audit(user.email, "rule.update", "rule", rule.id, { fields: Object.keys(patch) });
    return HttpResponse.json(rule);
  }),

  http.delete(url("/rules/:id"), async ({ request, params }) => {
    await latency();
    const { user, denied } = authorize(request, "rules.edit");
    if (denied) return denied;
    const list = db.rules[upstreamOf(request)] ?? [];
    const idx = list.findIndex((r) => r.id === params.id);
    if (idx < 0) return error(404, "not_found", "Rule not found.");
    list.splice(idx, 1);
    audit(user.email, "rule.delete", "rule", String(params.id));
    return new HttpResponse(null, { status: 204 });
  }),

  http.post(url("/rules/test"), async ({ request }) => {
    await latency();
    const { rule, request: sample } = (await request.json()) as { rule: Rule; request: { method: string; path: string } };
    const matched = ruleMatches(rule, sample.method, sample.path);
    return HttpResponse.json({
      matched,
      action: matched ? rule.action : null,
      explanation: matched
        ? `The request matches every condition of "${rule.name || rule.id}", so the gateway would ${rule.action} it.`
        : "The request does not match this rule, so the rule would not change how it is handled.",
    });
  }),

  // ---- Alerts and learning ----

  http.get(url("/alerts"), async ({ request }) => {
    await latency();
    const q = new URL(request.url).searchParams;
    let items = [...(db.alerts[q.get("upstream_id") ?? "up_shop"] ?? [])];
    const status = q.get("status");
    if (status === "active") items = items.filter((a) => a.status === "new" || a.status === "acknowledged");
    else if (status) items = items.filter((a) => a.status === status);
    const severity = q.get("severity");
    if (severity) items = items.filter((a) => a.severity === severity);
    items.sort((a, b) => a.rank - b.rank);
    return paged(items, request);
  }),

  http.get(url("/alerts/:id"), async ({ params }) => {
    await latency();
    const alert = findAlert(String(params.id));
    return alert ? HttpResponse.json(alert) : error(404, "not_found", "Alert not found.");
  }),

  http.patch(url("/alerts/:id"), async ({ request, params }) => {
    await latency();
    const { user, denied } = authorize(request, "alerts.triage");
    if (denied) return denied;
    const alert = findAlert(String(params.id));
    if (!alert) return error(404, "not_found", "Alert not found.");
    const { status } = (await request.json()) as { status: Alert["status"] };
    alert.status = status;
    const adjustment =
      status === "false_positive" ? { feature: alert.reasons[0]?.feature ?? "score", threshold_delta: 0.1 } : null;
    audit(user.email, "alert.feedback", "alert", alert.id, { status });
    return HttpResponse.json({ alert, adjustment });
  }),

  http.post(url("/alerts/:id/promote-to-rule"), async ({ request, params }) => {
    await latency();
    const { user, denied } = authorize(request, "rules.edit");
    if (denied) return denied;
    const alert = findAlert(String(params.id));
    if (!alert) return error(404, "not_found", "Alert not found.");
    const [method, path] = alert.endpoint.split(" ");
    const rule: Rule = {
      id: `alert-${alert.id}`,
      name: `From alert ${alert.id}`,
      enabled: true,
      match: alert.caller.startsWith("key_")
        ? { path, method, condition: `caller == '${alert.caller}'` }
        : { path, method },
      action: "throttle",
      throttle: { limit: 10, per: 60 },
      source: "analyst",
      hits_24h: 0,
      created_at: new Date().toISOString(),
      created_by: user.email,
    };
    (db.rules[upstreamOf(request)] ??= []).push(rule);
    audit(user.email, "rule.create", "rule", rule.id, { from_alert: alert.id });
    return HttpResponse.json(rule, { status: 201 });
  }),

  http.get(url("/learning/status"), async ({ request }) => {
    await latency();
    const id = upstreamOf(request);
    return HttpResponse.json(db.learning[id] ?? db.learning.up_shop);
  }),

  http.patch(url("/learning"), async ({ request }) => {
    await latency();
    const { user, denied } = authorize(request, "settings.edit");
    if (denied) return denied;
    const status = db.learning[upstreamOf(request)];
    const patch = (await request.json()) as { mode?: "active" | "disabled"; sensitivity?: number };
    Object.assign(status, patch);
    audit(user.email, "learning.update", "learning", upstreamOf(request), patch);
    return HttpResponse.json(status);
  }),

  http.post(url("/learning/reset"), async ({ request }) => {
    await latency();
    const { user, denied } = authorize(request, "settings.edit");
    if (denied) return denied;
    const id = upstreamOf(request);
    db.learning[id] = {
      mode: "warmup",
      progress: 0,
      started_at: new Date().toISOString(),
      ends_at: new Date(Date.now() + 24 * 3600_000).toISOString(),
      endpoints_learned: 0,
      shapes_learned: 0,
    };
    audit(user.email, "learning.reset", "learning", id);
    return HttpResponse.json(db.learning[id]);
  }),

  // ---- Scans and findings ----

  http.get(url("/scans"), async ({ request }) => {
    await latency();
    return paged((db.scans[upstreamOf(request)] ?? []).map(scanView), request);
  }),

  http.post(url("/scans"), async ({ request }) => {
    await latency();
    const { user, denied } = authorize(request, "scans.run");
    if (denied) return denied;
    const body = (await request.json()) as { upstream_id: string; consent?: boolean; safe_mode?: boolean };
    if (body.consent !== true) return error(400, "consent_required", "Confirm that you own this API before scanning it.");
    const list = (db.scans[body.upstream_id] ??= []);
    const scan: Scan = {
      id: `sc_${Date.now().toString(16)}`,
      upstream_id: body.upstream_id,
      status: "queued",
      progress: 0,
      started_at: new Date().toISOString(),
      counts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
      api_risk_score: 8.2,
    };
    scanStarted.set(scan.id, Date.now());
    list.unshift(scan);
    audit(user.email, "scan.start", "scan", scan.id, { upstream_id: body.upstream_id, safe_mode: body.safe_mode ?? true });
    return HttpResponse.json(scan, { status: 202 });
  }),

  http.get(url("/scans/:id"), async ({ params }) => {
    await latency();
    const scan = Object.values(db.scans)
      .flat()
      .find((s) => s.id === params.id);
    return scan ? HttpResponse.json(scanView(scan)) : error(404, "not_found", "Scan not found.");
  }),

  http.get(url("/scans/:id/findings"), async ({ request }) => {
    await latency();
    // Every mock scan reports the same seeded findings.
    return paged(db.findings[upstreamOf(request)] ?? [], request);
  }),

  http.get(url("/scans/:id/report"), async ({ request, params }) => {
    await latency();
    const findings = db.findings[upstreamOf(request)] ?? [];
    if (new URL(request.url).searchParams.get("format") === "html") {
      return HttpResponse.html(`<!doctype html><title>Scan ${params.id}</title><h1>Mock report</h1><p>${findings.length} findings</p>`);
    }
    return HttpResponse.json({ scan_id: params.id, findings });
  }),

  http.post(url("/findings/:id/apply-rule"), async ({ request, params }) => {
    await latency();
    const { user, denied } = authorize(request, "rules.edit");
    if (denied) return denied;
    const finding = Object.values(db.findings)
      .flat()
      .find((f) => f.id === params.id);
    if (!finding) return error(404, "not_found", "Finding not found.");
    if (!finding.suggested_rule) return error(409, "no_suggested_rule", "This finding has no suggested rule.");
    const list = (db.rules[upstreamOf(request)] ??= []);
    const rule: Rule = { ...finding.suggested_rule, enabled: true, created_at: new Date().toISOString(), created_by: user.email };
    const idx = list.findIndex((r) => r.id === rule.id);
    if (idx >= 0) list[idx] = rule;
    else list.push(rule);
    finding.status = "mitigated";
    audit(user.email, "finding.apply_rule", "finding", finding.id, { rule_id: rule.id });
    return HttpResponse.json(finding);
  }),

  http.get(url("/endpoints"), async ({ request }) => {
    await latency();
    return paged(db.inventory[upstreamOf(request)] ?? [], request);
  }),

  // ---- Audit and privacy ----

  http.get(url("/audit-log"), async ({ request }) => {
    await latency();
    const { denied } = authorize(request, "settings.edit");
    if (denied) return denied;
    return paged(db.audit, request);
  }),

  http.post(url("/privacy/purge"), async ({ request }) => {
    await latency();
    const { user, denied } = authorize(request, "data.purge");
    if (denied) return denied;
    audit(user.email, "data.purge", "traffic", upstreamOf(request));
    return HttpResponse.json({ purged_at: new Date().toISOString(), recent_events: 0, aggregate_rows: 0 });
  }),
];

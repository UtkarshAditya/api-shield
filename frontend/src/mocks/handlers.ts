import { delay, http, HttpResponse } from "msw";
import { API_BASE } from "@/api/client";
import type { Range } from "@/api/schemas";
import { buildSummary, buildTimeseries, db } from "./db";
import { demoUsers } from "./seed";

const url = (p: string) => `${API_BASE}${p}`;
const latency = () => delay(150 + Math.random() * 250);
const error = (status: number, code: string, message: string) => HttpResponse.json({ error: { code, message } }, { status });

function userFromRequest(req: Request) {
  const token = req.headers.get("Authorization")?.replace("Bearer ", "");
  return demoUsers.find((u) => token === `mock.${u.id}`);
}

const parseRange = (v: string | null): Range => (v === "1h" || v === "7d" ? v : "24h");

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
    const total = items.length;
    const limit = Number(q.get("limit") ?? 50);
    return HttpResponse.json({ items: items.slice(0, limit), total });
  }),

  http.get(url("/learning/status"), async ({ request }) => {
    await latency();
    const id = new URL(request.url).searchParams.get("upstream_id") ?? "up_shop";
    return HttpResponse.json(db.learning[id] ?? db.learning.up_shop);
  }),
];

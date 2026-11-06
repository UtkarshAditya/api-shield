# Admin API contract questions

The dashboard currently runs against MSW mocks in `src/mocks/`. Wherever the brief was silent, `src/api/schemas.ts` makes an assumption and marks it with `CONTRACT-TBD`. Please confirm or correct each item below. Once a shape is agreed, only `schemas.ts` and `endpoints.ts` need to change.

## All backend owners
1. **Error envelope.** We assume `{ "error": { "code": string, "message": string } }` with a matching HTTP status. Is that right?
2. **Pagination.** We assume `{ items: T[], total: number }` plus `limit`/`offset` query params. Would you prefer a cursor?
3. **Multi-upstream.** We assume every data endpoint takes `?upstream_id=`. Is that the plan, or is it a path prefix?
4. **Auth.** `POST /auth/login` returns `{ token, user: { id, email, name, role } }`, and `GET /me` returns the user. What is the token lifetime, and is there a refresh endpoint?
5. **Masking guarantee.** The UI assumes caller IDs, IPs and evidence arrive already masked (for example `key_9f3a••••`). Is there any endpoint that could return raw values?

## M1: Gateway / Protection
6. **`GET /metrics/summary`.** The UI needs these fields:
   - `requests`, `blocked`, `allowed`, `active_alerts`, `p95_latency_ms`
   - `top_endpoints[] { method, path_template, requests, blocked, risk_score }`
   - `top_callers[] { caller, requests, alerts }`
   - `previous { … }`, the same KPIs for the previous period, used to show deltas.

   Which of these will the gateway compute, and which come from M2/M3?
7. **`GET /metrics/timeseries`.** We assume `{ range, metric, points: [{ t, allowed, blocked }] }`. Bucket sizes are 1 min for 1h, 15 min for 24h, and 2 h for 7d.
8. **`/traffic/stream` (SSE).** Will events come one at a time or in batches? What is the heartbeat interval, and what is the event name?
9. **Rule "mode".** The brief mentions a per-rule mode of log vs block. Is that the same as `Rule.action`, or a separate field?
10. **Rule metadata.** Can we have `created_at` and `created_by` on `Rule` for the audit trail?

## M2: Scanner / Risk
11. **Overall API risk score (0–10) and its top drivers.** Which endpoint returns them? We currently put them on `/metrics/summary` as `risk_score` and `risk_drivers[]`.
12. **`Scan` object.** What is its shape? We need `id`, `upstream_id`, `status` (queued/running/done/failed), `progress` (0–1), `started_at`, `finished_at`, and counts by severity.
13. **Endpoint inventory API.** This is missing from §5. The API-map screen needs, per endpoint:
    - source (spec / observed / both)
    - shadow flag
    - auth required
    - rate-limited
    - risk score

## M3: Learning / Alerts
14. **`PATCH /alerts/:id` with `false_positive`.** Can the response include the threshold change (for example `{ threshold_delta, feature }`), so the UI can show "threshold adjusted"?
15. **Alert timeline.** What field holds the timeline for the alert detail view?
16. **Sensitivity slider.** Which endpoint and value range? This is missing from §5.
17. **`LearningStatus`.** We added `shapes_learned` for the "shape count" the brief mentions. Can you confirm the name?
18. **`GET /alerts?status=active`.** We use this as shorthand for "new or acknowledged". Is that OK, or should we send `status=new,acknowledged`?

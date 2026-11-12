# Admin API contract questions

The dashboard currently runs against MSW mocks in `src/mocks/`. Wherever the brief was silent, `src/api/schemas.ts` makes an assumption and marks it with `CONTRACT-TBD`. Please confirm or correct each item below. Once a shape is agreed, only `schemas.ts` and `endpoints.ts` need to change.

## Answered

Items 6 to 10 were answered by M1 in `gateway/README.md`. Items 1 to 5 were for all owners; the Admin API (M4) owns those decisions now, and nobody objected.

1. **Error envelope** (Admin API, matches the gateway): `{ "error": { "code", "message" }, "request_id" }` with a matching HTTP status. `request_id` is optional in the schema.
2. **Pagination** (Admin API): collections return `{ items, total }` and take `limit`/`offset`. No cursor for now. `/upstreams` stays a plain array.
3. **Multi-upstream** (Admin API): every data endpoint takes `?upstream_id=`. The gateway itself protects one upstream, so its events are assigned to the Admin API's `APISHIELD_UPSTREAM_ID`.
4. **Auth** (Admin API): `POST /auth/login` returns `{ token, user }`. The JWT lives 8 hours, with no refresh endpoint. `/traffic/stream` also accepts `?access_token=`, because `EventSource` cannot send headers.
5. **Masking guarantee** (Admin API): the Admin API pseudonymizes `ip_`/`user_` callers and the `ip` field with HMAC-SHA256 before storing or returning them. `key_` is already the gateway's key hash. Scan evidence is masked again at the boundary. The one exception is `Rule.match.ip`: that is operator-entered CIDR config and is returned as entered.
6. **`/metrics/summary`** (M1): the gateway serves no metrics. The Admin API aggregates the raw Redis stream events, and `blocked` means `action in (block, throttle, challenge)`.
7. **`/metrics/timeseries`** (M1): the Admin API buckets the events by `ts` (1 min / 15 min / 2 h), using the shape we proposed.
8. **`/traffic/stream`** (M1): the gateway serves no SSE. Events arrive one at a time on the Redis stream, and the Admin API relays them as `event: traffic` with a `: ping` comment every 15 s.
9. **Rule "mode"** (M1): this is `Rule.action` (`log` vs `block`). The global monitor/enforce switch is separate (`PUT /_apishield/mode`, via `PATCH /settings`).
10. **Rule metadata** (M1): the gateway ignores unknown fields, so `created_at`/`created_by` live in the Admin API database and come back as optional fields on `Rule`.

## Open

## M2: Scanner / Risk
11. **Overall API risk score (0–10) and its top drivers.** Which endpoint returns them? We currently put them on `/metrics/summary` as `risk_score` and `risk_drivers[]`.
12. **`Scan` object.** What is its shape? We need `id`, `upstream_id`, `status` (queued/running/done/failed), `progress` (0–1), `started_at`, `finished_at`, and counts by severity.
    *Draft in `schemas.ts` (`Scan`):* those fields, plus `counts{critical,high,medium,low,info}`, `api_risk_score` and `error`. `run_scan` has no progress callback, so `progress` is coarse for now (0, 0.1, 1). We also need `safe_mode` and `on_progress` parameters on `run_scan`. The localhost and consent checks live only in `cli.main()`, so the Admin API repeats them. `endpoint_risk` is keyed by path only; can it include the method?
13. **Endpoint inventory API.** This is missing from §5. The API-map screen needs, per endpoint:
    - source (spec / observed / both)
    - shadow flag
    - auth required
    - rate-limited
    - risk score

    *Draft in `schemas.ts` (`EndpointInventoryItem`):* `GET /endpoints` returns `{method, path, source, shadow, auth_required, rate_limited, risk_score, requests_24h}`. The Admin API builds it from the spec, the observed traffic and the latest scan.

## M3: Learning / Alerts
14. **`PATCH /alerts/:id` with `false_positive`.** Can the response include the threshold change (for example `{ threshold_delta, feature }`), so the UI can show "threshold adjusted"?
    *Draft (`AlertFeedbackResponse`):* `PATCH /alerts/:id` always returns `{alert, adjustment}`, where `adjustment` is `null` unless the status is `false_positive`. The Admin API writes an `alert_feedback` row for the learner to consume. Until M3 owns the math, the delta is a placeholder of +0.1 on the top reason's feature.
15. **Alert timeline.** What field holds the timeline for the alert detail view?
    *Draft:* `Alert.timeline: [{ts, count}]`, optional.
16. **Sensitivity slider.** Which endpoint and value range? This is missing from §5.
    *Draft:* `PATCH /learning {mode?, sensitivity?}`, with `sensitivity` from 0 to 1, also returned on `LearningStatus`.
17. **`LearningStatus`.** We added `shapes_learned` for the "shape count" the brief mentions. Can you confirm the name?
18. **`GET /alerts?status=active`.** We use this as shorthand for "new or acknowledged". Is that OK, or should we send `status=new,acknowledged`?

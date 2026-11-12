# APIShield Admin API (M4: Platform)

The only service the dashboard talks to. It reads the gateway's traffic stream, proxies
rule and mode changes to the gateway, runs the scanner, serves alerts written by the
learner (M3), and keeps the audit log.

```
dashboard --/api--> [ Admin API ] --control endpoints--> gateway (:8080)
                        |  ^
     XREADGROUP admin-api  |  run_scan() in a worker thread --> demo API (:8001, never via the gateway)
                        v  |
                 Redis stream apishield:traffic        DB (SQLite dev / Postgres in Compose)
                                                       shared with M3: alerts, learning_state, alert_feedback
```

## Run it

Run all commands from the **repo root**. You need Python 3.10 or newer.

```bash
pip install -r admin_api/requirements.txt
APISHIELD_ADMIN_TOKEN=demo-admin DEMO_SEED=true python -m admin_api      # http://localhost:8000/api
```

The gateway and Redis should run as described in `gateway/README.md`, with the same
`APISHIELD_ADMIN_TOKEN`. If either one is down, the Admin API still starts:
- When **Redis** is down, ingestion pauses with a warning and retries.
- When the **gateway** is down, rule and mode changes return `502 gateway_unreachable` and nothing is saved.

To use the dashboard against the Admin API:
- **Dev server:** set `VITE_USE_MOCKS=false` in `frontend/.env`, then run `npm run dev`. Vite proxies `/api` to `:8000`.
- **Built dashboard:** set `ADMIN_STATIC_DIR=frontend/dist` and the Admin API serves the build at `/`.

The demo logins are `admin@demo.local`, `analyst@demo.local` and `viewer@demo.local`, all with the password `demo`. They exist only with `DEMO_SEED=true`.

Whole stack: `cp .env.example .env && docker compose up --build`, then open http://localhost:8000.
Traffic: `python scripts/simulate_traffic.py`.

Tests: `pytest admin_api/tests`. They need no Redis, gateway or network. One test runs the real
scanner against `demo_api` on a free localhost port.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_DATABASE_URL` | `sqlite:///./admin_api.db` | e.g. `postgresql+psycopg://user:pw@postgres/apishield` |
| `APISHIELD_REDIS_URL` | empty (ingestion off) | `redis://redis:6379/0` |
| `APISHIELD_GATEWAY_URL` | `http://localhost:8080` | Gateway base URL |
| `APISHIELD_ADMIN_TOKEN` | empty | Gateway control token. Server-side only: never logged, never returned |
| `APISHIELD_PSEUDO_SALT` | dev-only salt, with a warning | HMAC key for caller pseudonyms. **Must match the learner (M3)** |
| `ADMIN_JWT_SECRET` | dev-only secret, with a warning | Signs dashboard sessions (8 h, no refresh) |
| `DEMO_SEED` | `false` | Demo users, alerts and learning progress. Also enables `POST /demo/reset` |
| `ADMIN_DEMO_ALERTS` | `false` | Every 5 s, turn callers that stand out in recent traffic into alerts marked "demo replay" (stand-in for M3; Compose sets `true`) |
| `APISHIELD_UPSTREAM_ID` / `_NAME` / `_URL` | `up_shop` / `Demo Shop API` / `http://localhost:8001` | The protected API. The URL is what gets scanned |
| `APISHIELD_OPENAPI_SPEC` | `demo_api/openapi.json` | Spec for scans and the endpoint inventory |
| `APISHIELD_SCAN_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Hosts the scanner may target. Compose adds `demo-api` |
| `APISHIELD_SCAN_USERNAME` / `_PASSWORD` | `alice` / `alice123` | Demo API login used by the scanner |
| `ADMIN_CORS_ORIGINS` | empty | Only if the dashboard is served from another origin |
| `ADMIN_STATIC_DIR` | empty | Built dashboard to serve at `/` |
| `ADMIN_AUTO_MIGRATE` | `true` | Run `alembic upgrade head` at startup |
| `ADMIN_HOST`, `ADMIN_PORT` | `127.0.0.1`, `8000` | Listen address |

Migrations: `alembic -c admin_api/alembic.ini upgrade head`. To add a revision, add
`revision --autogenerate -m "..."` with `ADMIN_DATABASE_URL` pointing at an up-to-date database.

## Endpoints (all under `/api`)

Every data endpoint takes `?upstream_id=`. Collections return `{items, total}` with
`limit`/`offset`. Errors use the gateway's envelope:
`{"error": {"code", "message"}, "request_id"}`. The response shapes are the Zod schemas in
`frontend/src/api/schemas.ts`. `tests/test_contract_samples.py` writes one sample per
endpoint, and `frontend/src/test/contract.test.ts` parses each one with its schema.

| Endpoint | Who | Notes |
|---|---|---|
| `POST /auth/login`, `GET /me` | anyone / signed in | bcrypt passwords, HS256 JWT |
| `GET /upstreams`, `GET /settings` | signed in | |
| `PATCH /settings` | admin | `mode` calls the gateway's `PUT /_apishield/mode` first. `fail_open` is stored only (the gateway has no endpoint for it) |
| `GET /metrics/summary?range=`, `GET /metrics/timeseries?range=` | signed in | Buckets: 1 min / 15 min / 2 h. `blocked` = action in block, throttle, challenge. p95 comes from a latency histogram (≤10% above exact) |
| `GET /traffic/recent`, `GET /traffic/stream` | signed in | SSE sends `event: traffic` plus a `: ping` every 15 s. The stream alone accepts `?access_token=`, which is redacted from access logs |
| `GET/POST/PATCH/DELETE /rules`, `POST /rules/test` | edit: admin, analyst | Validated with the gateway's own `Rule` class, pushed to the gateway, then saved. `hits_24h` comes from the traffic stream. Gateway-file rules are listed read-only |
| `GET /alerts`, `GET/PATCH /alerts/:id`, `POST /alerts/:id/promote-to-rule` | triage: admin, analyst | `PATCH` returns `{alert, adjustment}`. A false positive writes an `alert_feedback` row |
| `GET /learning/status`, `PATCH /learning`, `POST /learning/reset` | change: admin | Reset sets `reset_requested_at` for the learner |
| `POST /scans`, `GET /scans`, `/scans/:id`, `/scans/:id/findings`, `/scans/:id/report?format=json\|html` | start: admin, analyst | Needs `consent: true`, a host on the allow-list, and safe mode. Runs in a worker thread, one at a time per upstream |
| `POST /findings/:id/apply-rule` | admin, analyst | Pushes the scanner's adapted rule. Sets the finding to `mitigated` only for block, throttle or challenge, not for `log` |
| `GET /endpoints` | signed in | API map: spec ∪ traffic seen in 24 h, with the shadow flag, auth, rate limit and risk |
| `GET /audit-log`, `POST /privacy/purge` | admin | Rule, mode, scan, feedback, learning and purge actions are all audited |
| `POST /demo/alerts/replay` | admin | Demo-replay alerts from the buffered (masked) events, see `demo_alerts.py`. Idempotent: same ids on every run, analyst status kept |
| `POST /demo/reset` | admin, `DEMO_SEED=true` only | Rehearsal reset used by `scripts/demo_reset.py`: deletes scans, findings, feedback and demo-replay alerts, re-seeds the demo alerts, forgets buffered events |

## Privacy

- **Pseudonyms:** `privacy.pseudonymize()` turns `ip_<addr>` and `user_<sub>` into `<prefix>` plus the first 8 hex chars of HMAC-SHA256 with `APISHIELD_PSEUDO_SALT`. `key_` ids are already hashes and pass through. M3 must use the same function and salt.
- **On ingest:** events are masked before anything is stored or broadcast, so raw IPs never reach the database or the browser.
- **Alerts:** the learner writes them, so callers and free text are checked again on the way out.
- **Scan evidence:** masked with the regexes in `masking.py` (JWTs, API keys, bearer tokens, emails, card numbers, IPv4, and `field=value` pairs for the settings' redaction fields). The HTML report is escaped and served with a sandboxing CSP.
- **The one exception:** `Rule.match.ip` holds operator-entered CIDRs and is returned as entered.
- **Tests:** `tests/test_privacy_sweep.py` calls every endpoint plus the SSE stream. It fails if a raw IP, a raw user subject or the gateway token shows up in a response, the database or the logs.

## For M3 (learner)

- **Reading traffic:** read `apishield:traffic` with your own group, `learner`.
- **Alerts:** write rows into `alerts`. Store `caller` already pseudonymized with `admin_api.privacy.pseudonymize`. Set `rank` (1 = most urgent) and optionally `timeline: [{ts, count}]`.
- **Learning progress:** keep `learning_state` up to date (mode, progress, endpoints and shapes learned). Watch `reset_requested_at`.
- **Feedback:** consume `alert_feedback` rows where `consumed_at IS NULL`, then set `consumed_at`. Until you own the math, the Admin API reports a placeholder `threshold_delta` of +0.1 on the top reason's feature.
- **Until you write alerts:** `ADMIN_DEMO_ALERTS=true` makes the Admin API write stand-in alerts (ids `al_demo_*`, explanation ends with "Demo replay: … not by the M3 learner"). They compare each caller with the other callers of the last 15 minutes. Turn the flag off once the learner writes real alerts.

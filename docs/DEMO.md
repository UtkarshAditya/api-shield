# APIShield demo runbook

One page, in order. Story (5–6 min): **scan → apply the suggested rule → switch to ENFORCE → attack burst → ranked alert → mark a false positive.**

## Before the audience arrives (T−15 min)

Run from the repo root. Docker Desktop must be running.

```bash
cp .env.example .env                 # first time only
docker compose up --build -d         # redis, postgres, demo-api :8001, gateway :8080, admin-api + dashboard :8000
python scripts/demo_reset.py         # MONITOR, no scanner/analyst rules, no scans, fresh demo alerts
python scripts/demo_check.py         # full dry run: must print "14/14 steps passed"
python scripts/demo_reset.py         # demo_check leaves ENFORCE + rules on: reset again
```

Open http://localhost:8000 and sign in as `admin@demo.local` / `demo`. Keep two terminals ready at the repo root.

**Terminal 1 (start it about 2 minutes before you begin and leave it running):** normal traffic. The alert detector compares the attacker with these callers, so this must run in the 15 minutes before the burst.

```bash
python scripts/simulate_traffic.py --normal 900 --no-burst
```

## The script

| # | Time | Click | Say |
|---|---|---|---|
| 1 | 0:00 | **Overview** | "APIShield sits in front of any API. This is live traffic from our demo shop. Every caller is a pseudonym: we learn shapes, never contents." |
| 2 | 0:40 | **Scans & reports → New scan →** Next → tick the consent box → **Start scan** | "First, Scan. Safe, read-only probes for the OWASP API Top 10. We ask for consent because a scan sends real attack payloads." |
| 3 | 1:30 | When it's done, open **GET /search → Possible SQL injection** | "It found SQL injection on /search and no rate limit on /login. The evidence is masked before it is stored. Each finding has a risk score with a 'why'." |
| 4 | 2:00 | **Apply suggested rule** (also on **POST /login**) → click the rule id | "Second, Protect. We can't fix their code today, but we can push a gateway rule in one click. The finding now shows *mitigated*." |
| 5 | 2:40 | Top bar **MONITOR** badge → **Switch to ENFORCE** | "Until now we only watched. ENFORCE makes the gateway reject what the rules match. We always confirm first." |
| 6 | 3:10 | **Terminal 2:** `python scripts/simulate_traffic.py --burst-only` then **Live traffic** (Action filter: block) | "Here's an attacker: SQL injection, a scanner, password guessing. 403, 429 and 401, all blocked before they reach the API. Click a row: you see the rules it hit, not its payload." |
| 7 | 4:00 | **Alerts** (sidebar badge) → open **#1** | "Third, Learn. The attacker's key is flagged automatically, ranked #1, in plain English: observed vs normal, with the timeline of the spike." |
| 8 | 4:45 | Open an alert you'd call noise → **False positive** | "Analysts teach it. A false positive adjusts the threshold. Here it shows 'threshold adjusted'." |
| 9 | 5:15 | **Settings & privacy** (Privacy panel, audit log) | "Self-hosted, nothing leaves your network, and every change is audited. Questions?" |

Live alerts are marked *"Demo replay: computed by the Admin API from recent traffic, not by the M3 learner"*. If someone asks: the learner engine exists (`learning/`, 152 tests), and this replay is the bridge into the dashboard until it writes alerts directly.

After the demo, or between rehearsals: `python scripts/demo_reset.py`.

## Fallback layers (switch without apologizing)

1. **Live stack** (above). If Compose itself is the problem, run the same stack as local processes. See `admin_api/README.md` and add `ADMIN_DEMO_ALERTS=true DEMO_SEED=true`.
2. **Mock mode:** no backend at all. `cd frontend && npm run dev` (`VITE_USE_MOCKS=true` is the default in `frontend/.env`), open http://localhost:5173 and sign in as `admin@demo.local` / `demo`. Every screen works on seeded story data: scans finish in about 6 s, apply rule, ENFORCE, alerts and false positives all work. Live traffic is simulated, and there is no real gateway blocking.
3. **Recorded video** of a full run (record it after a clean `demo_check`).

## If it breaks

| Symptom | Fix |
|---|---|
| Dashboard won't load or login fails | `docker compose ps`. If admin-api is not Up: `docker compose logs admin-api`, then `docker compose up -d admin-api`. |
| Mode switch says "gateway is not reachable" | `docker compose restart gateway`. The Admin API pushes the mode and rules back within 30 s. |
| Scan says "already running" | Wait for it, or run `python scripts/demo_reset.py`. |
| Scan fails | Is demo-api up? `curl localhost:8001/openapi.json`. Then `docker compose restart demo-api`. |
| No alert after the burst | Wait 5–10 s. Check normal traffic ran in the last 15 min. Force it: `curl -X POST "localhost:8000/api/demo/alerts/replay?upstream_id=up_shop" -H "Authorization: Bearer <token>"`, or run `python scripts/demo_check.py`, which triggers it. |
| Live traffic empty | Terminal 1 stopped? Restart it. Check Redis: `curl localhost:8080/_apishield/health` must show `"redis": true`. |
| SQLi not blocked | The badge must say ENFORCE (step 5). |
| Anything else, under 30 s to the next slide | Switch to fallback 2 (mock mode). |

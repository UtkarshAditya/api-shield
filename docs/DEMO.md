# APIShield demo runbook

One page, in order. Story (5–6 min): **scan → apply the suggested rule → switch to ENFORCE → attack burst → ranked alert → mark a false positive.**

## Before the audience arrives (T−15 min)

Run from the repo root. Docker Desktop must be running.

```bash
cp .env.example .env                 # first time only
docker compose up --build -d         # redis, postgres, demo-api :8001, gateway :8080, admin-api + dashboard :8000, learning
python scripts/demo_reset.py         # MONITOR, no scanner/analyst rules, no scans, no alerts (learned baseline kept)
python scripts/demo_warmup.py        # normal traffic until the learner says "active": ~75 s the first time, 0 s after
python scripts/demo_check.py         # full dry run: must print "15/15 steps passed"
python scripts/demo_reset.py         # demo_check leaves ENFORCE + rules on: reset again
```

Open http://localhost:8000 and sign in as `admin@demo.local` / `demo`. Keep two terminals ready at the repo root.

**Terminal 1 (start it about 2 minutes before you begin and leave it running):** normal traffic, so Live traffic and the Overview are alive. The learner keeps learning from it.

```bash
python scripts/simulate_traffic.py --normal 900 --no-burst
```

## Where alerts come from (two modes)

| Mode | How to run | Alert ids | Explanation ends with |
|---|---|---|---|
| **Learner (default)** | `docker compose up` as above | UUIDs | `(Learner: priority … from anomaly …, endpoint risk …, repeats …)` |
| **Replay fallback** | `docker compose stop learning` then `ADMIN_DEMO_ALERTS=true ADMIN_SEED_ALERTS=true docker compose up -d admin-api`, then `python scripts/demo_reset.py` | `al_demo_*` (plus canned `al_100x`) | `(Demo replay: computed by the Admin API …)` |

Back to the learner: `docker compose up -d admin-api learning` (the defaults are `false`), then `python scripts/demo_reset.py`.
`demo_check.py --alerts-from learner|replay|any` checks the source (default `learner`, or `replay` when `ADMIN_DEMO_ALERTS=true` is set in your shell).

**The learner (M3)** (`learning/apishield_learning/live.py`) reads the gateway's events, learns per-endpoint baselines (rates, sizes, latency, error ratio, payload shapes, endpoint order), runs M3's detectors, and writes ranked, explained alerts and learning progress into the Admin database. Demo profile (in `docker-compose.yml`, measured with the simulator):

| Setting | Demo | Code default | Why |
|---|---|---|---|
| `APISHIELD_LEARNING_WARMUP_SECONDS` | 30 | 3600 | warm-up fits the demo |
| `APISHIELD_LEARNING_MIN_OBSERVATIONS` | 8 | 30 | `/login` gets ~4 normal requests/min: 8 takes ~70 s |
| `APISHIELD_LEARNING_ALERT_DURING_WARMUP` | false | true | no alerts for the first call to each endpoint during warm-up |
| `APISHIELD_LEARNING_THRESHOLD_MULTIPLIERS` | `latency=3` | none | localhost latency jitter (sd ~2 ms) raised false latency alerts on normal keys; z threshold 9 instead of 3 |
| `APISHIELD_LEARNING_ISOLATION_FOREST` | false | true | trained on ~100 demo samples it flagged ~5 % of normal requests as critical. **Don't claim it in the demo.** If asked: it exists in the learner but isn't tuned for demo-sized data, so it is off |

Measured: warm-up from scratch 72 s (local processes) and 73 s (Compose), then 0 alerts on the normal keys over 404 normal requests, and the burst raises 4–5 learner alerts for `key_929bf132` (`/login` failed logins, `/search` errors and rule hits, `/comments`, `/debug`). The learned baseline survives `demo_reset.py` and restarts; **Settings → Learning → Reset** drops it (warm-up again, ~75 s).

## The script

| # | Time | Click | Say |
|---|---|---|---|
| 1 | 0:00 | **Overview** | "APIShield sits in front of any API. This is live traffic from our demo shop. Every caller is a pseudonym: we learn shapes, never contents." |
| 2 | 0:40 | **Scans & reports → New scan →** Next → tick the consent box → **Start scan** | "First, Scan. Safe, read-only probes for the OWASP API Top 10. We ask for consent because a scan sends real attack payloads." |
| 3 | 1:30 | When it's done, open **GET /search → Possible SQL injection** | "It found SQL injection on /search and no rate limit on /login. The evidence is masked before it is stored. Each finding has a risk score with a 'why'." |
| 4 | 2:00 | **Apply suggested rule** (also on **POST /login**) → click the rule id | "Second, Protect. We can't fix their code today, but we can push a gateway rule in one click. The finding now shows *mitigated*." |
| 5 | 2:40 | Top bar mode control: click the **ENFORCE** segment → **Switch to ENFORCE** (it turns vermilion) | "Until now we only watched. ENFORCE makes the gateway reject what the rules match. We always confirm first." |
| 6 | 3:10 | **Terminal 2:** `python scripts/simulate_traffic.py --burst-only` then **Live traffic** (Action filter: block) | "Here's an attacker: SQL injection, a scanner, password guessing. 403, 429 and 401, all blocked before they reach the API. Click a row: you see the rules it hit, not its payload." |
| 7 | 4:00 | **Alerts** (sidebar badge) → open **#1** | "Third, Learn. The learner compared the attacker's key with what it learned from normal traffic: flagged automatically, ranked #1, in plain English: observed vs normal, with the timeline of the spike. It's a signal, not a verdict." Then open the attacker's **GET /search** alert: "The scan rated /search high risk, so this alert is ranked higher. It says so in the explanation." Use **/search** for this point, not /login: /login's scan risk is low, so the scan *lowers* its priority (M3's formula, accepted for the demo). |
| 8 | 4:45 | Open an alert whose top reason in the "why" list shows a z-score (e.g. Request rate, Error ratio, Response size) → **False positive** | "Analysts teach it. A false positive raises that detector's threshold by 10 %, and the learner records what it applied." The UI shows "threshold adjusted" only for z-scored reasons; signal-only alerts like *Rule hits / blocked* just say *Marked as false positive*. |
| 9 | 5:15 | **Settings & privacy** (Privacy panel, audit log) | "Self-hosted, nothing leaves your network, and every change is audited. Questions?" |

Alerts come from the M3 learner: ids are UUIDs and the explanation ends with *"(Learner: priority …)"*. If you switched to the replay fallback, they are marked *"Demo replay: computed by the Admin API from recent traffic, not by the M3 learner"*: say so if asked.

After the demo, or between rehearsals: `python scripts/demo_reset.py`.

## Fallback layers (switch without apologizing)

1. **Live stack** (above). If the learner misbehaves, switch to the replay fallback (table above). If Compose itself is the problem, run the same stack as local processes: see `admin_api/README.md` (`DEMO_SEED=true ADMIN_DEMO_ALERTS=false ADMIN_SEED_ALERTS=false`) and `learning/README.md` (live mode, same `ADMIN_DATABASE_URL` and `APISHIELD_PSEUDO_SALT`), or simply `ADMIN_DEMO_ALERTS=true DEMO_SEED=true` without the learner.
2. **Mock mode:** no backend at all. `cd frontend && npm run dev` (`VITE_USE_MOCKS=true` is the default in `frontend/.env`), open http://localhost:5173 and sign in as `admin@demo.local` / `demo`. Every screen works on seeded story data: scans finish in about 6 s, apply rule, ENFORCE, alerts and false positives all work. Live traffic is simulated, and there is no real gateway blocking.
3. **Recorded video** of a full run (record it after a clean `demo_check`).

## If it breaks

| Symptom | Fix |
|---|---|
| Dashboard won't load or login fails | `docker compose ps`. If admin-api is not Up: `docker compose logs admin-api`, then `docker compose up -d admin-api`. |
| Mode switch says "gateway is not reachable" | `docker compose restart gateway`. The Admin API pushes the mode and rules back within 30 s. |
| Scan says "already running" | Wait for it, or run `python scripts/demo_reset.py`. |
| Scan fails | Is demo-api up? `curl localhost:8001/openapi.json`. Then `docker compose restart demo-api`. |
| No alert after the burst | Wait 5 s. Is the learner active? `python scripts/demo_warmup.py` (returns at once when it is). `docker compose logs learning --tail 20` shows mode, counts and errors. Still nothing: switch to the replay fallback (table above). |
| Learning shows warm-up during the demo | Someone pressed Reset in Settings: run `python scripts/demo_warmup.py` (~75 s), or switch to the replay fallback. |
| Normal keys get alerts | Normal traffic ran faster than the simulator's defaults, or the gateway rate limit was hit (two simulators at once?). Stop extra simulators; mark them false positive, or `python scripts/demo_reset.py`. |
| Live traffic empty | Terminal 1 stopped? Restart it. Check Redis: `curl localhost:8080/_apishield/health` must show `"redis": true`. |
| SQLi not blocked | The badge must say ENFORCE (step 5). |
| Anything else, under 30 s to the next slide | Switch to fallback 2 (mock mode). |

"""Runs the whole demo flow against a RUNNING stack and prints PASS/FAIL per step.

    python scripts/demo_reset.py && python scripts/demo_check.py
    python scripts/demo_check.py --admin http://localhost:8000 --gateway http://localhost:8080 --normal 20
    python scripts/demo_check.py --alerts-from replay     # the Admin API's stand-in (ADMIN_DEMO_ALERTS=true)

It starts nothing. Steps: login, normal traffic through the gateway (scripts/simulate_traffic.py),
metrics > 0 with masked callers, learner warm-up (scripts/demo_warmup.py), scan finishes, apply
suggested rules, switch to ENFORCE, SQL injection gets 403, no-auth /admin/stats gets 401, /login
is throttled with 429, the attack burst produces an alert for the attacker from the chosen
source, learning status is readable.

--alerts-from: `learner` (default unless ADMIN_DEMO_ALERTS=true in this shell) accepts only alerts
written by the M3 learner (not an `al_demo_` replay id, not a canned `al_100x` seed, and an
explanation carrying the "(Learner:" marker); `replay` accepts only `al_demo_` alerts; `any`
accepts either. With `learner` the warm-up step must reach "active".

It changes the stack (rules applied, ENFORCE on): run scripts/demo_reset.py afterwards.
Exit code 0 only when every step passed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
PSEUDONYM = re.compile(r"^(key|ip|user)_[0-9a-f]{8}$")
RAW_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


CANNED = re.compile(r"^al_\d+$")  # seeded story alerts (admin_api/seed.py)


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_simulator():
    return load_module("simulate_traffic")


def alert_source(alert: dict) -> str:
    if not alert:
        return "none"
    if alert["id"].startswith("al_demo_"):
        return "replay"
    if CANNED.match(alert["id"]):
        return "seed"
    return "learner" if "(Learner:" in alert.get("explanation", "") else "unknown"


class Check:
    def __init__(self):
        self.results: list = []

    def step(self, name: str, passed: bool, detail: str = "") -> bool:
        self.results.append((name, passed))
        print(f"{'PASS' if passed else 'FAIL'}  {name}{f'  ({detail})' if detail else ''}", flush=True)
        return passed


def wait_for(fn, timeout: float, every: float = 1.0):
    """Calls fn until it returns something truthy or the timeout passes; returns the last value."""
    end = time.monotonic() + timeout
    value = fn()
    while not value and time.monotonic() < end:
        time.sleep(every)
        value = fn()
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin", default="http://localhost:8000", help="Admin API base URL")
    parser.add_argument("--gateway", default="http://localhost:8080", help="Gateway base URL")
    parser.add_argument("--email", default="admin@demo.local")
    parser.add_argument("--password", default="demo")
    parser.add_argument("--upstream", default="up_shop")
    parser.add_argument("--normal", type=float, default=20, help="seconds of normal traffic")
    parser.add_argument("--scan-timeout", type=float, default=180)
    parser.add_argument("--warmup-timeout", type=float, default=180)
    replay_default = os.environ.get("ADMIN_DEMO_ALERTS", "false").strip().lower() in ("1", "true", "yes", "on")
    parser.add_argument("--alerts-from", choices=("learner", "replay", "any"),
                        default="replay" if replay_default else "learner",
                        help="which alert source counts (default: learner unless ADMIN_DEMO_ALERTS=true)")
    args = parser.parse_args()
    print(f"alerts from: {args.alerts_from}")

    sim = load_simulator()
    c = Check()
    q = {"upstream_id": args.upstream}
    attacker = "key_" + hashlib.sha256(sim.ATTACKER_KEY.encode()).hexdigest()[:8]

    with httpx.Client(base_url=args.admin.rstrip("/") + "/api", timeout=20.0) as api, \
            httpx.Client(base_url=args.gateway, timeout=10.0) as gw:
        # 1. login
        try:
            resp = api.post("/auth/login", json={"email": args.email, "password": args.password})
        except httpx.HTTPError as exc:
            c.step("login", False, f"Admin API not reachable: {exc}")
            return 1
        if not c.step("login", resp.status_code == 200, f"{args.email} -> {resp.status_code}"):
            return 1
        api.headers["Authorization"] = f"Bearer {resp.json()['token']}"
        try:
            health = gw.get("/_apishield/health").json()
        except httpx.HTTPError as exc:
            c.step("gateway reachable", False, str(exc))
            return 1
        c.step("gateway reachable", health.get("status") == "ok", f"mode {health.get('mode')}, redis {health.get('redis')}")
        if health.get("mode") == "enforce":
            print("      note: the gateway is already in ENFORCE; run scripts/demo_reset.py for a clean run")

        # 2. normal traffic
        counts = sim.run_normal(gw, args.normal, 5, random.Random(7))
        c.step("simulator normal traffic", sum(counts.values()) > 0 and set(counts) == {200},
               f"statuses {dict(sorted(counts.items()))}")

        # 3. metrics > 0, callers masked
        summary = wait_for(lambda: (s := api.get("/metrics/summary", params={**q, "range": "1h"}).json())
                           .get("requests", 0) > 0 and s, timeout=15)
        c.step("metrics show traffic", bool(summary), f"{(summary or {}).get('requests', 0)} requests in the last hour")
        recent = api.get("/traffic/recent", params={**q, "limit": 500})
        callers = {e["caller"] for e in recent.json().get("items", [])} if recent.status_code == 200 else set()
        ips = {e["ip"] for e in recent.json().get("items", [])} if recent.status_code == 200 else set()
        raw = RAW_IP.findall(recent.text)
        c.step("callers are masked", bool(callers) and all(PSEUDONYM.match(x) for x in callers | ips) and not raw,
               f"{len(callers)} callers, e.g. {sorted(callers)[:3]}" + (f"; raw IPs seen: {raw[:3]}" if raw else ""))

        # 3b. learner warm-up (normal traffic until GET /learning/status says active)
        warmup = load_module("demo_warmup")
        ok, status, seconds = warmup.warm_up(api, gw, args.upstream, timeout=args.warmup_timeout,
                                             out=lambda line, **kw: print("    " + line.strip(), **kw))
        if args.alerts_from == "learner":
            c.step("learner warm-up done", ok, f"{status.get('mode')} after {seconds:.0f}s, "
                   f"{status.get('endpoints_learned')} endpoints, {status.get('shapes_learned')} shapes")
        else:
            print(f"      warm-up: {status.get('mode')} after {seconds:.0f}s (not required for --alerts-from "
                  f"{args.alerts_from})")

        # 4. scan
        resp = api.post("/scans", json={"upstream_id": args.upstream, "consent": True, "safe_mode": True})
        scan = resp.json() if resp.status_code == 202 else None
        if scan:
            scan = wait_for(lambda: (s := api.get(f"/scans/{scan['id']}").json())["status"] in ("done", "failed") and s,
                            timeout=args.scan_timeout, every=2)
        done = bool(scan) and scan.get("status") == "done"
        c.step("scan finishes", done, f"{scan.get('status')} {scan.get('counts')} risk {scan.get('api_risk_score')}"
               if scan else f"start failed: {resp.status_code} {resp.text[:150]}")

        # 5. apply suggested rules
        applied = []
        if done:
            findings = api.get(f"/scans/{scan['id']}/findings", params={"limit": 200}).json()["items"]
            for f in findings:
                if f.get("suggested_rule") and f["status"] == "open":
                    r = api.post(f"/findings/{f['id']}/apply-rule")
                    if r.status_code == 200:
                        applied.append(f["suggested_rule"]["id"])
        rules = {r["id"]: r for r in api.get("/rules", params={**q, "limit": 500}).json().get("items", [])}
        c.step("apply suggested rules", bool(applied) and all(a in rules for a in applied),
               f"{len(applied)} applied: {sorted(set(applied))}")

        # 6. enforce
        resp = api.patch("/settings", json={"mode": "enforce"})
        mode = gw.get("/_apishield/health").json().get("mode")
        c.step("switch to ENFORCE", resp.status_code == 200 and mode == "enforce", f"gateway mode {mode}")

        # 7-9. the gateway blocks the attacks
        alice = {"X-API-Key": sim.NORMAL_KEYS[0]}
        r = gw.get("/search", params={"q": "' OR '1'='1"}, headers=alice)
        c.step("SQL injection blocked (403)", r.status_code == 403, f"got {r.status_code}")
        r = gw.get("/admin/stats")
        c.step("no-auth /admin/stats rejected (401)", r.status_code == 401, f"got {r.status_code}")
        statuses = []
        for i in range(8):
            statuses.append(gw.post("/login", json={"username": "alice", "password": f"wrong{i}"},
                                    headers={"X-API-Key": sim.ATTACKER_KEY}).status_code)
            if statuses[-1] == 429:
                break
        c.step("login throttled (429)", 429 in statuses, f"statuses {statuses}")

        # 10. attack burst -> ranked, explained alert for the attacker
        burst = sim.run_burst(gw, rounds=2, brute_force=10)
        print(f"      burst: {dict(sorted(burst.items()))}")

        wanted = {"learner": ("learner",), "replay": ("replay",), "any": ("learner", "replay")}[args.alerts_from]

        def attacker_alerts():
            items = api.get("/alerts", params={**q, "status": "active", "sort": "rank", "limit": 200}).json()["items"]
            return [a for a in items if a["caller"] == attacker and alert_source(a) in wanted]
        found = wait_for(attacker_alerts, timeout=20)
        how = {"learner": "M3 learner", "replay": "background replay (ADMIN_DEMO_ALERTS=true)",
               "any": "learner or replay"}[args.alerts_from]
        if not found and args.alerts_from != "learner":
            r = api.post("/demo/alerts/replay", params=q)
            how = f"triggered POST /demo/alerts/replay -> {r.status_code}"
            found = attacker_alerts()
        top = found[0] if found else {}
        c.step("alert for the attacker", bool(found) and bool(top.get("reasons")) and bool(top.get("explanation")),
               f"{len(found)} alert(s) for {attacker} via {how}; top #{top.get('rank')} {top.get('severity')} "
               f"{top.get('endpoint')} score {top.get('score')} id {top.get('id')} [{alert_source(top)}]"
               if found else f"none for {attacker} ({how})")
        if found:
            print(f"      reasons: {[r['feature'] for r in top['reasons']]}")
            print(f"      explanation: {top['explanation']}")
        leaked = RAW_IP.findall(json.dumps(found))
        c.step("alerts carry no raw IPs", not leaked, f"found {leaked[:3]}" if leaked else "")

        # 11. learning
        r = api.get("/learning/status", params=q)
        c.step("learning status readable", r.status_code == 200 and "mode" in r.json(),
               f"{r.json().get('mode')} {r.json().get('progress')}" if r.status_code == 200 else str(r.status_code))

    failed = [n for n, ok in c.results if not ok]
    print(f"\n{len(c.results) - len(failed)}/{len(c.results)} steps passed." +
          (f" Failed: {', '.join(failed)}" if failed else " The demo flow works end to end."))
    print("The stack is now in ENFORCE with the scanner's rules applied: run scripts/demo_reset.py before the next run.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

"""Puts a running APIShield stack back to the demo's starting state, for the next rehearsal.

    python scripts/demo_reset.py                       # Admin API on http://localhost:8000
    python scripts/demo_reset.py --admin http://localhost:8000 --email admin@demo.local

It starts nothing. Through the Admin API (which keeps the gateway in sync) it:
  1. switches the gateway to MONITOR,
  2. deletes scanner, analyst and learner rules (built-in rules stay),
  3. calls POST /api/demo/reset: deletes scans, findings and alert feedback, removes the
     demo-replay alerts, re-seeds the demo alerts with fresh times, and forgets buffered
     events so the last burst does not come back as alerts.
Users, settings (except the mode), traffic counts and the audit log are kept.
Needs the Admin API to run with DEMO_SEED=true (step 3 refuses otherwise).
Exit code 0 when everything was reset, 1 otherwise.
"""
from __future__ import annotations

import argparse
import sys

import httpx

REMOVABLE_SOURCES = ("scanner", "analyst", "learner")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin", default="http://localhost:8000", help="Admin API base URL")
    parser.add_argument("--email", default="admin@demo.local")
    parser.add_argument("--password", default="demo")
    parser.add_argument("--upstream", default="up_shop")
    args = parser.parse_args()

    ok = True
    with httpx.Client(base_url=args.admin.rstrip("/") + "/api", timeout=15.0) as api:
        try:
            resp = api.post("/auth/login", json={"email": args.email, "password": args.password})
        except httpx.HTTPError as exc:
            print(f"FAIL  Admin API not reachable at {args.admin}: {exc}")
            return 1
        if resp.status_code != 200:
            print(f"FAIL  login as {args.email}: {resp.status_code} {resp.text[:200]}")
            return 1
        api.headers["Authorization"] = f"Bearer {resp.json()['token']}"
        q = {"upstream_id": args.upstream}

        resp = api.patch("/settings", json={"mode": "monitor"})
        ok &= report(resp.status_code == 200, "mode set to MONITOR", resp)

        rules = api.get("/rules", params={**q, "limit": 500})
        removed, kept = [], []
        for rule in rules.json().get("items", []) if rules.status_code == 200 else []:
            if rule["source"] not in REMOVABLE_SOURCES:
                kept.append(rule["id"])
                continue
            resp = api.delete(f"/rules/{rule['id']}", params=q)
            if resp.status_code == 204:
                removed.append(rule["id"])
            else:
                ok = False
                report(False, f"delete rule {rule['id']}", resp)
        ok &= report(rules.status_code == 200, f"rules: removed {len(removed)} {removed}, kept {len(kept)} built-in", rules)

        resp = api.post("/demo/reset", params=q)
        detail = resp.json() if resp.status_code == 200 else None
        ok &= report(resp.status_code == 200, f"scans, findings, feedback and demo alerts reset {detail or ''}", resp)

    print("Stack reset for the next rehearsal." if ok else "Reset finished with failures (see above).")
    return 0 if ok else 1


def report(passed: bool, label: str, resp: httpx.Response) -> bool:
    if passed:
        print(f"OK    {label}")
    else:
        print(f"FAIL  {label}: {resp.status_code} {resp.text[:200]}")
    return passed


if __name__ == "__main__":
    sys.exit(main())

"""Sends demo traffic through the gateway: normal use from two API keys, then an attack
burst from a third. Run from the repo root:

    python scripts/simulate_traffic.py                       # 30 s normal, then the burst
    python scripts/simulate_traffic.py --normal 10 --burst-only
    python scripts/simulate_traffic.py --gateway http://localhost:8080 --rps 8

The keys are placeholders until M1 confirms them; the gateway must know them, e.g.
APISHIELD_API_KEYS=alice:key-alice,bob:key-bob,mallory:key-mallory (docker-compose.yml sets this).
Always target the gateway (:8080). Never point this at an API you do not own.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from collections import Counter
from urllib.parse import urlsplit

import httpx

NORMAL_KEYS = ["key-alice", "key-bob"]  # PLACEHOLDER: confirm with M1
ATTACKER_KEY = "key-mallory"            # PLACEHOLDER: confirm with M1
SEARCH_TERMS = ["al", "bob", "shoes", "admin", "a", "x", "lamp"]

ATTACKS = [
    ("sqli", "GET", "/search", {"params": {"q": "' OR '1'='1"}}),
    ("sqli", "GET", "/search", {"params": {"q": "x' UNION SELECT username, password FROM users --"}}),
    ("sqli", "GET", "/search", {"params": {"q": "1; DROP TABLE users; --"}}),
    ("traversal", "GET", "/search", {"params": {"q": "../../etc/passwd"}}),
    ("xss", "POST", "/comments", {"json": {"text": "<script>document.cookie</script>"}}),
    ("scanner-ua", "GET", "/search", {"params": {"q": "a"}, "headers": {"User-Agent": "sqlmap/1.7"}}),
    ("no-auth", "GET", "/admin/stats", {}),
    ("debug", "GET", "/debug", {}),
]


def normal_request(client: httpx.Client, rng: random.Random) -> httpx.Response:
    key = rng.choice(NORMAL_KEYS)
    headers = {"X-API-Key": key, "User-Agent": "demo-shop-web/2.3"}
    roll = rng.random()
    if roll < 0.6:
        return client.get("/search", params={"q": rng.choice(SEARCH_TERMS)}, headers=headers)
    if roll < 0.8:
        return client.post("/comments", json={"text": rng.choice(["Great!", "Fast shipping", "Would buy again"])},
                           headers=headers)
    user = "alice" if key == "key-alice" else "bob"
    return client.post("/login", json={"username": user, "password": f"{user}123"}, headers=headers)


def run_normal(client: httpx.Client, seconds: float, rps: float, rng: random.Random) -> Counter:
    counts: Counter = Counter()
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        counts[normal_request(client, rng).status_code] += 1
        time.sleep(rng.expovariate(rps))
    return counts


def run_burst(client: httpx.Client, rounds: int, brute_force: int) -> Counter:
    counts: Counter = Counter()
    headers = {"X-API-Key": ATTACKER_KEY}
    for _ in range(rounds):
        for name, method, path, kwargs in ATTACKS:
            h = {**headers, **kwargs.get("headers", {})}
            resp = client.request(method, path, params=kwargs.get("params"), json=kwargs.get("json"), headers=h)
            counts[f"{name} {resp.status_code}"] += 1
    for i in range(brute_force):  # credential stuffing against /login
        resp = client.post("/login", json={"username": "alice", "password": f"guess{i}"}, headers=headers)
        counts[f"login-bruteforce {resp.status_code}"] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--gateway", default="http://localhost:8080")
    parser.add_argument("--normal", type=float, default=30, help="seconds of normal traffic before the burst")
    parser.add_argument("--rps", type=float, default=5, help="average normal requests per second")
    parser.add_argument("--rounds", type=int, default=5, help="times the attack list is repeated")
    parser.add_argument("--brute-force", type=int, default=30, help="failed /login attempts in the burst")
    parser.add_argument("--burst-only", action="store_true")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    if urlsplit(args.gateway).port == 8001:
        print("Refusing: :8001 is the demo API itself. Send traffic through the gateway (:8080).")
        return 2
    rng = random.Random(args.seed)
    with httpx.Client(base_url=args.gateway, timeout=5.0) as client:
        try:
            client.get("/_apishield/health").raise_for_status()
        except httpx.HTTPError as exc:
            print(f"Gateway not reachable at {args.gateway}: {exc}")
            return 1
        if not args.burst_only:
            print(f"normal traffic for {args.normal:.0f}s from {len(NORMAL_KEYS)} keys...")
            print("  statuses:", dict(sorted(run_normal(client, args.normal, args.rps, rng).items())))
        print(f"attack burst from {ATTACKER_KEY}...")
        for line, n in sorted(run_burst(client, args.rounds, args.brute_force).items()):
            print(f"  {line}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

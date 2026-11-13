"""Sends normal traffic only, until the learner reports warm-up done (or a timeout).

    python scripts/demo_warmup.py                  # Admin API :8000, gateway :8080, up to 180 s
    python scripts/demo_warmup.py --timeout 120 --extra 20

Run it while presenting the Overview. It uses the simulator's normal mix (two API keys,
mostly /search, some /comments, a few logins) and polls GET /api/learning/status every few
seconds, printing mode, progress and endpoints learned. If the learner already learned the
baseline (it keeps it across demo resets and restarts), it returns at once.
--extra keeps normal traffic going a little longer after warm-up, so the Isolation Forest
also gets training samples.
Exit code 0 when the status is "active", 1 on timeout or error.
"""
from __future__ import annotations

import argparse
import importlib.util
import random
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent


def load_simulator():
    spec = importlib.util.spec_from_file_location("simulate_traffic", HERE / "simulate_traffic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def login(api: httpx.Client, email: str, password: str) -> None:
    resp = api.post("/auth/login", json={"email": email, "password": password})
    resp.raise_for_status()
    api.headers["Authorization"] = f"Bearer {resp.json()['token']}"


def warm_up(api: httpx.Client, gw: httpx.Client, upstream: str, *, timeout: float = 180, extra: float = 0,
            rps: float = 5, chunk: float = 5, seed: int = 11, out=print) -> tuple[bool, dict, float]:
    """Normal traffic in `chunk`-second slices until learning is active. Returns (ok, status, seconds)."""
    sim = load_simulator()
    rng = random.Random(seed)
    logins = sim.LoginBudget(2)  # one budget across chunks keeps every key under the gateway's login limit
    started = time.monotonic()
    status: dict = {}
    sent = 0
    while True:
        status = api.get("/learning/status", params={"upstream_id": upstream}).json()
        elapsed = time.monotonic() - started
        out(f"  {elapsed:5.0f}s  mode {status.get('mode'):<8} progress {status.get('progress', 0):.2f}  "
            f"endpoints learned {status.get('endpoints_learned')}  shapes {status.get('shapes_learned')}  "
            f"({sent} requests sent)", flush=True)
        if status.get("mode") == "active" and status.get("progress", 0) >= 1:
            break
        if status.get("mode") == "disabled":
            out("  learning is disabled (Settings > Learning): not waiting")
            return False, status, elapsed
        if elapsed >= timeout:
            return False, status, elapsed
        sent += sum(sim.run_normal(gw, chunk, rps, rng, logins=logins).values())
    if extra > 0:
        out(f"  active; {extra:.0f}s more normal traffic for the Isolation Forest...", flush=True)
        sent += sum(sim.run_normal(gw, extra, rps, rng, logins=logins).values())
    return True, status, time.monotonic() - started


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--admin", default="http://localhost:8000", help="Admin API base URL")
    parser.add_argument("--gateway", default="http://localhost:8080", help="Gateway base URL")
    parser.add_argument("--email", default="admin@demo.local")
    parser.add_argument("--password", default="demo")
    parser.add_argument("--upstream", default="up_shop")
    parser.add_argument("--timeout", type=float, default=180, help="give up after this many seconds")
    parser.add_argument("--extra", type=float, default=0, help="seconds of normal traffic after warm-up")
    parser.add_argument("--rps", type=float, default=5, help="average normal requests per second")
    args = parser.parse_args()

    with httpx.Client(base_url=args.admin.rstrip("/") + "/api", timeout=15.0) as api, \
            httpx.Client(base_url=args.gateway, timeout=10.0) as gw:
        try:
            login(api, args.email, args.password)
            gw.get("/_apishield/health").raise_for_status()
        except httpx.HTTPError as exc:
            print(f"FAIL  stack not reachable: {exc}")
            return 1
        print("warming up the learner with normal traffic...")
        ok, status, seconds = warm_up(api, gw, args.upstream, timeout=args.timeout, extra=args.extra, rps=args.rps)
    if ok:
        print(f"OK    learner active after {seconds:.0f}s: {status.get('endpoints_learned')} endpoints, "
              f"{status.get('shapes_learned')} shapes learned")
        return 0
    print(f"FAIL  not active after {seconds:.0f}s (mode {status.get('mode')}, progress {status.get('progress')}). "
          "Is the learner running? docker compose logs learning")
    return 1


if __name__ == "__main__":
    sys.exit(main())

"""Writes one JSON sample per Admin API endpoint to frontend/src/test/contract/samples/.
The frontend test `src/test/contract.test.ts` parses each one with its Zod schema, so
`npm test` fails if the Admin API drifts from the contract.

Volatile values (timestamps, generated ids, tokens, and time-series counts, which depend on
where "now" falls in a bucket) are replaced with fixed placeholders, so the committed files
only change when a response shape changes."""
import json
import re
from pathlib import Path

from .scenario import build, call_everything

SAMPLES = Path(__file__).resolve().parents[2] / "frontend" / "src" / "test" / "contract" / "samples"
NOT_IN_CONTRACT = {"scan_report_json", "scan_report_html"}  # downloads, not parsed by the UI

_ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?")
_IDS = re.compile(r"\b(sc|fd|au)_[0-9a-f]{12}\b")
_VOLATILE_KEYS = {"req_id": "req_0000", "request_id": "0" * 32, "token": "<jwt>"}


def stabilize(value, key=None):
    if key in _VOLATILE_KEYS and isinstance(value, str):
        return _VOLATILE_KEYS[key]
    if isinstance(value, str):
        return _IDS.sub(lambda m: f"{m.group(1)}_000000000000", _ISO.sub("2026-01-01T00:00:00.000Z", value))
    if isinstance(value, dict):
        out = {k: stabilize(v, k) for k, v in value.items()}
        if "points" in out and "metric" in out:  # a Timeseries
            out["points"] = [{**p, "allowed": 0, "blocked": 0} for p in out["points"][-3:]]
        return out
    if isinstance(value, list):
        return [stabilize(v) for v in value]
    return value


def test_write_contract_samples():
    responses = call_everything(*build())
    SAMPLES.mkdir(parents=True, exist_ok=True)
    written = set()
    for name, (_status, body) in sorted(responses.items()):
        if name in NOT_IN_CONTRACT:
            continue
        assert not isinstance(body, str), f"{name} did not return JSON"
        text = json.dumps(stabilize(body), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        path = SAMPLES / f"{name}.json"
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
        written.add(path.name)
    for stale in set(p.name for p in SAMPLES.glob("*.json")) - written:
        (SAMPLES / stale).unlink()
    assert len(written) == len(responses) - len(NOT_IN_CONTRACT)

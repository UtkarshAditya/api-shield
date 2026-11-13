"""Map learner alerts onto the Admin API's shared ``alerts`` table (M4 contract).

Pure functions, no I/O. Only pseudonymous caller ids, path templates, counts and
numbers are produced; detector evidence that could carry anything else (shape
hashes, sequence keys) is summarized as counts.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Mapping

ADMIN_SEVERITIES = ("critical", "high", "medium", "low")
MARKER_PREFIX = "(Learner:"
TIMELINE_BUCKET_SECONDS = 15
TIMELINE_BUCKETS = 20
Z_CAP = 99.0

# detector name -> label shown in the dashboard's "why" list
DETECTOR_LABELS = {
    "request_rate_spike": "Request rate",
    "request_size": "Request size",
    "response_size": "Response size",
    "latency": "Latency",
    "http_error_rate": "Error ratio",
    "new_payload_shape": "New payload shape",
    "unexpected_endpoint_method": "Unexpected endpoint",
    "rule_hit_or_blocked_action": "Rule hits / blocked",
    "endpoint_sequence": "Unusual endpoint sequence",
    "isolation_forest": "Unusual feature combination",
}
LOGIN_ERROR_LABEL = "Failed logins"
LABEL_TO_DETECTOR = {label: name for name, label in DETECTOR_LABELS.items()}
LABEL_TO_DETECTOR[LOGIN_ERROR_LABEL] = "http_error_rate"

_UNITS = {"request_size": "B", "response_size": "B", "latency": "ms"}


def detector_for_label(label: str | None) -> str | None:
    """Detector name for a reason label (the Admin API stores the label as feedback.feature)."""
    if not label:
        return None
    return LABEL_TO_DETECTOR.get(label) or (label if label in DETECTOR_LABELS else None)


def admin_endpoint(alert: Mapping[str, Any]) -> str:
    return f"{alert['method']} {alert['endpoint']}"


def group_id(alert: Mapping[str, Any]) -> str:
    return "grp_" + str(alert.get("grouping_key") or alert["alert_id"])[:12]


def to_alert_row(
    alert: Mapping[str, Any], upstream_id: str, timeline: list[dict[str, Any]] | None
) -> dict[str, Any] | None:
    """Column values for an ``alerts`` row, or None for info-level alerts (not shown).

    ``status`` and ``rank`` are left out: the Admin API owns status, and rank is
    recomputed for the whole upstream after every write.
    """
    severity = alert.get("severity")
    if severity not in ADMIN_SEVERITIES:
        return None
    reasons = build_reasons(alert)
    return {
        "id": str(alert["alert_id"]),
        "upstream_id": upstream_id,
        "ts": parse_ts(str(alert.get("last_seen") or alert["timestamp"])),
        "caller": str(alert["caller_id"]),
        "endpoint": admin_endpoint(alert),
        "score": round(float(alert["priority_score"]), 4),
        "severity": severity,
        "reasons": reasons,
        "explanation": build_explanation(alert, reasons),
        "group_id": group_id(alert),
        "timeline": timeline or None,
    }


# ---- reasons ---------------------------------------------------------------------------

def build_reasons(alert: Mapping[str, Any]) -> list[dict[str, Any]]:
    observed = alert.get("observed_values") or {}
    expected = alert.get("expected_values") or {}
    is_login = str(alert.get("endpoint", "")).rstrip("/").endswith("/login")
    reasons = []
    for name in alert.get("detector_names") or ():
        reason = _reason(name, observed.get(name), expected.get(name), is_login)
        if reason is not None:
            reasons.append(reason)
    reasons.sort(key=lambda r: (-(r.get("z") or 0.0), r["feature"]))
    return reasons


def _reason(name: str, observed: Any, expected: Any, is_login: bool) -> dict[str, Any] | None:
    label = DETECTOR_LABELS.get(name)
    if label is None:
        return None
    if name in ("request_rate_spike", "request_size", "response_size", "latency"):
        stats = expected if isinstance(expected, Mapping) else {}
        value = _number(observed)
        typical = _number(stats.get("ewma"))
        typical = typical if typical is not None else _number(stats.get("mean"))
        unit = _UNITS.get(name, "")
        if name == "request_rate_spike":
            obs, base = f"{_fmt(value)} req/min", f"{_fmt(typical)} req/min"
        else:
            obs, base = f"{_fmt(value)} {unit}", f"{_fmt(typical)} {unit}"
        return _with_z({"feature": label, "observed": obs, "baseline": f"typically {base}"},
                       value, stats)
    if name == "http_error_rate":
        stats = expected if isinstance(expected, Mapping) else {}
        mean = _number(stats.get("mean"))
        reason = {
            "feature": LOGIN_ERROR_LABEL if is_login else label,
            "observed": "failed responses (4xx/5xx)",
            "baseline": f"{_pct(mean)} of requests fail normally",
        }
        return _with_z(reason, _number(observed), stats)
    if name == "new_payload_shape":
        known = len(expected) if isinstance(expected, (list, tuple)) else 0
        return {"feature": label, "observed": "a payload shape never seen on this endpoint",
                "baseline": f"{known} learned shape(s)"}
    if name == "unexpected_endpoint_method":
        known = len(expected) if isinstance(expected, (list, tuple)) else 0
        return {"feature": label, "observed": "no learned baseline for this endpoint",
                "baseline": f"{known} learned endpoint(s)"}
    if name == "rule_hit_or_blocked_action":
        data = observed if isinstance(observed, Mapping) else {}
        hits = data.get("rule_hit_count", 0)
        action = data.get("action", "allow")
        action = action if action in ("allow", "log", "block", "throttle", "challenge") else "other"
        return {"feature": label, "observed": f"{hits} rule hit(s), action {action}",
                "baseline": "no rule hits, allowed"}
    if name == "endpoint_sequence":
        known = len(expected) if isinstance(expected, (list, tuple)) else 0
        return {"feature": label, "observed": "an endpoint order never seen before",
                "baseline": f"{known} known next step(s)"}
    if name == "isolation_forest":
        value = _number(observed)
        return {"feature": label, "observed": f"anomaly score {_fmt(value, 2)}",
                "baseline": "trained on normal traffic"}
    return None


def _with_z(reason: dict[str, Any], value: float | None, stats: Mapping[str, Any]) -> dict[str, Any]:
    mean, std = _number(stats.get("mean")), _number(stats.get("standard_deviation"))
    if value is not None and mean is not None and std:
        reason["z"] = round(max(-Z_CAP, min(Z_CAP, (value - mean) / std)), 1)
    elif value is not None and mean is not None and std == 0 and value != mean:
        reason["z"] = Z_CAP  # learned value never varied: any deviation is maximal
    return reason


# ---- explanation -------------------------------------------------------------------------

_PHRASES = {
    "rule_hit_or_blocked_action": "its requests matched gateway rules or were blocked",
    "http_error_rate": "it got failed responses where this endpoint normally succeeds",
    "new_payload_shape": "it sent a request shape this endpoint has never seen",
    "unexpected_endpoint_method": "it called an endpoint that normal traffic does not use",
    "request_rate_spike": "the endpoint's request rate jumped far above its learned rate",
    "request_size": "its request size is far from what this endpoint usually receives",
    "response_size": "the responses it got are far from the usual size",
    "latency": "its requests were much slower than usual",
    "endpoint_sequence": "it moved between endpoints in an order normal callers never use",
    "isolation_forest": "its overall mix of features looks unlike normal traffic",
}
_ORDER = tuple(_PHRASES)


def build_explanation(alert: Mapping[str, Any], reasons: list[dict[str, Any]] | None = None) -> str:
    """Two or three plain sentences for a developer, ending with the learner marker."""
    endpoint = admin_endpoint(alert)
    names = [n for n in _ORDER if n in set(alert.get("detector_names") or ())]
    is_login = str(alert.get("endpoint", "")).rstrip("/").endswith("/login")
    phrases = [_PHRASES[n] for n in names[:3]]
    if is_login and "http_error_rate" in names:
        phrases[names.index("http_error_rate")] = "its logins kept failing"
    count = int(alert.get("repeat_count") or 1)
    what = f"This caller made {count} unusual request{'s' if count != 1 else ''} to {endpoint}"
    what += f": {_join(phrases)}." if phrases else "."
    compared = "Compared with the baseline learned from this API's normal traffic"
    risk = alert.get("endpoint_risk_score")
    if isinstance(risk, (int, float)) and risk >= 0.6:
        why = (f"{compared}, this stands out, and the last scan rated this endpoint high risk, "
               "so it is ranked higher.")
    elif "rule_hit_or_blocked_action" in names or "http_error_rate" in names:
        why = f"{compared}, this looks like probing or guessing rather than normal use."
    else:
        why = f"{compared}, this is out of the ordinary."
    why += " It is a signal to investigate, not proof of an attack."
    marker = (f"{MARKER_PREFIX} priority {float(alert['priority_score']):.2f} from anomaly "
              f"{float(alert['anomaly_score']):.2f}, endpoint risk "
              f"{'n/a' if risk is None else f'{float(risk):.2f}'}, repeats x{float(alert['repeat_factor']):.1f}.)")
    return f"{what} {why} {marker}"


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


# ---- timeline ---------------------------------------------------------------------------

def timeline_add(buckets: dict[int, int], ts: str) -> None:
    """Count one observation in its 15 s bucket; keeps only the newest buckets."""
    epoch = int(parse_ts(ts).timestamp())
    start = epoch - epoch % TIMELINE_BUCKET_SECONDS
    buckets[start] = buckets.get(start, 0) + 1
    for old in sorted(buckets)[:-TIMELINE_BUCKETS]:
        del buckets[old]


def timeline_view(buckets: Mapping[int, int], last_seen: str) -> list[dict[str, Any]]:
    """TIMELINE_BUCKETS buckets ending at last_seen, zeros included, as [{ts, count}]."""
    epoch = int(parse_ts(last_seen).timestamp())
    end = epoch - epoch % TIMELINE_BUCKET_SECONDS
    starts = [end - i * TIMELINE_BUCKET_SECONDS for i in range(TIMELINE_BUCKETS - 1, -1, -1)]
    return [{"ts": datetime.fromtimestamp(s, timezone.utc).isoformat().replace("+00:00", "Z"),
             "count": int(buckets.get(s, 0))} for s in starts]


# ---- helpers -----------------------------------------------------------------------------

def parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _fmt(value: float | None, digits: int = 0) -> str:
    if value is None:
        return "n/a"
    if digits == 0 and abs(value) < 10 and value != int(value):
        return f"{value:.1f}"
    return f"{value:.{digits}f}"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{round(100 * value)}%"

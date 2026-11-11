import json
from datetime import datetime, timezone

from .risk import api_risk, endpoint_risk, risk_band, score_all


def build_report(findings: list, target: str) -> dict:
    findings = score_all(findings)
    ep_risk = endpoint_risk(findings)
    findings_sorted = sorted(findings, key=lambda f: f.risk_score, reverse=True)
    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "api_risk_score": api_risk(ep_risk),
        "endpoint_risk": ep_risk,
        "findings": [
            {**f.to_dict(), "risk_band": risk_band(f.risk_score)}
            for f in findings_sorted
        ],
    }


def write_json_report(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
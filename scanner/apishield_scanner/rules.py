import json

import yaml

# Maps a scanner action to one the gateway's RulesStage actually understands.
# Anything not listed downgrades to "log" (visible, but not blocking).
ACTION_MAP = {
    "require_auth": "challenge",
    "require_valid_jwt": "challenge",
    "rate_limit": "throttle",
    "block": "block",
}


def _adapt_rule(raw: dict) -> dict:
    """Convert a scanner-format suggested_rule into the gateway's Rule schema."""
    action = ACTION_MAP.get(raw.get("action"), "log")
    match = dict(raw.get("match", {}))

    # injection rules: use the gateway's built-in sqli signature instead of a custom pattern
    if raw.get("pattern") == "sql_injection":
        match["signature"] = "sqli"

    rule = {
        "id": raw["id"],
        "name": raw["id"].replace("-", " "),
        "match": match,
        "action": action,
        "source": "scanner",
        "enabled": True,
        "priority": 100,
    }
    if action == "throttle":
        rule["throttle"] = {"limit": 5, "per": 60}
    return rule


def export_rules(findings: list) -> list[dict]:
    """One adapted rule per fixable finding, deduplicated by rule id."""
    seen = {}
    for f in findings:
        if f.suggested_rule:
            adapted = _adapt_rule(f.suggested_rule)
            seen[adapted["id"]] = adapted
    return list(seen.values())


def write_rules_yaml(rules: list[dict], path: str) -> None:
    # Match the file shape RuleSet._scan loads: a list under a "rules" key
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump({"rules": rules}, f, sort_keys=False)


def write_endpoint_risk(endpoint_risk: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(endpoint_risk, f, indent=2)
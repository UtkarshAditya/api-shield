import argparse
import sys

from .checks.headers_cors import check_headers_cors
from .checks.idor import check_idor
from .checks.injection import check_injection
from .checks.jwt_flaws import check_jwt_flaws
from .checks.missing_auth import check_missing_auth
from .checks.rate_limit import check_rate_limit
from .checks.secrets_errors import check_secrets_errors
from .client import ApiClient, login
from .report import build_report, write_json_report
from .report_html import write_html_report
from .rules import export_rules, write_endpoint_risk, write_rules_yaml
from .spec import load_spec, parse_endpoints

ALLOWED_HOSTS = ("localhost", "127.0.0.1")


def run_scan(spec_path: str, target: str, username: str, password: str, out_prefix: str) -> dict:
    endpoints = parse_endpoints(load_spec(spec_path))
    client = ApiClient(target)
    token = login(client, "/login", username, password)

    findings = []
    findings += check_missing_auth(client, endpoints)
    findings += check_jwt_flaws(client, endpoints)
    findings += check_idor(client, endpoints, token=token, own_id=1)
    findings += check_injection(client, endpoints)
    findings += check_rate_limit(client, endpoints)
    findings += check_headers_cors(client, endpoints)
    findings += check_secrets_errors(client, endpoints, token=token)

    report = build_report(findings, target=target)
    write_json_report(report, f"{out_prefix}_report.json")
    write_html_report(report, f"{out_prefix}_report.html")
    write_rules_yaml(export_rules(findings), f"{out_prefix}_rules.yaml")
    write_endpoint_risk(report["endpoint_risk"], f"{out_prefix}_endpoint_risk.json")
    return report


def main():
    parser = argparse.ArgumentParser(description="APIShield scanner")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="alice123")
    parser.add_argument("--out", default="apishield")
    parser.add_argument("--i-own-this", action="store_true")
    args = parser.parse_args()

    host = args.target.split("//")[-1].split(":")[0].split("/")[0]
    if not args.i_own_this:
        print("Refusing to scan without --i-own-this (consent flag required).")
        sys.exit(1)
    if host not in ALLOWED_HOSTS:
        print(f"Refusing to scan '{host}': only localhost targets are allowed.")
        sys.exit(1)

    report = run_scan(args.spec, args.target, args.username, args.password, args.out)
    print(f"API risk score: {report['api_risk_score']}")
    print(f"Findings: {len(report['findings'])}")
    for f in report["findings"]:
        print(f"  [{f['risk_band'].upper()}] {f['title']} ({f['endpoint']})")
    print(f"\nReports written: {args.out}_report.json, {args.out}_report.html")
    print(f"Rules written:   {args.out}_rules.yaml")


if __name__ == "__main__":
    main()
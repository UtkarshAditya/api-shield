"""Scan runner: runs the scanner's run_scan() in a worker thread (never inside a request),
then stores a masked copy of the report and its findings mapped to the dashboard's Finding."""
from __future__ import annotations

import html
import logging
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from scanner.apishield_scanner.cli import ALLOWED_HOSTS
from scanner.apishield_scanner.report_html import render_html_report
from scanner.apishield_scanner.rules import export_rules

from .config import Config
from .db import iso, utcnow
from .errors import APIError
from .masking import DEFAULT_SENSITIVE_FIELDS, mask_text, mask_value
from .models import FindingRow, ScanRow, SettingsRow
from .rules_service import normalize, rule_view

log = logging.getLogger("apishield.admin.scans")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def check_target(target: str, cfg: Config) -> None:
    """The scanner's own policy (cli.main) is localhost only. The Admin API repeats it because
    run_scan() does not check; Compose adds its internal demo-api host explicitly."""
    host = (urlsplit(target).hostname or "").lower()
    allowed = set(ALLOWED_HOSTS) | {h.lower() for h in cfg.scan_allowed_hosts}
    if host not in allowed:
        raise APIError(422, "scan_refused",
                       f"Refusing to scan '{host or target}': only {', '.join(sorted(allowed))} can be scanned.")


def sensitive_fields(session) -> tuple:
    row = session.get(SettingsRow, 1)
    return tuple(DEFAULT_SENSITIVE_FIELDS) + tuple(row.redaction_patterns or [])


def evidence_strings(raw: dict, fields) -> dict:
    """Scanner evidence is a free-form dict per check; the dashboard shows two short lines."""
    ev = raw.get("evidence") or {}
    method, endpoint = raw.get("method", ""), raw.get("endpoint", "")
    if ev.get("request"):
        request = str(ev["request"])
    elif "payload" in ev:
        request = f"{method} {endpoint} with payload {ev['payload']}"
    elif "requests_sent" in ev:
        request = f"{method} {endpoint} ×{ev['requests_sent']}"
    else:
        request = f"{method} {endpoint}"

    parts = []
    if "status_code" in ev:
        parts.append(str(ev["status_code"]))
    if ev.get("signal"):
        parts.append(str(ev["signal"]).replace("_", " "))
    if ev.get("got_429") is False:
        parts.append("never 429")
    if ev.get("missing_headers"):
        parts.append("missing headers: " + ", ".join(map(str, ev["missing_headers"])))
    if ev.get("cors_wildcard"):
        parts.append("CORS allows any origin")
    if ev.get("secrets_found"):
        parts.append("secrets in response")
    if ev.get("verbose_error"):
        parts.append("verbose error")
    known = {"request", "payload", "requests_sent", "status_code", "signal", "got_429", "missing_headers",
             "cors_wildcard", "secrets_found", "verbose_error", "response_snippet"}
    for key, value in ev.items():
        if key not in known and isinstance(value, (bool, int, float)):
            parts.append(f"{key.replace('_', ' ')}: {value}")
    if ev.get("response_snippet"):
        snippet = " ".join(str(ev["response_snippet"]).split())
        parts.append(snippet[:120] + ("…" if len(snippet) > 120 else ""))
    return {"request": mask_text(request, fields)[:300], "response": mask_text(" · ".join(parts) or "—", fields)}


def suggested_rule(raw: dict) -> dict | None:
    """The scanner's draft rule adapted by its own export_rules(), validated by the gateway's Rule."""
    if not raw.get("suggested_rule"):
        return None
    adapted = export_rules([SimpleNamespace(suggested_rule=raw["suggested_rule"])])
    try:
        return normalize(adapted[0]) if adapted else None
    except APIError as exc:
        log.warning("dropping unusable suggested rule for %s: %s", raw.get("id"), exc.message)
        return None


def map_finding(raw: dict, scan_id: str, upstream_id: str, fields) -> FindingRow:
    severity = raw.get("risk_band") if raw.get("risk_band") in SEVERITIES else "info"
    return FindingRow(
        id="fd_" + uuid.uuid4().hex[:12], scan_id=scan_id, upstream_id=upstream_id,
        scanner_id=str(raw.get("id", "")), endpoint=str(raw.get("endpoint", "")),
        method=str(raw.get("method", "")).upper(), owasp_cat=str(raw.get("owasp_cat", "")),
        title=mask_text(str(raw.get("title", "")), fields), severity=severity,
        risk_score=max(0.0, min(10.0, float(raw.get("risk_score") or 0))),
        evidence=evidence_strings(raw, fields), fix=mask_text(str(raw.get("fix", "")), fields),
        suggested_rule=suggested_rule(raw), status="open",
    )


def finding_view(row: FindingRow) -> dict:
    out = {"id": row.id, "scan_id": row.scan_id, "endpoint": row.endpoint, "method": row.method,
           "owasp_cat": row.owasp_cat, "title": row.title, "severity": row.severity,
           "risk_score": row.risk_score, "evidence": row.evidence, "fix": row.fix, "status": row.status}
    if row.suggested_rule:
        out["suggested_rule"] = rule_view(row.suggested_rule, 0)
    return out


def scan_view(row: ScanRow) -> dict:
    out = {"id": row.id, "upstream_id": row.upstream_id, "status": row.status, "progress": row.progress,
           "started_at": iso(row.started_at), "counts": {s: (row.counts or {}).get(s, 0) for s in SEVERITIES}}
    if row.finished_at:
        out["finished_at"] = iso(row.finished_at)
    if row.api_risk_score is not None:
        out["api_risk_score"] = row.api_risk_score
    if row.error:
        out["error"] = row.error
    return out


def report_html(report: dict) -> str:
    """The scanner's template does not autoescape, so escape every string first."""
    def esc(value):
        if isinstance(value, str):
            return html.escape(value)
        if isinstance(value, dict):
            return {k: esc(v) for k, v in value.items()}
        if isinstance(value, list):
            return [esc(v) for v in value]
        return value
    return render_html_report(esc(report))


class ScanRunner:
    def __init__(self, cfg: Config, session_factory, scan_fn=None):
        self.cfg = cfg
        self.session_factory = session_factory
        self.scan_fn = scan_fn
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="admin-scan")
        self.futures: dict = {}

    def submit(self, scan_id: str, target: str, spec_path: str, spec_text: str | None = None):
        future = self.executor.submit(self._run, scan_id, target, spec_path, spec_text)
        self.futures[scan_id] = future
        return future

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)

    def _set(self, scan_id: str, **fields) -> None:
        with self.session_factory() as session:
            row = session.get(ScanRow, scan_id)
            for key, value in fields.items():
                setattr(row, key, value)
            session.commit()

    def _run(self, scan_id: str, target: str, spec_path: str, spec_text: str | None) -> None:
        self._set(scan_id, status="running", progress=0.1)
        try:
            scan_fn = self.scan_fn
            if scan_fn is None:
                from scanner.apishield_scanner.cli import run_scan as scan_fn
            with tempfile.TemporaryDirectory(prefix="apishield-scan-") as tmp:
                if spec_text is not None:
                    suffix = ".json" if spec_text.lstrip().startswith("{") else ".yaml"
                    spec_path = str(Path(tmp) / f"spec{suffix}")
                    Path(spec_path).write_text(spec_text, encoding="utf-8")
                # run_scan writes report files next to out_prefix; they are deleted with tmp.
                report = scan_fn(spec_path, target, self.cfg.scan_username, self.cfg.scan_password,
                                 str(Path(tmp) / "scan"))
            self._store(scan_id, report)
        except Exception as exc:
            log.warning("scan %s failed: %s", scan_id, type(exc).__name__)
            message = mask_text(f"{type(exc).__name__}: {exc}")[:300]
            self._set(scan_id, status="failed", progress=1.0, finished_at=utcnow(), error=message)

    def _store(self, scan_id: str, report: dict) -> None:
        with self.session_factory() as session:
            scan = session.get(ScanRow, scan_id)
            fields = sensitive_fields(session)
            findings = [map_finding(f, scan_id, scan.upstream_id, fields) for f in report.get("findings", [])]
            session.add_all(findings)
            counts = {s: 0 for s in SEVERITIES}
            for f in findings:
                counts[f.severity] += 1
            scan.counts = counts
            scan.api_risk_score = max(0.0, min(10.0, float(report.get("api_risk_score") or 0)))
            scan.endpoint_risk = {str(k): float(v) for k, v in (report.get("endpoint_risk") or {}).items()}
            scan.report = mask_value(report, fields)
            scan.status, scan.progress, scan.finished_at = "done", 1.0, utcnow()
            session.commit()

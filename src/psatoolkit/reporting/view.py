"""Format-independent report view built from the canonical JSON report document.

HTML, PDF and CSV are all rendered from the same ``report.json`` document, so
every format states exactly the same facts and any format can be regenerated
later from a verified JSON report.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
PRIORITIES = ["immediate", "short-term", "planned", "monitoring"]
PRIORITY_TITLES = {
    "immediate": "Immediate action",
    "short-term": "Short-term action",
    "planned": "Planned improvements",
    "monitoring": "Ongoing monitoring",
}
PRIORITY_HELP = {
    "immediate": "Critical issues and urgent, confirmed exposure. Address now, or isolate the system.",
    "short-term": "High-priority weaknesses. Validate and remediate within the next maintenance cycle.",
    "planned": "Medium- and low-priority findings. Schedule into regular change windows.",
    "monitoring": "Informational observations and recurring checks to keep the posture from drifting.",
}
RECURRING_ACTIVITIES = [
    "Re-run this assessment after remediation and at least monthly.",
    "Refresh the offline vulnerability snapshot before every engagement.",
    "Review local administrator and sudo group membership quarterly.",
    "Confirm patching, antivirus and backup monitoring alerts are reviewed daily.",
    "Forward security logs to central monitoring and review high-severity events.",
]
STATUS_LABELS = {"confirmed": "Confirmed", "potential": "Potential", "informational": "Informational",
                 "inconclusive": "Inconclusive"}
CHECK_STATUS_LABELS = {"passed": "Passed", "findings": "Findings", "skipped": "Skipped",
                       "not_applicable": "Not applicable", "error": "Error", "timeout": "Timed out",
                       "cancelled": "Cancelled"}


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def fmt_time(value: str | None) -> str:
    dt = parse_time(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "-"


def duration_text(start: str | None, end: str | None) -> str:
    a, b = parse_time(start), parse_time(end)
    if not a or not b:
        return "-"
    seconds = int((b - a).total_seconds())
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    return f"{minutes}m {sec}s" if minutes else f"{sec}s"


def reference_text(ref: dict[str, Any]) -> str:
    text = str(ref.get("identifier", ""))
    if ref.get("cvss_score") is not None:
        text += f" (CVSS v{ref.get('cvss_version')} {ref['cvss_score']}"
        text += f", {ref['source']})" if ref.get("source") else ")"
    elif ref.get("source") and ref.get("kind") != "URL":
        text += f" ({ref['source']})"
    return text


def evidence_text(evidence: dict[str, Any], limit: int = 4000) -> str:
    data = evidence.get("data")
    if data is None:
        body = ""
    elif isinstance(data, str):
        body = data
    else:
        body = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)
    if len(body) > limit:
        body = body[:limit] + f"\n... ({len(body) - limit} more characters in report.json)"
    return body


def evidence_summary(finding: dict[str, Any], limit: int = 300) -> str:
    parts = []
    for ev in finding.get("evidence") or []:
        text = f"{ev.get('description', '')} [{ev.get('source', '')}]"
        data = ev.get("data")
        if isinstance(data, (dict, list)):
            text += " " + json.dumps(data, ensure_ascii=False)[:limit]
        elif isinstance(data, str):
            text += " " + data[:limit]
        parts.append(text)
    return " | ".join(parts)[: limit * 2]


class ReportView:
    """Derived, read-only view over a report document."""

    def __init__(self, doc: dict[str, Any]) -> None:
        self.doc = doc
        self.a = doc["assessment"]
        self.host = self.a["host"]
        self.findings: list[dict[str, Any]] = doc.get("findings", [])
        self.checks: list[dict[str, Any]] = doc.get("checks", [])
        self.posture: dict[str, Any] = self.a.get("posture") or {}
        self.auth: dict[str, Any] = self.a.get("authorization") or {}

    # -- identification ------------------------------------------------------
    @property
    def is_demo(self) -> bool:
        return self.a.get("mode") == "demo"

    @property
    def title(self) -> str:
        return f"Security Assessment Report - {self.host.get('hostname')}"

    @property
    def counts(self) -> dict[str, int]:
        counts = self.a.get("severity_counts") or {}
        return {s: int(counts.get(s, 0)) for s in SEVERITIES}

    @property
    def total_findings(self) -> int:
        return sum(self.counts.values())

    def identification(self) -> list[tuple[str, str]]:
        h = self.host
        return [
            ("Hostname", str(h.get("hostname"))),
            ("Operating system", f"{h.get('os_name')} (version {h.get('os_version')}, build {h.get('os_build')})"),
            ("Architecture", str(h.get("architecture"))),
            ("Role", "Server" if h.get("is_server") else "Workstation"),
            ("Privileges during assessment", "Administrator/root" if h.get("elevated") else "Standard user"),
            ("Assessment ID", str(self.a.get("assessment_id"))),
            ("Assessment mode", "DEMONSTRATION (sample data)" if self.is_demo else "Live, read-only"),
            ("Started", fmt_time(self.a.get("started_at"))),
            ("Completed", fmt_time(self.a.get("finished_at"))),
            ("Duration", duration_text(self.a.get("started_at"), self.a.get("finished_at"))),
            ("Status", str(self.a.get("status", "")).capitalize()),
            ("Tool version", f"{self.doc.get('tool', {}).get('name')} {self.doc.get('tool', {}).get('version')}"),
        ]

    def scope(self) -> list[tuple[str, str]]:
        a = self.auth
        rows = [
            ("Authorized by (operator)", str(a.get("operator", "-"))),
            ("Organization", str(a.get("organization") or "-")),
            ("Authorization reference", str(a.get("engagement_reference", "-"))),
            ("Scope statement", str(a.get("scope_statement", "-"))),
            ("Confirmed at", fmt_time(a.get("confirmed_at"))),
            ("Modules", ", ".join(self.a.get("selected_modules") or [])),
        ]
        targets = a.get("remote_scope") or []
        rows.append(("Remote targets", ", ".join(f"{t['target']} (ref {t['permission_reference']})"
                                                  for t in targets) or "None (local host only)"))
        return rows

    # -- summary -------------------------------------------------------------
    def top_risks(self, n: int = 5) -> list[dict[str, Any]]:
        ranked = sorted((f for f in self.findings if (f.get("risk_score") or 0) > 0),
                        key=lambda f: (f.get("risk_score") or 0, SEVERITIES[::-1].index(f["severity"])), reverse=True)
        return ranked[:n]

    def key_recommendations(self, n: int = 6) -> list[dict[str, Any]]:
        """Distinct remediation actions for immediate/short-term work, most urgent first."""
        out: list[dict[str, Any]] = []
        for prio in ("immediate", "short-term", "planned"):
            for f in sorted(self.by_priority().get(prio, []), key=lambda x: -(x.get("risk_score") or 0)):
                text = f.get("remediation", "")
                existing = next((r for r in out if r["text"] == text), None)
                if existing:
                    existing["findings"].append(f["finding_id"])
                    continue
                out.append({"text": text, "priority": prio, "findings": [f["finding_id"]], "title": f["title"]})
                if len(out) >= n:
                    return out
        return out

    def by_priority(self) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = {p: [] for p in PRIORITIES}
        for f in self.findings:
            groups.setdefault(f.get("priority") or "monitoring", []).append(f)
        return groups

    def checks_by_status(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c in self.checks:
            out[c["status"]] = out.get(c["status"], 0) + 1
        return out

    def limitations_by_category(self) -> dict[str, list[dict[str, Any]]]:
        groups: dict[str, list[dict[str, Any]]] = {}
        for lim in self.a.get("limitations") or []:
            groups.setdefault(lim.get("category", "other"), []).append(lim)
        return groups

    @property
    def data_sources(self) -> list[dict[str, Any]]:
        return self.a.get("data_sources") or []

    @property
    def integrity(self) -> dict[str, Any]:
        return {
            "assessment_id": self.a.get("assessment_id"),
            "tool_version": self.doc.get("tool", {}).get("version"),
            "generated_at": self.doc.get("generated_at"),
            "canonical_sha256": (self.doc.get("integrity") or {}).get("canonical_sha256"),
        }

"""CSV export for findings and remediation tracking.

Spreadsheet formula injection is neutralised: any cell starting with
``= + - @``, a tab or a carriage return is prefixed with an apostrophe, so
evidence from the assessed system can never execute as a formula.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from psatoolkit.reporting.view import ReportView, evidence_summary, reference_text

COLUMNS = ["finding_id", "fingerprint", "severity", "risk_score", "priority", "status", "confidence", "title",
           "affected_host", "affected_component", "description", "impact", "evidence_summary", "references",
           "remediation", "verification", "manual_validation_required", "severity_rationale", "check_id",
           "assessment_id",
           # Remediation tracking (left empty for the IT team to fill in)
           "owner", "due_date", "ticket", "remediation_state"]
_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith(_DANGEROUS):
        text = "'" + text
    return text


def render(doc: dict[str, Any]) -> str:
    v = ReportView(doc)
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for f in v.findings:
        row = {
            **{k: f.get(k) for k in COLUMNS},
            "evidence_summary": evidence_summary(f),
            "references": "; ".join(reference_text(r) for r in f.get("references") or []),
            "manual_validation_required": "yes" if f.get("manual_validation_required") else "no",
            "assessment_id": v.a.get("assessment_id"),
            "owner": "", "due_date": "", "ticket": "", "remediation_state": "open",
        }
        writer.writerow([safe_cell(row[c]) for c in COLUMNS])
    return buf.getvalue()


def write_csv_report(doc: dict[str, Any], folder: Path) -> Path:
    path = folder / "findings.csv"
    # UTF-8 with BOM so Excel detects the encoding.
    path.write_text("﻿" + render(doc), encoding="utf-8", newline="")
    return path

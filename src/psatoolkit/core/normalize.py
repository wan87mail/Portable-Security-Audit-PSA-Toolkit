"""Finding normalization: consistency rules, de-duplication, fingerprints and scoring.

Applied once to every completed assessment (live and demo) before reporting.
Every adjustment is recorded in the finding's severity rationale or the
result's limitations, so normalization never changes a result silently.
"""

from __future__ import annotations

import hashlib
import re

from psatoolkit.core.models import (AssessmentResult, Finding, FindingStatus, Limitation, ReferenceKind,
                                    Severity)
from psatoolkit.core.redaction import redact
from psatoolkit.core.scoring import assess_posture, remediation_priority, risk_score

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE = re.compile(r"^CWE-\d+$")


def fingerprint(f: Finding) -> str:
    """Stable ID for tracking the same issue across assessments (independent of wording changes in counts)."""
    title = re.sub(r"\d+", "#", f.title.lower())
    key = "|".join((f.check_id, f.affected_host.lower(), f.affected_component.lower(), title))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def normalize_finding(f: Finding) -> list[str]:
    """Apply consistency rules in place; return notes describing any adjustment."""
    notes = []
    if f.status == FindingStatus.INFORMATIONAL and f.severity != Severity.INFO:
        notes.append(f"status 'informational' implies severity Informational (was {f.severity.value})")
        f.severity = Severity.INFO
    if f.severity == Severity.INFO and f.status not in (FindingStatus.INFORMATIONAL,):
        notes.append(f"severity Informational implies status 'informational' (was {f.status.value})")
        f.status = FindingStatus.INFORMATIONAL
    if f.status in (FindingStatus.POTENTIAL, FindingStatus.INCONCLUSIVE) and not f.manual_validation_required:
        f.manual_validation_required = True
    valid_refs = []
    for r in f.references:
        if r.kind == ReferenceKind.CVE and not _CVE.match(r.identifier):
            notes.append(f"dropped malformed CVE reference {r.identifier!r}")
            continue
        if r.kind == ReferenceKind.CWE and not _CWE.match(r.identifier):
            notes.append(f"dropped malformed CWE reference {r.identifier!r}")
            continue
        if r.cvss_score is not None and (not r.cvss_version or not (0.0 <= r.cvss_score <= 10.0)):
            notes.append(f"removed CVSS score without a valid version/range from {r.identifier}")
            r.cvss_score = None
        valid_refs.append(r)
    f.references = valid_refs
    f.title = redact(f.title)
    f.description = redact(f.description)
    if notes:
        f.severity_rationale = f.severity_rationale + " [Normalized: " + "; ".join(notes) + "]"
    return notes


def finalize(result: AssessmentResult) -> AssessmentResult:
    """Normalize, de-duplicate, fingerprint, score and rate an assessment in place."""
    seen: dict[str, Finding] = {}
    duplicates = 0
    for check in result.checks:
        kept = []
        for f in check.findings:
            normalize_finding(f)
            f.fingerprint = fingerprint(f)
            if f.fingerprint in seen:
                duplicates += 1
                original = seen[f.fingerprint]
                original.evidence.extend(f.evidence)
                continue
            seen[f.fingerprint] = f
            f.risk_score = risk_score(f)
            f.priority = remediation_priority(f)
            kept.append(f)
        check.findings = kept
    if duplicates:
        result.limitations.append(Limitation("normalization", f"{duplicates} duplicate finding(s) were merged "
                                             "into the first occurrence (evidence kept)."))
    result.posture = assess_posture(result)
    return result

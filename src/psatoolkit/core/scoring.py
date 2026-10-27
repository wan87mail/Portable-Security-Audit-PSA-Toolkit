"""Risk scoring, remediation priority and overall security posture.

Severity (Critical..Informational) is decided by each check, using CVSS for
vulnerability findings. The *risk score* is a 0-10 ranking value that also
weighs how certain a finding is:

    risk_score = severity weight x status factor x confidence factor

so a confirmed High outranks a potential High with low confidence. The
score is for ordering work only; it is not a CVSS score and is never
presented as one.
"""

from __future__ import annotations

from typing import Any

from psatoolkit.core.models import (AssessmentResult, CheckStatus, Confidence, Finding, FindingStatus, Severity)

SEVERITY_WEIGHT = {Severity.CRITICAL: 10.0, Severity.HIGH: 7.5, Severity.MEDIUM: 5.0, Severity.LOW: 2.5,
                   Severity.INFO: 0.0}
STATUS_FACTOR = {FindingStatus.CONFIRMED: 1.0, FindingStatus.POTENTIAL: 0.8, FindingStatus.INCONCLUSIVE: 0.5,
                 FindingStatus.INFORMATIONAL: 0.0}
CONFIDENCE_FACTOR = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.85, Confidence.LOW: 0.65}

IMMEDIATE, SHORT_TERM, PLANNED, MONITORING = "immediate", "short-term", "planned", "monitoring"
PRIORITY_LABELS = {
    IMMEDIATE: "Immediate action: critical issues and urgent exposure",
    SHORT_TERM: "Short-term action: high-priority weaknesses",
    PLANNED: "Planned improvements: medium- and low-priority findings",
    MONITORING: "Ongoing monitoring: informational items and recurring checks",
}


def risk_score(f: Finding) -> float:
    return round(SEVERITY_WEIGHT[f.severity] * STATUS_FACTOR[f.status] * CONFIDENCE_FACTOR[f.confidence], 1)


def remediation_priority(f: Finding) -> str:
    if f.severity == Severity.CRITICAL:
        return IMMEDIATE
    if f.severity == Severity.HIGH:
        # Directly observed high-severity issues are urgent; unverified ones are scheduled after validation.
        return IMMEDIATE if f.status == FindingStatus.CONFIRMED and f.confidence == Confidence.HIGH else SHORT_TERM
    if f.severity in (Severity.MEDIUM, Severity.LOW):
        return PLANNED
    return MONITORING


POSTURE_LEVELS = ("Critical risk", "High risk", "Elevated risk", "Moderate risk", "Low risk")


def assess_posture(result: AssessmentResult) -> dict[str, Any]:
    """Overall rating with an explanation that a reader can verify against the counts."""
    findings = result.findings
    confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]
    count = lambda sev, pool=findings: sum(1 for f in pool if f.severity == sev)  # noqa: E731
    crit, high, med = count(Severity.CRITICAL), count(Severity.HIGH), count(Severity.MEDIUM)
    if count(Severity.CRITICAL, confirmed):
        level, why = 0, f"{count(Severity.CRITICAL, confirmed)} confirmed critical finding(s)"
    elif crit or count(Severity.HIGH, confirmed) >= 3:
        level, why = 1, (f"{crit} potential critical finding(s)" if crit
                         else f"{count(Severity.HIGH, confirmed)} confirmed high-severity findings")
    elif high:
        level, why = 2, f"{high} high-severity finding(s)"
    elif med:
        level, why = 3, f"{med} medium-severity finding(s) and no high or critical findings"
    else:
        level, why = 4, "no critical, high or medium findings"

    applicable = [c for c in result.checks if c.status != CheckStatus.NOT_APPLICABLE]
    completed = [c for c in applicable if c.status in (CheckStatus.PASSED, CheckStatus.FINDINGS)]
    coverage = round(100 * len(completed) / len(applicable)) if applicable else 0
    caveat = ""
    if coverage < 75:
        caveat = (f"Only {coverage}% of applicable checks completed (see Limitations); the real posture may be "
                  "worse than shown.")
    priorities = {p: sum(1 for f in findings if f.priority == p) for p in PRIORITY_LABELS}
    return {
        "rating": POSTURE_LEVELS[level],
        "level": level,
        "reason": why,
        "coverage_percent": coverage,
        "checks_completed": len(completed),
        "checks_applicable": len(applicable),
        "caveat": caveat,
        "top_risks": [{"finding_id": f.finding_id, "title": f.title, "severity": f.severity.value,
                       "risk_score": f.risk_score} for f in sorted(findings, key=lambda x: x.risk_score or 0,
                                                                 reverse=True)[:5] if (f.risk_score or 0) > 0],
        "remediation_counts": priorities,
        "method": "Rating is driven by the most severe confirmed findings; coverage below 75% is flagged.",
    }

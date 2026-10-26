"""Structured data models for assessment results.

All models are plain dataclasses so they serialise deterministically to JSON
(see :func:`to_jsonable`) and can be rebuilt from JSON in tests.
"""

from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @property
    def rank(self) -> int:
        """Higher is more severe; used for sorting."""
        return _SEVERITY_RANK[self]

    @classmethod
    def ordered(cls) -> list["Severity"]:
        return sorted(cls, key=lambda s: s.rank, reverse=True)


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingStatus(str, enum.Enum):
    """How certain the toolkit is that the issue actually exists."""

    CONFIRMED = "confirmed"          # directly observed configuration/state
    POTENTIAL = "potential"          # indirect evidence, e.g. version string only
    INFORMATIONAL = "informational"  # observation, not a weakness by itself
    INCONCLUSIVE = "inconclusive"    # check ran but evidence was insufficient


class Confidence(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CheckStatus(str, enum.Enum):
    PASSED = "passed"                # ran, nothing found
    FINDINGS = "findings"            # ran, produced findings
    SKIPPED = "skipped"              # prerequisites missing (privilege, tool, scope)
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ReferenceKind(str, enum.Enum):
    CVE = "CVE"
    CWE = "CWE"
    BASELINE = "BASELINE"
    URL = "URL"


@dataclass
class Reference:
    kind: ReferenceKind
    identifier: str
    source: str = ""                # e.g. "NVD", "CIS Ubuntu 24.04 v1.0.0 5.1.20"
    cvss_score: float | None = None
    cvss_version: str | None = None  # "3.1", "4.0"
    cvss_vector: str | None = None


@dataclass
class Evidence:
    description: str
    source: str                      # command line or API used, e.g. "sshd -T"
    data: Any = None                 # redacted raw observation
    collected_at: datetime = field(default_factory=utcnow)


@dataclass
class Finding:
    title: str
    severity: Severity
    status: FindingStatus
    affected_host: str
    affected_component: str
    description: str
    impact: str
    confidence: Confidence
    remediation: str
    verification: str
    severity_rationale: str
    evidence: list[Evidence] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    manual_validation_required: bool = False
    check_id: str = ""
    finding_id: str = ""             # assigned by the engine: "<check_id>-<n>"
    # Set by normalization/scoring (core/normalize.py, core/scoring.py):
    fingerprint: str = ""            # stable across runs for the same issue on the same host
    risk_score: float | None = None  # 0-10 ranking score; see scoring.risk_score()
    priority: str = ""               # remediation roadmap bucket


@dataclass
class CheckResult:
    check_id: str
    module_id: str
    title: str
    status: CheckStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    message: str = ""
    requires_admin: bool = False
    findings: list[Finding] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


@dataclass
class HostInfo:
    hostname: str
    os_family: str
    os_name: str
    os_version: str
    os_build: str
    architecture: str
    is_server: bool
    elevated: bool
    support_level: str


@dataclass
class Limitation:
    category: str          # "privilege", "dependency", "timeout", "error", "scope", "platform"
    description: str
    check_id: str = ""


@dataclass
class AssessmentResult:
    assessment_id: str
    tool_version: str
    mode: str                              # "live" or "demo"
    host: HostInfo
    authorization: dict[str, Any]
    selected_modules: list[str]
    started_at: datetime
    finished_at: datetime | None = None
    status: str = "running"                # running, completed, stopped, failed
    checks: list[CheckResult] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)
    posture: dict[str, Any] = field(default_factory=dict)       # overall rating, set by scoring
    data_sources: list[dict[str, Any]] = field(default_factory=list)  # e.g. vulnerability data snapshot

    @property
    def findings(self) -> list[Finding]:
        out = [f for c in self.checks for f in c.findings]
        return sorted(out, key=lambda f: (f.severity.rank, f.risk_score or 0.0), reverse=True)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity.ordered()}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


def to_jsonable(obj: Any) -> Any:
    """Convert models (recursively) into JSON-compatible primitives."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out = {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
        if isinstance(obj, CheckResult):
            out["duration_seconds"] = obj.duration_seconds
        if isinstance(obj, AssessmentResult):
            out["severity_counts"] = obj.severity_counts()
        return out
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, datetime):
        return iso(obj)
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in obj]
    return obj

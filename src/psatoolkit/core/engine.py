"""Assessment engine: module registry, gating, isolation, timeouts, stop.

The engine is the only component that executes checks. For every check it
decides whether it may run (OS, privileges, tools, scope, offline mode, demo
mode), runs it in a worker thread with a timeout, converts any exception into
an ``error`` result, and records every skip as a report limitation.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from psatoolkit import __version__
from psatoolkit.core.authorization import AuthorizationError, AuthorizationRecord, TargetScope
from psatoolkit.core.config import AppConfig
from psatoolkit.core.hostfs import HostFS
from psatoolkit.core.logging_setup import AuditLog
from psatoolkit.core.models import (AssessmentResult, CheckResult, CheckStatus, Confidence, Evidence,
                                    Finding, FindingStatus, HostInfo, Limitation, Severity, utcnow)
from psatoolkit.core.osdetect import OSInfo
from psatoolkit.core.privileges import elevation_help
from psatoolkit.core.redaction import redact
from psatoolkit.core.safe_exec import CommandRunner
from psatoolkit.core.stop import StopRequested, StopToken
from psatoolkit.core.tempfiles import SecureTempDir

log = logging.getLogger(__name__)

ProgressCallback = Callable[[dict[str, Any]], None]


class SkipCheck(Exception):
    """Raised by a check that discovers at run time it cannot assess reliably."""

    def __init__(self, reason: str, category: str = "dependency") -> None:
        super().__init__(reason)
        self.reason = reason
        self.category = category


# --------------------------------------------------------------------------
# Check and module contracts
# --------------------------------------------------------------------------

class Check:
    check_id: str = ""
    title: str = ""
    description: str = ""
    supported_os: frozenset[str] = frozenset({"windows", "linux"})
    requires_admin: bool = False
    admin_reason: str = ""
    required_tools: tuple[str, ...] = ()
    requires_network: bool = False      # sends traffic to remote targets -> needs scope
    requires_internet: bool = False     # contacts external services -> blocked offline
    demo_safe: bool = False             # may run in demo mode (synthetic data only)
    timeout_seconds: float | None = None

    def run(self, ctx: "AssessmentContext") -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<Check {self.check_id}>"


@dataclass
class Module:
    module_id: str
    name: str
    description: str
    category: str                       # "local", "network", "baseline", "demo"
    checks: list[Check] = field(default_factory=list)

    @property
    def supported_os(self) -> frozenset[str]:
        out: frozenset[str] = frozenset()
        for c in self.checks:
            out |= c.supported_os
        return out

    def applicable_to(self, os_family: str) -> bool:
        return os_family in self.supported_os


@dataclass
class AssessmentContext:
    host: HostInfo
    os_info: OSInfo
    config: AppConfig
    runner: CommandRunner
    stop: StopToken
    audit: AuditLog
    scope: TargetScope
    demo: bool
    temp_dir: Path | None = None
    fs: HostFS = field(default_factory=HostFS)
    notes: list[str] = field(default_factory=list)
    partial: list[Limitation] = field(default_factory=list)

    def note(self, text: str) -> None:
        """Record what a check verified; shown as the check message (e.g. for passed checks)."""
        self.notes.append(text)

    def limitation(self, description: str, category: str = "dependency") -> None:
        """Record reduced coverage without skipping the whole check."""
        self.partial.append(Limitation(category, description))

    def evidence(self, description: str, source: str, data: Any = None) -> Evidence:
        return Evidence(description=description, source=source, data=redact(data))

    def finding(self, check: Check, *, title: str, severity: Severity, status: FindingStatus,
                component: str, description: str, impact: str, confidence: Confidence,
                remediation: str, verification: str, severity_rationale: str,
                evidence: Iterable[Evidence] = (), references: Iterable = (),
                manual_validation_required: bool = False, host: str | None = None) -> Finding:
        """Helper so checks cannot forget mandatory finding fields."""
        return Finding(
            title=title, severity=severity, status=status,
            affected_host=host or self.host.hostname, affected_component=component,
            description=description, impact=impact, confidence=confidence,
            remediation=remediation, verification=verification,
            severity_rationale=severity_rationale, evidence=list(evidence),
            references=list(references), manual_validation_required=manual_validation_required,
            check_id=check.check_id,
        )


@dataclass
class PlannedCheck:
    module_id: str
    check: Check
    runnable: bool
    skip_status: CheckStatus | None = None
    skip_reason: str = ""
    skip_category: str = ""


def new_assessment_id(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"PSA-{now:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6].upper()}"


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class AssessmentEngine:
    def __init__(self, modules: list[Module], config: AppConfig) -> None:
        ids = [m.module_id for m in modules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate module ids")
        check_ids = [c.check_id for m in modules for c in m.checks]
        if len(check_ids) != len(set(check_ids)) or not all(check_ids):
            raise ValueError("check ids must be unique and non-empty")
        self.modules = {m.module_id: m for m in modules}
        self.config = config

    # -- discovery -------------------------------------------------------
    def modules_for(self, os_family: str, demo: bool = False) -> list[Module]:
        if demo:
            return [m for m in self.modules.values() if m.category == "demo"]
        return [m for m in self.modules.values() if m.category != "demo" and m.applicable_to(os_family)]

    def plan(self, selected: list[str], os_info: OSInfo, elevated: bool, runner: CommandRunner,
             scope: TargetScope, demo: bool = False) -> list[PlannedCheck]:
        """Decide for each check whether it can run. Used for the run and for previews."""
        unknown = [m for m in selected if m not in self.modules]
        if unknown:
            raise ValueError(f"unknown module(s): {', '.join(unknown)}")
        planned: list[PlannedCheck] = []
        for module_id in selected:
            module = self.modules[module_id]
            if demo != (module.category == "demo"):
                raise ValueError(f"module '{module_id}' cannot be used in {'demo' if demo else 'live'} mode")
            for check in module.checks:
                planned.append(self._gate(module_id, check, os_info, elevated, runner, scope, demo))
        return planned

    def _gate(self, module_id: str, check: Check, os_info: OSInfo, elevated: bool,
              runner: CommandRunner, scope: TargetScope, demo: bool) -> PlannedCheck:
        def skip(status: CheckStatus, reason: str, category: str) -> PlannedCheck:
            return PlannedCheck(module_id, check, False, status, reason, category)

        if demo and not check.demo_safe:
            return skip(CheckStatus.SKIPPED, "Not available in demo mode.", "platform")
        if os_info.family not in check.supported_os:
            return skip(CheckStatus.NOT_APPLICABLE,
                        f"Not applicable to {os_info.family} (supports {', '.join(sorted(check.supported_os))}).",
                        "platform")
        if check.requires_admin and not elevated:
            why = check.admin_reason or "This check reads protected configuration."
            return skip(CheckStatus.SKIPPED,
                        f"Requires administrator/root privileges: {why} {elevation_help(os_info.family)}",
                        "privilege")
        if check.requires_internet and self.config.offline_mode:
            return skip(CheckStatus.SKIPPED, "Requires internet access; offline mode is enabled.", "dependency")
        if check.requires_network and not scope.targets:
            return skip(CheckStatus.SKIPPED, "No authorized remote target has been configured.", "scope")
        if not demo:
            missing = [t for t in check.required_tools if not runner.is_available(t)]
            if missing:
                return skip(CheckStatus.SKIPPED,
                            f"Required tool(s) not available: {', '.join(missing)}.", "dependency")
        return PlannedCheck(module_id, check, True)

    # -- execution -------------------------------------------------------
    def run(self, *, authorization: AuthorizationRecord | None, selected: list[str], host: HostInfo,
            os_info: OSInfo, runner: CommandRunner, audit: AuditLog, scope: TargetScope | None = None,
            stop: StopToken | None = None, demo: bool = False, temp_base: Path | None = None,
            progress: ProgressCallback | None = None, assessment_id: str | None = None,
            fs: HostFS | None = None) -> AssessmentResult:
        if authorization is None:
            raise AuthorizationError("An authorization record is required before any assessment.")
        if not selected:
            raise ValueError("No assessment modules selected.")
        stop = stop or runner.stop_token
        if runner.stop_token is not stop:
            raise ValueError("runner and engine must share the same stop token")
        scope = scope or TargetScope()
        fs = fs or HostFS()
        emit = progress or (lambda event: None)

        result = AssessmentResult(
            assessment_id=assessment_id or audit.assessment_id or new_assessment_id(),
            tool_version=__version__, mode="demo" if demo else "live", host=host,
            authorization={**authorization.to_dict(), "remote_scope": scope.to_dict()},
            selected_modules=list(selected), started_at=utcnow())
        audit.assessment_id = result.assessment_id

        planned = self.plan(selected, os_info, host.elevated, runner, scope, demo)
        audit.write("assessment_start", mode=result.mode, modules=selected,
                    authorization=result.authorization, planned_checks=len(planned),
                    elevated=host.elevated)
        emit({"type": "start", "assessment_id": result.assessment_id, "total": len(planned)})

        with SecureTempDir(base=temp_base) as tmp:
            for index, item in enumerate(planned, 1):
                if stop.stopped:
                    cr = self._result(item, CheckStatus.CANCELLED, "Assessment stopped by operator.")
                elif not item.runnable:
                    cr = self._result(item, item.skip_status or CheckStatus.SKIPPED, item.skip_reason)
                    if item.skip_status == CheckStatus.SKIPPED:
                        result.limitations.append(Limitation(item.skip_category, item.skip_reason,
                                                             item.check.check_id))
                else:
                    emit({"type": "check_start", "check_id": item.check.check_id,
                          "title": item.check.title, "index": index, "total": len(planned)})
                    ctx = AssessmentContext(host=host, os_info=os_info, config=self.config, runner=runner,
                                            stop=stop, audit=audit, scope=scope, demo=demo, temp_dir=tmp, fs=fs)
                    cr = self._execute(item, ctx, result)
                result.checks.append(cr)
                audit.write("check_end", check_id=cr.check_id, status=cr.status.value,
                            findings=len(cr.findings), message=cr.message)
                emit({"type": "check_end", "check_id": cr.check_id, "status": cr.status.value,
                      "findings": len(cr.findings), "index": index, "total": len(planned),
                      "severity_counts": result.severity_counts(), "message": cr.message})

        result.finished_at = utcnow()
        result.status = "stopped" if stop.stopped else "completed"
        if stop.stopped:
            result.limitations.append(Limitation("scope", f"Assessment stopped early: {stop.reason}"))
        audit.write("assessment_end", status=result.status, severity_counts=result.severity_counts())
        emit({"type": "end", "status": result.status, "severity_counts": result.severity_counts()})
        return result

    def _result(self, item: PlannedCheck, status: CheckStatus, message: str) -> CheckResult:
        now = utcnow()
        return CheckResult(check_id=item.check.check_id, module_id=item.module_id, title=item.check.title,
                           status=status, started_at=now, finished_at=now, message=message,
                           requires_admin=item.check.requires_admin)

    def _execute(self, item: PlannedCheck, ctx: AssessmentContext, result: AssessmentResult) -> CheckResult:
        check = item.check
        cr = CheckResult(check_id=check.check_id, module_id=item.module_id, title=check.title,
                         status=CheckStatus.ERROR, started_at=utcnow(), requires_admin=check.requires_admin)
        timeout = check.timeout_seconds or self.config.execution.check_timeout_seconds
        box: dict[str, Any] = {}

        def worker() -> None:
            try:
                box["findings"] = check.run(ctx)
            except BaseException as exc:  # noqa: BLE001 - isolate every failure
                box["error"] = exc

        thread = threading.Thread(target=worker, name=f"check-{check.check_id}", daemon=True)
        thread.start()
        deadline = time.monotonic() + timeout
        while thread.is_alive() and time.monotonic() < deadline:
            thread.join(0.1)
            if ctx.stop.stopped:
                thread.join(2.0)   # runner kills subprocesses; give the check a moment to unwind
                break
        cr.finished_at = utcnow()

        if thread.is_alive():
            if ctx.stop.stopped:
                cr.status, cr.message = CheckStatus.CANCELLED, "Stopped by operator while running."
            else:
                cr.status, cr.message = CheckStatus.TIMEOUT, f"Check exceeded its {timeout:.0f}s timeout."
                result.limitations.append(Limitation("timeout", cr.message, check.check_id))
            return cr

        for lim in ctx.partial:
            result.limitations.append(Limitation(lim.category, lim.description, check.check_id))
        error = box.get("error")
        if isinstance(error, StopRequested):
            cr.status, cr.message = CheckStatus.CANCELLED, "Stopped by operator while running."
        elif isinstance(error, SkipCheck):
            cr.status, cr.message = CheckStatus.SKIPPED, error.reason
            result.limitations.append(Limitation(error.category, error.reason, check.check_id))
        elif error is not None:
            cr.status = CheckStatus.ERROR
            cr.message = f"{type(error).__name__}: {redact(str(error))}"
            result.limitations.append(Limitation("error", f"Check failed: {cr.message}", check.check_id))
            # Traceback goes to the log file only; the operator sees the result row.
            log.info("check %s failed", check.check_id, exc_info=error)
        else:
            findings = box.get("findings") or []
            if not isinstance(findings, list) or not all(isinstance(f, Finding) for f in findings):
                cr.status, cr.message = CheckStatus.ERROR, "Check returned invalid results."
                result.limitations.append(Limitation("error", cr.message, check.check_id))
                return cr
            for n, finding in enumerate(findings, 1):
                finding.check_id = check.check_id
                finding.finding_id = f"{check.check_id}-{n:02d}"
                for ev in finding.evidence:
                    ev.data = redact(ev.data)
                    ev.description = redact(ev.description)
            cr.findings = findings
            cr.status = CheckStatus.FINDINGS if findings else CheckStatus.PASSED
            cr.message = redact("; ".join(ctx.notes))
            if ctx.stop.stopped:
                cr.message = (cr.message + "; " if cr.message else "") + "assessment was stopped afterwards."
        return cr


def build_host_info(os_info: OSInfo, hostname: str, elevated: bool) -> HostInfo:
    return HostInfo(hostname=hostname, os_family=os_info.family, os_name=os_info.name,
                    os_version=os_info.version, os_build=os_info.build, architecture=os_info.architecture,
                    is_server=os_info.is_server, elevated=elevated, support_level=os_info.support_level)

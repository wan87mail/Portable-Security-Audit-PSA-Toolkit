"""Application façade shared by the CLI and the GUI.

Wires together paths, configuration, OS detection, the module registry, the
engine, the audit log and report writing, so both interfaces behave
identically.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from psatoolkit.core.authorization import AuthorizationRecord, TargetScope
from psatoolkit.core.config import AppConfig, load_config
from psatoolkit.core.engine import AssessmentEngine, Module, ProgressCallback, build_host_info, new_assessment_id
from psatoolkit.core.integrity import IntegrityReport, verify_manifest
from psatoolkit.core.logging_setup import AuditLog
from psatoolkit.core.models import AssessmentResult, HostInfo
from psatoolkit.core.osdetect import SUPPORTED, OSInfo, detect_os, get_hostname
from psatoolkit.core.paths import AppPaths, choose_output_dir, get_paths, is_writable
from psatoolkit.core.privileges import is_elevated
from psatoolkit.core.safe_exec import CommandRunner
from psatoolkit.core.stop import StopToken
from psatoolkit.modules import load_modules
from psatoolkit.modules.demo import DEMO_HOST
from psatoolkit.reporting import write_reports
from psatoolkit.reporting.json_report import report_folder

log = logging.getLogger(__name__)

DEMO_OS = OSInfo(family="demo", name="Demonstration environment (synthetic)", version="demo",
                 build="demo", architecture="x86_64", is_server=True, support_level=SUPPORTED)


@dataclass
class SessionOutcome:
    result: AssessmentResult
    output_dir: Path
    report_folder: Path | None
    report_files: list[Path] = field(default_factory=list)
    audit_log: Path | None = None
    report_error: str = ""


@dataclass
class ReportSummary:
    folder: Path
    assessment_id: str
    hostname: str
    mode: str
    started_at: str
    status: str
    severity_counts: dict[str, int]


class Toolkit:
    def __init__(self, root: Path | None = None, config_file: Path | None = None,
                 os_info: OSInfo | None = None, elevated: bool | None = None,
                 hostname: str | None = None) -> None:
        self.paths: AppPaths = get_paths(root)
        self.config: AppConfig = load_config(self.paths.config_dir, config_file)
        self.modules: list[Module] = load_modules()
        vd = Path(self.config.vulndata.directory) if self.config.vulndata.directory else self.paths.vulndata_dir
        self.config.vulndata.directory = str(vd if vd.is_absolute() else self.paths.root / vd)
        self.engine = AssessmentEngine(self.modules, self.config)
        self.os_info = os_info or detect_os()
        self.hostname = hostname or get_hostname()
        self.elevated = is_elevated() if elevated is None else elevated
        self.scope = TargetScope(max_hosts_per_target=self.config.network.max_hosts_per_target,
                                 max_total_hosts=self.config.network.max_total_hosts)

    # -- information -----------------------------------------------------
    def host_info(self, demo: bool = False) -> HostInfo:
        if demo:
            return build_host_info(DEMO_OS, DEMO_HOST, elevated=False)
        return build_host_info(self.os_info, self.hostname, self.elevated)

    def available_modules(self, demo: bool = False) -> list[Module]:
        return self.engine.modules_for(DEMO_OS.family if demo else self.os_info.family, demo)

    def unavailable_modules(self) -> list[tuple[Module, str]]:
        """Live modules that do not apply to this OS, with the reason (for the UI)."""
        avail = {m.module_id for m in self.available_modules()}
        return [(m, f"Not supported on {self.os_info.family}") for m in self.modules
                if m.category != "demo" and m.module_id not in avail]

    def network_modules(self) -> list[Module]:
        return [m for m in self.available_modules() if m.category == "network"]

    def create_runner(self, stop: StopToken, audit: AuditLog | None = None, demo: bool = False) -> CommandRunner:
        return CommandRunner(stop_token=stop, default_timeout=self.config.execution.command_timeout_seconds,
                             max_output_bytes=self.config.execution.max_output_bytes,
                             tool_dirs=[self.paths.tools_dir(self.os_info.family)],
                             audit=audit, demo=demo)

    def resolve_output_dir(self, override: str | None = None) -> Path:
        return choose_output_dir(self.paths, self.config.output_dir, override)

    def logs_dir_for(self, output_dir: Path) -> Path:
        """Logs stay on the USB drive unless it is read-only."""
        return self.paths.logs_dir if is_writable(self.paths.logs_dir) else output_dir / "logs"

    # -- run -------------------------------------------------------------
    def run_assessment(self, authorization: AuthorizationRecord, selected: list[str], *,
                       demo: bool = False, output_override: str | None = None,
                       stop: StopToken | None = None, progress: ProgressCallback | None = None) -> SessionOutcome:
        output_dir = self.resolve_output_dir(output_override)
        stop = stop or StopToken()
        assessment_id = new_assessment_id()
        audit_path = self.logs_dir_for(output_dir) / f"audit-{assessment_id}.jsonl"
        audit = AuditLog(audit_path, assessment_id)
        runner = self.create_runner(stop, audit, demo)
        host = self.host_info(demo)
        os_info = DEMO_OS if demo else self.os_info

        result = self.engine.run(authorization=authorization, selected=selected, host=host,
                                 os_info=os_info, runner=runner, audit=audit,
                                 scope=TargetScope() if demo else self.scope, stop=stop, demo=demo,
                                 temp_base=None, progress=progress, assessment_id=assessment_id)
        outcome = SessionOutcome(result=result, output_dir=output_dir, report_folder=None, audit_log=audit_path)
        try:
            folder = report_folder(output_dir, result)
            outcome.report_folder = folder
            written = write_reports(result, folder, self.config.reporting.formats,
                                    self.config.reporting.include_raw_evidence)
            outcome.report_files.extend(written.files)
            if written.errors:
                outcome.report_error = "; ".join(written.errors)
                log.error(outcome.report_error)
            audit.write("report_written", files=[str(p) for p in outcome.report_files], errors=written.errors)
        except OSError as exc:
            outcome.report_error = f"Report could not be written: {exc}"
            audit.write("report_failed", error=str(exc))
            log.error(outcome.report_error)
        return outcome

    # -- reports & integrity ---------------------------------------------
    def list_reports(self, output_dir: Path | None = None) -> list[ReportSummary]:
        base = output_dir or self.paths.reports_dir
        out: list[ReportSummary] = []
        if not base.is_dir():
            return out
        for report in sorted(base.glob("PSA-*/report.json"), reverse=True):
            try:
                doc: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
                a = doc["assessment"]
                out.append(ReportSummary(report.parent, a["assessment_id"], a["host"]["hostname"], a["mode"],
                                         a["started_at"], a["status"], a.get("severity_counts", {})))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return out

    def verify_integrity(self) -> IntegrityReport:
        return verify_manifest(self.paths.root)

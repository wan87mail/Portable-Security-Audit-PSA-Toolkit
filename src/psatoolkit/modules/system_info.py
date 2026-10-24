"""Module A (part 1): asset identification and assessment context.

Phase 2 ships the checks that need no external commands. Phase 3 adds patch
status, services, listening ports, software inventory, AV/firewall and
encryption discovery to this module.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

from psatoolkit.core.engine import AssessmentContext, Check, Module
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Reference, ReferenceKind, Severity
from psatoolkit.core.osdetect import SUPPORTED, UNSUPPORTED


def read_uptime_seconds() -> float | None:
    """Uptime without external commands: /proc/uptime or GetTickCount64."""
    if sys.platform.startswith("linux"):
        try:
            return float(Path("/proc/uptime").read_text().split()[0])
        except (OSError, ValueError, IndexError):
            return None
    if sys.platform.startswith("win"):
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.GetTickCount64.restype = ctypes.c_ulonglong
            return kernel32.GetTickCount64() / 1000.0
        except Exception:
            return None
    return None


def format_duration(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    return f"{days}d {hours}h {rem // 60}m"


class AssetIdentificationCheck(Check):
    check_id = "SYS-ASSET-001"
    title = "Asset identification"
    description = "Records host name, OS, build, architecture, uptime and privilege context."
    supported_os = frozenset({"windows", "linux", "macos", "unknown"})

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        uptime = read_uptime_seconds()
        data = {
            "hostname": ctx.host.hostname,
            "os_name": ctx.os_info.name,
            "os_version": ctx.os_info.version,
            "build": ctx.os_info.build,
            "architecture": ctx.os_info.architecture,
            "server": ctx.os_info.is_server,
            "uptime": format_duration(uptime) if uptime is not None else "unavailable",
            "elevated": ctx.host.elevated,
            "python": platform.python_version(),
            "support_level": ctx.os_info.support_level,
        }
        return [ctx.finding(
            self,
            title="Assessed system identification",
            severity=Severity.INFO, status=FindingStatus.INFORMATIONAL,
            component="Operating system",
            description=f"{ctx.host.hostname} runs {ctx.os_info.name} (build {ctx.os_info.build}, "
                        f"{ctx.os_info.architecture}).",
            impact="None. Recorded to identify the assessed asset in the report.",
            confidence=Confidence.HIGH,
            remediation="No action required. Confirm the host matches the asset in the authorization scope.",
            verification="Compare the hostname and OS with the CMDB / asset register entry.",
            severity_rationale="Informational observation; not a weakness.",
            evidence=[ctx.evidence("Values read via Python platform APIs", "platform / socket APIs", data)],
        )]


class PlatformSupportCheck(Check):
    check_id = "SYS-ASSET-002"
    title = "Platform support and end-of-life"
    description = "Flags operating systems outside the supported/tested list."
    supported_os = frozenset({"windows", "linux", "macos", "unknown"})

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        info = ctx.os_info
        if info.support_level == SUPPORTED:
            return []
        windows_legacy = info.family == "windows" and info.support_level == UNSUPPORTED
        if windows_legacy:
            return [ctx.finding(
                self,
                title="Operating system is out of vendor support",
                severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                component=info.name,
                description=f"{info.name} (build {info.build}) no longer receives security updates "
                            "from Microsoft.",
                impact="Newly discovered vulnerabilities will remain unpatched, increasing the "
                       "likelihood of compromise.",
                confidence=Confidence.HIGH,
                remediation="Upgrade to a supported Windows release, or isolate the system and "
                            "enrol it in an Extended Security Updates programme if eligible.",
                verification="Re-run the assessment after the upgrade; this finding should disappear.",
                severity_rationale="High: an unsupported OS accumulates unpatched vulnerabilities; "
                                   "rated below Critical because exposure depends on network reachability.",
                evidence=[ctx.evidence("OS build reported by the platform API", "platform.win32_ver()",
                                       {"name": info.name, "build": info.build})],
                references=[Reference(ReferenceKind.URL,
                                      "https://learn.microsoft.com/lifecycle/products/",
                                      "Microsoft Lifecycle Policy")],
            )]
        return [ctx.finding(
            self,
            title="Platform is outside the tested support list",
            severity=Severity.INFO, status=FindingStatus.INFORMATIONAL,
            component=info.name,
            description=f"{info.name} is assessed on a {info.support_level} basis. "
                        + " ".join(info.notes),
            impact="Some checks may not apply or may return inconclusive results on this platform.",
            confidence=Confidence.HIGH,
            remediation="Confirm that the distribution/version is still supported by its vendor and "
                        "review inconclusive checks manually.",
            verification="Check the vendor's lifecycle page for this release.",
            severity_rationale="Informational: describes assessment coverage, not a weakness.",
            evidence=[ctx.evidence("Detected platform", "OS detection",
                                   {"name": info.name, "version": info.version,
                                    "distro_id": info.distro_id, "support": info.support_level})],
            manual_validation_required=True,
        )]


def build_module() -> Module:
    return Module(
        module_id="system_info",
        name="A. System information and asset discovery",
        description="Identifies the asset and assessment context (Phase 3 adds inventory checks).",
        category="local",
        checks=[AssetIdentificationCheck(), PlatformSupportCheck()],
    )

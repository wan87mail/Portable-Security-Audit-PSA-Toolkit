"""Safe demonstration module.

Generates clearly labelled *sample* findings for training, report previews and
UI testing. In demo mode the engine runs only checks marked ``demo_safe`` and
the command runner refuses to execute anything, so no real system is touched.
"""

from __future__ import annotations

from psatoolkit.core.engine import AssessmentContext, Check, Module
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Reference, ReferenceKind, Severity

DEMO_HOST = "demo-host.example.internal"
DEMO_NOTE = "[DEMO DATA - not from a real system] "


class _DemoCheck(Check):
    supported_os = frozenset({"demo"})
    demo_safe = True


class DemoSmbCheck(_DemoCheck):
    check_id = "DEMO-WIN-SMB-001"
    title = "SMBv1 protocol (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        return [ctx.finding(
            self, host=DEMO_HOST,
            title="SMBv1 server protocol is enabled",
            severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
            component="LanmanServer / SMB 1.0",
            description=DEMO_NOTE + "The SMB 1.0 server component is enabled. SMBv1 lacks modern "
                        "integrity and encryption protections and is deprecated by Microsoft.",
            impact="SMBv1 has been used by wormable malware (e.g. WannaCry via MS17-010). If a "
                   "related patch is missing, remote code execution may be possible.",
            confidence=Confidence.HIGH,
            remediation="Disable SMBv1 after confirming no legacy clients depend on it: "
                        "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
                        "(run by an administrator during a change window, not by this tool).",
            verification="Get-SmbServerConfiguration | Select EnableSMB1Protocol should return False.",
            severity_rationale="High: configuration directly observed and network-exposed; not "
                               "Critical because MS17-010 patch status is assessed separately.",
            evidence=[ctx.evidence("SMB server configuration (sample)",
                                   "Get-SmbServerConfiguration", {"EnableSMB1Protocol": True})],
            references=[
                Reference(ReferenceKind.CVE, "CVE-2017-0144", "NVD (sample reference)", 8.1, "3.1",
                          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                Reference(ReferenceKind.BASELINE, "MS-SecBaseline: Configure SMB v1 server = Disabled",
                          "Microsoft Security Baseline"),
            ],
        )]


class DemoRdpCheck(_DemoCheck):
    check_id = "DEMO-WIN-RDP-001"
    title = "Remote Desktop exposure (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        return [ctx.finding(
            self, host=DEMO_HOST,
            title="Remote Desktop allows connections without Network Level Authentication",
            severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
            component="Terminal Services (RDP-Tcp)",
            description=DEMO_NOTE + "RDP is enabled and UserAuthentication = 0, so the logon "
                        "screen is presented before the client authenticates.",
            impact="Unauthenticated users can reach the logon screen, increasing exposure to "
                   "brute-force attempts and pre-authentication vulnerabilities.",
            confidence=Confidence.HIGH,
            remediation="Require NLA via Group Policy: Computer Configuration > Administrative "
                        "Templates > Windows Components > Remote Desktop Services > Security > "
                        "'Require user authentication for remote connections by using NLA' = Enabled.",
            verification="reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
                         "WinStations\\RDP-Tcp\" /v UserAuthentication should show 0x1.",
            severity_rationale="Medium: weakens an authentication control on a remote service; "
                               "not High because RDP exposure is limited to the internal network.",
            evidence=[ctx.evidence("Registry values (sample)", "reg query ...\\RDP-Tcp",
                                   {"fDenyTSConnections": 0, "UserAuthentication": 0})],
            references=[Reference(ReferenceKind.CWE, "CWE-287", "MITRE CWE: Improper Authentication")],
        )]


class DemoSshCheck(_DemoCheck):
    check_id = "DEMO-LNX-SSH-001"
    title = "SSH root login (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        return [ctx.finding(
            self, host=DEMO_HOST,
            title="SSH permits direct root login with a password",
            severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
            component="OpenSSH server (sshd)",
            description=DEMO_NOTE + "The effective sshd configuration has PermitRootLogin yes and "
                        "PasswordAuthentication yes.",
            impact="Attackers can target the root account directly with password guessing; a "
                   "successful guess grants full control and bypasses per-user accountability.",
            confidence=Confidence.HIGH,
            remediation="Set 'PermitRootLogin no' (or 'prohibit-password') and "
                        "'PasswordAuthentication no' in /etc/ssh/sshd_config.d/, then reload sshd.",
            verification="sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'",
            severity_rationale="High: directly observed, remotely reachable, targets the most "
                               "privileged account.",
            evidence=[ctx.evidence("Effective sshd settings (sample)", "sshd -T",
                                   "permitrootlogin yes\npasswordauthentication yes")],
            references=[Reference(ReferenceKind.BASELINE, "CIS Ubuntu Linux: Ensure sshd PermitRootLogin is disabled",
                                  "CIS Benchmark (title only; content licensed separately)")],
        )]


class DemoPatchCheck(_DemoCheck):
    check_id = "DEMO-LNX-PATCH-001"
    title = "Pending security updates (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        return [ctx.finding(
            self, host=DEMO_HOST,
            title="Security updates are pending for 3 packages",
            severity=Severity.MEDIUM, status=FindingStatus.POTENTIAL,
            component="APT package manager",
            description=DEMO_NOTE + "apt reports upgradable packages from the -security pocket. "
                        "The installed versions may be vulnerable to the issues fixed by these updates.",
            impact="Unpatched packages may contain exploitable vulnerabilities.",
            confidence=Confidence.MEDIUM,
            remediation="Apply updates during a maintenance window: sudo apt update && sudo apt upgrade.",
            verification="apt list --upgradable 2>/dev/null | grep -- -security should return nothing.",
            severity_rationale="Medium/potential: based on package metadata only; individual CVE "
                               "applicability and exploitability were not confirmed.",
            evidence=[ctx.evidence("Upgradable packages (sample)", "apt list --upgradable",
                                   ["openssl/noble-security 3.0.13-0ubuntu3.5",
                                    "libssl3t64/noble-security 3.0.13-0ubuntu3.5",
                                    "sudo/noble-security 1.9.15p5-3ubuntu5.1"])],
            manual_validation_required=True,
        )]


class DemoInfoCheck(_DemoCheck):
    check_id = "DEMO-SYS-001"
    title = "Disk encryption (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        return [ctx.finding(
            self, host=DEMO_HOST,
            title="System volume encryption status could not be determined",
            severity=Severity.LOW, status=FindingStatus.INCONCLUSIVE,
            component="Disk encryption",
            description=DEMO_NOTE + "No LUKS mapping was found for the root filesystem, but the "
                        "volume may be protected by hardware (SED) or hypervisor-level encryption.",
            impact="If the disk is unencrypted, data could be read from a stolen or decommissioned drive.",
            confidence=Confidence.LOW,
            remediation="Confirm the encryption approach with the platform owner; enable LUKS or "
                        "equivalent where policy requires encryption at rest.",
            verification="lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT and the hypervisor/storage console.",
            severity_rationale="Low/inconclusive: absence of evidence is not evidence of absence.",
            evidence=[ctx.evidence("Block devices (sample)", "lsblk -J",
                                   {"sda2": {"fstype": "ext4", "mountpoint": "/"}})],
            manual_validation_required=True,
        )]


class DemoFailingCheck(_DemoCheck):
    """Demonstrates that a failing check is isolated and reported as a limitation."""

    check_id = "DEMO-ERR-001"
    title = "Simulated check failure (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        raise RuntimeError("simulated failure to demonstrate fail-soft behaviour")


class DemoPrivilegedCheck(_DemoCheck):
    """Demonstrates how privilege-gated checks are skipped and explained."""

    check_id = "DEMO-PRIV-001"
    title = "Local security policy export (sample, needs admin)"
    requires_admin = True
    admin_reason = "Exporting the local security policy requires an elevated session."

    def run(self, ctx: AssessmentContext) -> list[Finding]:  # pragma: no cover - always skipped
        return []


def build_module() -> Module:
    return Module(
        module_id="demo",
        name="Demonstration (sample data)",
        description="Produces labelled sample findings; executes no commands and sends no traffic.",
        category="demo",
        checks=[DemoSmbCheck(), DemoRdpCheck(), DemoSshCheck(), DemoPatchCheck(), DemoInfoCheck(),
                DemoFailingCheck(), DemoPrivilegedCheck()],
    )

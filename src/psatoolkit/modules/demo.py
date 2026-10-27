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


class DemoEmptyPasswordCheck(_DemoCheck):
    check_id = "DEMO-LNX-ACCT-001"
    title = "Empty password with SSH access (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        return [ctx.finding(
            self, host=DEMO_HOST,
            title="Account 'backup' has an empty password and SSH permits empty passwords",
            severity=Severity.CRITICAL, status=FindingStatus.CONFIRMED,
            component="/etc/shadow and sshd (PermitEmptyPasswords yes)",
            description=DEMO_NOTE + "The 'backup' account has no password, and the effective sshd configuration "
                        "allows empty-password logins with password authentication enabled.",
            impact="Anyone who can reach SSH can log in as 'backup' without credentials.",
            confidence=Confidence.HIGH,
            remediation="Lock the account (sudo passwd -l backup), set 'PermitEmptyPasswords no' and reload sshd. "
                        "Review authentication logs for prior logins.",
            verification="sudo sshd -T | grep permitemptypasswords  -> no; sudo passwd -S backup  -> L",
            severity_rationale="Critical: unauthenticated remote access, directly observed in two independent "
                               "settings.",
            evidence=[ctx.evidence("Account flags and sshd settings (sample, no hashes)", "/etc/shadow; sshd -T",
                                   {"backup": "empty password field", "permitemptypasswords": "yes",
                                    "passwordauthentication": "yes"})],
            references=[Reference(ReferenceKind.CWE, "CWE-258", "MITRE CWE: Empty Password in Configuration File")],
        )]


class DemoVulnerablePackageCheck(_DemoCheck):
    check_id = "DEMO-VULN-001"
    title = "Known vulnerabilities in installed software (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        ctx.data_sources.append({"type": "vulnerability_data", "snapshot_date": "2026-10-20", "age_days": 6,
                                 "record_count": 64210, "ecosystem": "ubuntu:24.04",
                                 "sources": [{"name": "Sample snapshot (demo)"}]})
        return [ctx.finding(
            self, host=DEMO_HOST,
            title="examplelib: 3 known vulnerabilities affect the installed version",
            severity=Severity.HIGH, status=FindingStatus.POTENTIAL,
            component="Package examplelib (libexample1 1.2-1ubuntu0.1)",
            description=DEMO_NOTE + "The installed version is affected by 3 advisories (fictitious identifiers "
                        "CVE-2099-0001..0003); 2 are fixed in a newer package and 1 has no fix yet.",
            impact="Publicly documented vulnerabilities may allow attackers to compromise software that uses the "
                   "library.",
            confidence=Confidence.HIGH,
            remediation="Update examplelib to 1.2-1ubuntu0.5 or later (sudo apt install --only-upgrade libexample1), "
                        "then restart services that use it.",
            verification="dpkg-query -W libexample1 shows 1.2-1ubuntu0.5 or later.",
            severity_rationale="High: highest rating among the matching advisories is CVSS v3.1 base score 8.1 "
                               "(sample data). Potential because the match is version-based.",
            evidence=[ctx.evidence("Matching advisories (sample)", "offline vulnerability data",
                                   [{"advisory": "CVE-2099-0001", "cvss": 8.1, "fixed": "1.2-1ubuntu0.5"},
                                    {"advisory": "CVE-2099-0002", "cvss": 5.3, "fixed": "1.2-1ubuntu0.3"},
                                    {"advisory": "CVE-2099-0003", "cvss": None, "fixed": None}])],
            references=[Reference(ReferenceKind.CVE, "CVE-2099-0001", "Sample data (fictitious)", 8.1, "3.1",
                                  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")],
            manual_validation_required=True,
        )]


class DemoBaselineCheck(_DemoCheck):
    check_id = "DEMO-BASE-001"
    title = "Organisational baseline comparison (sample)"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        label = "Example Ubuntu Server Baseline v1.0"
        ctx.data_sources.append({"type": "baseline", "name": "Example Ubuntu Server Baseline", "version": "1.0",
                                 "file": "example-ubuntu-server.json", "sha256": "0" * 64, "rules": 21,
                                 "passed": 17, "failed": 2, "inconclusive": 2})
        ref = Reference(ReferenceKind.BASELINE, label, "Example organisational policy (demo)")
        return [
            ctx.finding(
                self, host=DEMO_HOST, title="Baseline 'Example Ubuntu Server Baseline': 17 of 19 evaluated rules met (89%)",
                severity=Severity.INFO, status=FindingStatus.INFORMATIONAL, component=f"Baseline {label}",
                description=DEMO_NOTE + "2 rules deviate and 2 could not be evaluated without root. This compares "
                            "configuration with the supplied baseline; it is not a formal compliance assessment.",
                impact="Deviations are listed as separate findings.", confidence=Confidence.HIGH,
                remediation="Remediate the deviations, or record approved exceptions in the baseline.",
                verification="Re-run the assessment after changes.",
                severity_rationale="Informational summary of the baseline comparison.",
                evidence=[ctx.evidence("Rule results (sample)", f"baseline {label}",
                                       {"passed": 17, "failed": ["ACC-02", "FILE-03"], "inconclusive": ["SSH-01", "SSH-02"]})],
                references=[ref]),
            ctx.finding(
                self, host=DEMO_HOST, title="Baseline deviation: Default umask is 027 or stricter",
                severity=Severity.LOW, status=FindingStatus.CONFIRMED,
                component=f"'UMASK' in /etc/login.defs ({label} ACC-02)",
                description=DEMO_NOTE + "Expected 'UMASK' in /etc/login.defs to be one of ['027', '077']; observed: 022.",
                impact="New files may be readable by other local users.", confidence=Confidence.HIGH,
                remediation="Set 'UMASK 027' in /etc/login.defs.",
                verification="Re-run the assessment and confirm rule ACC-02 passes.",
                severity_rationale="Low: severity assigned by the baseline author; the observed value was read directly.",
                evidence=[ctx.evidence("Observed vs expected (sample)", "baseline collector 'file_kv'",
                                       {"expected": "one of ['027', '077']", "observed": "022"})],
                references=[Reference(ReferenceKind.BASELINE, f"{label} rule ACC-02", ref.source)]),
        ]


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
        description="Produces labelled sample findings covering every severity and status, plus sample "
                    "vulnerability and baseline results; executes no commands and sends no traffic.",
        category="demo",
        checks=[DemoEmptyPasswordCheck(), DemoSmbCheck(), DemoRdpCheck(), DemoSshCheck(), DemoPatchCheck(),
                DemoInfoCheck(), DemoVulnerablePackageCheck(), DemoBaselineCheck(), DemoFailingCheck(),
                DemoPrivilegedCheck()],
    )

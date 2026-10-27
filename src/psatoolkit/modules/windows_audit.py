"""Module B: Windows security audit (read-only).

Every query is a ``Get-*`` PowerShell call, a registry read, or an
allow-listed read-only command (``net accounts``, ``auditpol /get``). Nothing
is changed on the system. Remediation text tells the administrator what to
change; the toolkit never applies it.

Note: ``net accounts`` and some PowerShell property values are localized. The
checks below parse locale-independent values where possible and report a
limitation otherwise.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import date, datetime

from psatoolkit.core.engine import AssessmentContext, Check, Module, SkipCheck
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Severity
from psatoolkit.modules._common import (CIS_WIN, MS_BASELINE, as_int, baseline, cwe, read_registry, run_ps,
                                        url)
from psatoolkit.modules.certificates import evaluate_certificates

WIN = frozenset({"windows"})
HKLM = "HKLM:\\SYSTEM\\CurrentControlSet"


class WindowsCheck(Check):
    supported_os = WIN


# --------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------

class FirewallProfilesCheck(WindowsCheck):
    check_id = "WIN-FW-001"
    title = "Windows Defender Firewall profiles"
    description = "Verifies every firewall profile is enabled and blocks unsolicited inbound traffic."
    PS = ("Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,"
          "@{n='Enabled';e={[string]$_.Enabled}},@{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}},"
          "@{n='DefaultOutboundAction';e={[string]$_.DefaultOutboundAction}}")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        profiles = [p for p in run_ps(ctx, self.PS, "firewall profiles") if isinstance(p, dict)]
        if not profiles:
            raise SkipCheck("No firewall profile information was returned.", "error")
        findings = []
        ev = ctx.evidence("Effective firewall profiles", "Get-NetFirewallProfile -PolicyStore ActiveStore", profiles)
        disabled = [p["Name"] for p in profiles if str(p.get("Enabled")).lower() == "false"]
        allow_in = [p["Name"] for p in profiles if str(p.get("DefaultInboundAction")).lower() == "allow"]
        if disabled:
            findings.append(ctx.finding(
                self, title=f"Windows Firewall is disabled for: {', '.join(disabled)}",
                severity=Severity.HIGH, status=FindingStatus.CONFIRMED, component="Windows Defender Firewall",
                description="The host firewall is turned off for one or more network profiles, so every "
                            "listening service is reachable from networks of that type.",
                impact="Attackers on the same network can reach all exposed services, enabling exploitation "
                       "and lateral movement (e.g. SMB, RDP, WinRM).",
                confidence=Confidence.HIGH,
                remediation="Enable the firewall for all profiles via Group Policy: Computer Configuration > "
                            "Windows Settings > Security Settings > Windows Defender Firewall with Advanced "
                            "Security > Properties > Firewall state = On (recommended) for Domain, Private "
                            "and Public. If a third-party firewall is used, document it and verify it is active.",
                verification="Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,Enabled",
                severity_rationale="High: a disabled host firewall removes a primary network control, directly "
                                   "observed in the effective policy store.",
                evidence=[ev], references=[baseline("Windows Firewall: <Profile>: Firewall state = On",
                                                    MS_BASELINE), cwe(284, "Improper Access Control")]))
        if allow_in:
            findings.append(ctx.finding(
                self, title=f"Firewall allows unsolicited inbound traffic by default ({', '.join(allow_in)})",
                severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED, component="Windows Defender Firewall",
                description="The default inbound action is Allow, so traffic not matched by a rule is accepted.",
                impact="New or unexpected services become reachable without an explicit firewall rule.",
                confidence=Confidence.HIGH,
                remediation="Set 'Inbound connections' to Block (default) for every profile and create explicit "
                            "allow rules only for required services.",
                verification="Get-NetFirewallProfile -PolicyStore ActiveStore | Select Name,DefaultInboundAction",
                severity_rationale="Medium: weakens the firewall's default-deny posture; individual services may "
                                   "still be protected by rules.",
                evidence=[ev], references=[baseline("Windows Firewall: <Profile>: Inbound connections = Block",
                                                    MS_BASELINE)]))
        if not findings:
            ctx.note(f"All {len(profiles)} firewall profiles are enabled with default-deny inbound")
        return findings


# --------------------------------------------------------------------------
# Antivirus / Defender
# --------------------------------------------------------------------------

def decode_security_center_state(state: int) -> dict[str, bool]:
    """Decode the (undocumented, widely used) SecurityCenter2 productState bit field."""
    return {"enabled": bool(state & 0x1000), "up_to_date": not bool(state & 0x10)}


class DefenderCheck(WindowsCheck):
    check_id = "WIN-AV-001"
    title = "Antivirus / Microsoft Defender status"
    description = "Checks that real-time antivirus protection is active and signatures are current."
    MAX_SIGNATURE_AGE_DAYS = 7
    PS = ("$s=$null; try { $s=Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,"
          "AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,"
          "AntivirusSignatureAge,IsTamperProtected,AMRunningMode,AMProductVersion } catch {}; "
          "$av=@(); try { $av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
          "-ErrorAction Stop | Select-Object displayName,productState) } catch {}; "
          "[pscustomobject]@{Defender=$s; Products=$av}")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        rows = run_ps(ctx, self.PS, "antivirus status")
        data = rows[0] if rows and isinstance(rows[0], dict) else {}
        defender = data.get("Defender") if isinstance(data.get("Defender"), dict) else None
        products = [p for p in (data.get("Products") or []) if isinstance(p, dict)]
        decoded = [{"name": p.get("displayName"), **decode_security_center_state(as_int(p.get("productState")) or 0)}
                   for p in products]
        ev = ctx.evidence("Defender and Security Center status", "Get-MpComputerStatus; root/SecurityCenter2",
                          {"defender": defender, "registered_products": decoded})
        third_party = [p for p in decoded if "defender" not in str(p["name"]).lower()]
        mode = str((defender or {}).get("AMRunningMode") or "")
        findings: list[Finding] = []

        def add(title: str, severity: Severity, description: str, rationale: str,
                status: FindingStatus = FindingStatus.CONFIRMED, confidence: Confidence = Confidence.HIGH) -> None:
            findings.append(ctx.finding(
                self, title=title, severity=severity, status=status, component="Antivirus / endpoint protection",
                description=description,
                impact="Malware, including ransomware, may run without being detected or blocked.",
                confidence=confidence,
                remediation="Ensure an approved antivirus/EDR product is installed, running with real-time "
                            "protection, and receiving signature updates. For Defender, enforce settings via "
                            "Group Policy/Intune and enable Tamper Protection.",
                verification="Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusSignatureAge,"
                             "IsTamperProtected (or the third-party console).",
                severity_rationale=rationale, evidence=[ev],
                references=[baseline("Microsoft Defender Antivirus: Turn on real-time protection", MS_BASELINE)],
                manual_validation_required=status != FindingStatus.CONFIRMED))

        if defender is None and not decoded:
            add("Antivirus status could not be determined", Severity.MEDIUM,
                "Neither Microsoft Defender nor a Security Center-registered antivirus product reported status. "
                "Windows Server does not provide Security Center, so third-party products may not be visible.",
                "Medium/inconclusive: absence of evidence; an unprotected host would be High.",
                FindingStatus.INCONCLUSIVE, Confidence.LOW)
            return findings

        passive = "passive" in mode.lower() or "edr block" in mode.lower()
        if defender is not None and not passive:
            if defender.get("RealTimeProtectionEnabled") is False or defender.get("AntivirusEnabled") is False:
                add("Microsoft Defender real-time protection is disabled", Severity.HIGH,
                    "Defender is the active antivirus but real-time protection (or the antivirus engine) is off.",
                    "High: directly observed loss of the primary malware control.")
            age = as_int(defender.get("AntivirusSignatureAge"))
            if age is not None and age > self.MAX_SIGNATURE_AGE_DAYS:
                add(f"Antivirus signatures are {age} days old", Severity.MEDIUM,
                    f"Defender signatures were last updated {age} days ago (threshold "
                    f"{self.MAX_SIGNATURE_AGE_DAYS} days). Note: offline hosts cannot update.",
                    "Medium: protection still runs but misses recent threats.")
            if defender.get("IsTamperProtected") is False:
                add("Defender Tamper Protection is off", Severity.LOW,
                    "Tamper Protection prevents malware and local admins from disabling Defender settings.",
                    "Low: hardening control; Defender itself is still running.")
        for p in third_party:
            if not p["enabled"]:
                add(f"Registered antivirus '{p['name']}' reports protection disabled", Severity.HIGH,
                    "Security Center reports this product as disabled.",
                    "High if confirmed; productState decoding is undocumented, so confidence is medium.",
                    FindingStatus.POTENTIAL, Confidence.MEDIUM)
            elif not p["up_to_date"]:
                add(f"Registered antivirus '{p['name']}' reports outdated definitions", Severity.MEDIUM,
                    "Security Center reports this product's definitions as out of date.",
                    "Medium; productState decoding is undocumented, so confidence is medium.",
                    FindingStatus.POTENTIAL, Confidence.MEDIUM)
        if passive and not [p for p in third_party if p["enabled"]]:
            add("Defender is in passive mode but no active third-party antivirus was confirmed", Severity.MEDIUM,
                f"Defender runs in '{mode}' and no enabled third-party product is registered in Security Center "
                "(Security Center is unavailable on Windows Server).",
                "Medium/potential: verify the third-party EDR in its management console.",
                FindingStatus.POTENTIAL, Confidence.MEDIUM)
        if not findings:
            ctx.note("Real-time antivirus protection is active with current signatures")
        return findings


# --------------------------------------------------------------------------
# SMB
# --------------------------------------------------------------------------

class SmbCheck(WindowsCheck):
    check_id = "WIN-SMB-001"
    title = "SMB protocol security (SMBv1, signing)"
    description = "Checks for SMBv1 and whether SMB signing is required."
    PS = ("$p=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
          "-ErrorAction SilentlyContinue; "
          "$c=$null; try { $c=Get-SmbServerConfiguration -ErrorAction Stop | Select-Object EnableSMB1Protocol,"
          "RequireSecuritySignature,EncryptData } catch {}; "
          "$w=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' "
          "-ErrorAction SilentlyContinue; "
          "$m=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10' "
          "-ErrorAction SilentlyContinue; "
          "[pscustomobject]@{RegSMB1=$p.SMB1; RegRequireSigning=$p.RequireSecuritySignature; Server=$c; "
          "ClientRequireSigning=$w.RequireSecuritySignature; Smb1ClientStart=$m.Start; Smb1ClientPresent=[bool]$m}")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        rows = run_ps(ctx, self.PS, "SMB configuration")
        d = rows[0] if rows and isinstance(rows[0], dict) else {}
        server = d.get("Server") if isinstance(d.get("Server"), dict) else None
        ev = ctx.evidence("SMB configuration", "Get-SmbServerConfiguration; LanmanServer/LanmanWorkstation registry", d)
        if server is None and not ctx.host.elevated:
            ctx.limitation("Get-SmbServerConfiguration requires administrator rights; registry values were used.",
                           "privilege")
        reg_smb1 = as_int(d.get("RegSMB1"))
        if server is not None and server.get("EnableSMB1Protocol") is not None:
            smb1 = bool(server.get("EnableSMB1Protocol"))
        else:
            smb1 = {1: True, 0: False}.get(reg_smb1)  # None = unknown
        findings = []
        refs = [cwe(327, "Use of a Broken or Risky Cryptographic Algorithm"),
                url("https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/"
                    "detect-enable-and-disable-smbv1-v2-v3", "Microsoft: SMBv1 guidance")]
        if smb1 is True:
            findings.append(ctx.finding(
                self, title="SMBv1 server protocol is enabled", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, component="LanmanServer (SMB 1.0)",
                description="The SMB 1.0 server protocol is enabled. SMBv1 is deprecated, lacks pre-authentication "
                            "integrity and encryption, and was the vector for WannaCry/NotPetya (MS17-010).",
                impact="Exposure to SMBv1 vulnerabilities and downgrade/relay attacks; wormable malware spreads "
                       "via SMBv1 where patches are missing.",
                confidence=Confidence.HIGH,
                remediation="Confirm no legacy clients need SMBv1, then remove it: Disable-WindowsOptionalFeature "
                            "-Online -FeatureName SMB1Protocol (servers: Remove-WindowsFeature FS-SMB1). Apply "
                            "during a change window.",
                verification="Get-SmbServerConfiguration | Select EnableSMB1Protocol  -> False",
                severity_rationale="High: network-reachable legacy protocol with a history of wormable exploits; "
                                   "directly observed.",
                evidence=[ev], references=[baseline("Configure SMB v1 server = Disabled", MS_BASELINE), *refs]))
        elif smb1 is None:
            findings.append(ctx.finding(
                self, title="SMBv1 server state could not be confirmed", severity=Severity.LOW,
                status=FindingStatus.INCONCLUSIVE, component="LanmanServer (SMB 1.0)",
                description="The SMB1 registry value is not set and the SMB server configuration could not be "
                            "read. Modern Windows releases do not install SMBv1 by default, but upgraded systems "
                            "may still have it.",
                impact="If SMBv1 is enabled, see the SMBv1 risks above.", confidence=Confidence.LOW,
                remediation="Re-run elevated, or check 'Get-WindowsOptionalFeature -Online -FeatureName "
                            "SMB1Protocol' as an administrator.",
                verification="Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                severity_rationale="Low/inconclusive: state unknown, most likely disabled on current releases.",
                evidence=[ev], references=refs, manual_validation_required=True))
        require = server.get("RequireSecuritySignature") if server else (as_int(d.get("RegRequireSigning")) == 1)
        if not require:
            sev = Severity.MEDIUM if ctx.os_info.is_server else Severity.LOW
            findings.append(ctx.finding(
                self, title="SMB server does not require signing", severity=sev, status=FindingStatus.CONFIRMED,
                component="LanmanServer", description="SMB packet signing is not required for connections to "
                                                      "this computer.",
                impact="Attackers who can intercept or relay NTLM authentication (e.g. via LLMNR/NBT-NS "
                       "poisoning) can relay it to this host's SMB service.",
                confidence=Confidence.HIGH if server else Confidence.MEDIUM,
                remediation="Enable 'Microsoft network server: Digitally sign communications (always)' via Group "
                            "Policy (Security Options). Windows 11 24H2 / Server 2025 require it by default.",
                verification="Get-SmbServerConfiguration | Select RequireSecuritySignature  -> True",
                severity_rationale=f"{sev.value.capitalize()}: enables NTLM relay; servers are higher-value relay "
                                   "targets than workstations.",
                evidence=[ev], references=[baseline("Microsoft network server: Digitally sign communications "
                                                    "(always) = Enabled", MS_BASELINE),
                                           cwe(294, "Authentication Bypass by Capture-replay")]))
        if d.get("Smb1ClientPresent") and as_int(d.get("Smb1ClientStart")) not in (4, None):
            findings.append(ctx.finding(
                self, title="SMBv1 client driver is enabled", severity=Severity.LOW, status=FindingStatus.CONFIRMED,
                component="mrxsmb10", description="The SMB 1.0 client driver (mrxsmb10) is not disabled.",
                impact="The host can be induced to connect to malicious SMBv1 servers.", confidence=Confidence.HIGH,
                remediation="Remove the SMB1Protocol optional feature (removes client and server).",
                verification="Get-Service mrxsmb10 should not exist or have StartType Disabled.",
                severity_rationale="Low: client-side legacy protocol; requires the host to connect outbound.",
                evidence=[ev], references=[baseline("Configure SMB v1 client driver = Disable driver", MS_BASELINE)]))
        if not findings:
            ctx.note("SMBv1 disabled and SMB signing required")
        return findings


# --------------------------------------------------------------------------
# Remote Desktop
# --------------------------------------------------------------------------

class RdpCheck(WindowsCheck):
    check_id = "WIN-RDP-001"
    title = "Remote Desktop exposure and security"
    description = "Checks whether RDP is enabled and whether NLA and TLS are enforced."
    TS = HKLM + "\\Control\\Terminal Server"
    SPEC = {
        "ts": (TS, ["fDenyTSConnections"]),
        "tcp": (TS + "\\WinStations\\RDP-Tcp", ["UserAuthentication", "SecurityLayer", "MinEncryptionLevel",
                                                "PortNumber"]),
        "pol": ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
                ["fDenyTSConnections", "UserAuthentication", "SecurityLayer", "MinEncryptionLevel"]),
    }

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        r = read_registry(ctx, self.SPEC, "Remote Desktop settings")

        def eff(name: str, local_alias: str) -> int | None:
            pol = as_int(r.get(f"pol.{name}"))
            return pol if pol is not None else as_int(r.get(f"{local_alias}.{name}"))

        deny = eff("fDenyTSConnections", "ts")
        if deny != 0:
            ctx.note("Remote Desktop is disabled")
            return []
        nla, layer, level = eff("UserAuthentication", "tcp"), eff("SecurityLayer", "tcp"), eff("MinEncryptionLevel", "tcp")
        port = as_int(r.get("tcp.PortNumber")) or 3389
        ev = ctx.evidence("Effective RDP settings (policy overrides local)", "Terminal Server registry",
                          {"enabled": True, "port": port, "UserAuthentication": nla, "SecurityLayer": layer,
                           "MinEncryptionLevel": level, "raw": r})
        findings = [ctx.finding(
            self, title=f"Remote Desktop is enabled (TCP {port})", severity=Severity.INFO,
            status=FindingStatus.INFORMATIONAL, component="Remote Desktop Services",
            description="Remote Desktop connections are allowed.",
            impact="RDP is a common target for password spraying and exploitation when exposed.",
            confidence=Confidence.HIGH,
            remediation="Allow RDP only from management networks/jump hosts via firewall rules or an RD Gateway, "
                        "and require MFA where possible.",
            verification="Confirm firewall rules restrict TCP/" + str(port) + " to approved sources.",
            severity_rationale="Informational: enabled RDP is often required; weaknesses are reported separately.",
            evidence=[ev])]
        if nla == 0:
            findings.append(ctx.finding(
                self, title="RDP does not require Network Level Authentication (NLA)", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="RDP-Tcp",
                description="Clients reach the full logon session before authenticating.",
                impact="Unauthenticated users consume server resources and reach pre-authentication attack "
                       "surface (e.g. BlueKeep CVE-2019-0708 was mitigated by NLA).",
                confidence=Confidence.HIGH,
                remediation="Enable 'Require user authentication for remote connections by using Network Level "
                            "Authentication' (Administrative Templates > Remote Desktop Services > Security).",
                verification="UserAuthentication under ...\\WinStations\\RDP-Tcp (or policy) = 1",
                severity_rationale="Medium: weakens authentication of a remote service; directly observed.",
                evidence=[ev], references=[cwe(287, "Improper Authentication"),
                                           baseline("Require user authentication for remote connections by using "
                                                    "NLA = Enabled", MS_BASELINE)]))
        if layer == 0:
            findings.append(ctx.finding(
                self, title="RDP uses the legacy RDP security layer instead of TLS", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="RDP-Tcp",
                description="SecurityLayer = 0 (RDP security): the server is not authenticated with TLS.",
                impact="Man-in-the-middle attacks against RDP sessions become feasible.",
                confidence=Confidence.HIGH,
                remediation="Set 'Require use of specific security layer for remote (RDP) connections' to SSL/TLS.",
                verification="SecurityLayer = 2",
                severity_rationale="Medium: enables interception on hostile networks.",
                evidence=[ev], references=[cwe(300, "Channel Accessible by Non-Endpoint")]))
        if level is not None and level < 3 and layer == 0:
            findings.append(ctx.finding(
                self, title="RDP encryption level is below High", severity=Severity.LOW,
                status=FindingStatus.CONFIRMED, component="RDP-Tcp",
                description=f"MinEncryptionLevel = {level} with the RDP security layer.",
                impact="Weaker session encryption.", confidence=Confidence.HIGH,
                remediation="Set 'Set client connection encryption level' to High Level (3), and use TLS.",
                verification="MinEncryptionLevel = 3", severity_rationale="Low: only relevant with the legacy layer.",
                evidence=[ev], references=[cwe(326, "Inadequate Encryption Strength")]))
        return findings


# --------------------------------------------------------------------------
# UAC
# --------------------------------------------------------------------------

class UacCheck(WindowsCheck):
    check_id = "WIN-UAC-001"
    title = "User Account Control (UAC) configuration"
    description = "Checks UAC is enabled with secure prompting and remote token filtering."
    SPEC = {"sys": ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop",
                     "LocalAccountTokenFilterPolicy", "FilterAdministratorToken"])}

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        r = read_registry(ctx, self.SPEC, "UAC settings")
        v = {k.split(".", 1)[1]: as_int(val) for k, val in r.items()}
        ev = ctx.evidence("UAC registry values (missing = Windows default)", "Policies\\System registry", v)
        findings = []

        def add(title, severity, description, impact, remediation, check, rationale, ref):
            findings.append(ctx.finding(
                self, title=title, severity=severity, status=FindingStatus.CONFIRMED, component="User Account Control",
                description=description, impact=impact, confidence=Confidence.HIGH, remediation=remediation,
                verification=check, severity_rationale=rationale, evidence=[ev],
                references=[baseline(ref, MS_BASELINE), cwe(250, "Execution with Unnecessary Privileges")]))

        if v.get("EnableLUA") == 0:
            add("User Account Control is disabled", Severity.HIGH,
                "EnableLUA = 0: administrators run every process with a full administrative token.",
                "Any malware executed by an administrator immediately gains full control of the system.",
                "Set 'User Account Control: Run all administrators in Admin Approval Mode' = Enabled and reboot.",
                "EnableLUA = 1", "High: removes a core privilege boundary; directly observed.",
                "UAC: Run all administrators in Admin Approval Mode = Enabled")
        if v.get("ConsentPromptBehaviorAdmin") == 0:
            add("UAC elevates administrators without prompting", Severity.MEDIUM,
                "ConsentPromptBehaviorAdmin = 0: elevation happens silently.",
                "Malware running as an administrator can elevate without user interaction.",
                "Set 'Behavior of the elevation prompt for administrators' to 'Prompt for consent on the secure "
                "desktop' (2) or stricter.", "ConsentPromptBehaviorAdmin = 2 (or 1)",
                "Medium: silent elevation; UAC still separates tokens.",
                "UAC: Behavior of the elevation prompt for administrators = Prompt for consent on the secure desktop")
        if v.get("PromptOnSecureDesktop") == 0:
            add("UAC prompts are not shown on the secure desktop", Severity.LOW,
                "PromptOnSecureDesktop = 0: other processes can interact with elevation prompts.",
                "Malware could spoof or auto-click elevation prompts.",
                "Set 'Switch to the secure desktop when prompting for elevation' = Enabled.",
                "PromptOnSecureDesktop = 1", "Low: requires code already running in the user session.",
                "UAC: Switch to the secure desktop when prompting for elevation = Enabled")
        if v.get("LocalAccountTokenFilterPolicy") == 1:
            add("Remote UAC token filtering is disabled for local accounts", Severity.MEDIUM,
                "LocalAccountTokenFilterPolicy = 1: local administrator accounts receive full admin rights over "
                "the network.",
                "Stolen local administrator credentials or hashes can be reused for remote administration and "
                "lateral movement (pass-the-hash).",
                "Remove the value or set it to 0 ('Apply UAC restrictions to local accounts on network logons'). "
                "Use LAPS for unique local admin passwords.", "LocalAccountTokenFilterPolicy absent or 0",
                "Medium: materially eases lateral movement with local credentials.",
                "MS Security Guide: Apply UAC restrictions to local accounts on network logons = Enabled")
        if not findings:
            ctx.note("UAC enabled with secure prompting and remote token filtering")
        return findings


# --------------------------------------------------------------------------
# Accounts and policy
# --------------------------------------------------------------------------

_NET_ACCOUNTS_KEYS = {
    "Minimum password length": "min_length",
    "Length of password history maintained": "history",
    "Lockout threshold": "lockout_threshold",
    "Maximum password age (days)": "max_age",
    "Lockout duration (minutes)": "lockout_duration",
    "Computer role": "role",
}


def parse_net_accounts(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(.+?):\s{2,}(.+)$", line.strip())
        if m and m.group(1).strip() in _NET_ACCOUNTS_KEYS:
            out[_NET_ACCOUNTS_KEYS[m.group(1).strip()]] = m.group(2).strip()
    return out


def _num(value: str | None) -> int | None:
    if value is None:
        return None
    if value.strip().lower() in ("never", "none", "unlimited"):
        return 0
    return as_int(value.strip())


class PasswordPolicyCheck(WindowsCheck):
    check_id = "WIN-ACCT-001"
    title = "Password and account lockout policy"
    description = "Compares the effective local password and lockout policy with the Microsoft baseline."
    required_tools = ("net",)

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        res = ctx.runner.run(["net", "accounts"])
        if not res.ok:
            raise SkipCheck(f"'net accounts' failed: {res.error_detail or res.stderr.strip()[:200]}")
        p = parse_net_accounts(res.stdout)
        if "min_length" not in p:
            raise SkipCheck("'net accounts' output is not in English; password policy could not be parsed.",
                            "platform")
        ev = ctx.evidence("Effective password policy", "net accounts", p)
        role = p.get("role", "").upper()
        scope = ("domain password policy (this is a domain controller)" if role in ("PRIMARY", "BACKUP")
                 else "local account policy; domain accounts follow the domain policy")
        findings = []
        min_len, threshold, history = _num(p.get("min_length")), _num(p.get("lockout_threshold")), _num(p.get("history"))
        if min_len is not None and min_len < 14:
            sev = Severity.MEDIUM if min_len < 8 else Severity.LOW
            findings.append(ctx.finding(
                self, title=f"Minimum password length is {min_len}", severity=sev, status=FindingStatus.CONFIRMED,
                component="Password policy", description=f"The {scope} allows passwords shorter than 14 characters.",
                impact="Short passwords are easier to guess or crack offline.", confidence=Confidence.HIGH,
                remediation="Set 'Minimum password length' to 14 (Group Policy: Account Policies > Password "
                            "Policy). Prefer passphrases and MFA.",
                verification="net accounts  -> Minimum password length: 14",
                severity_rationale=f"{sev.value.capitalize()}: below 8 characters is weak by any standard; 8-13 is "
                                   "below the Microsoft/CIS baseline of 14.",
                evidence=[ev], references=[cwe(521, "Weak Password Requirements"),
                                           baseline("Minimum password length = 14", MS_BASELINE)]))
        if threshold == 0:
            findings.append(ctx.finding(
                self, title="Account lockout is not configured", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="Account lockout policy",
                description=f"The {scope} never locks accounts after failed logons.",
                impact="Attackers can guess passwords indefinitely (online brute force / password spraying).",
                confidence=Confidence.HIGH,
                remediation="Set 'Account lockout threshold' to 10 or fewer invalid attempts, with a 15-minute "
                            "lockout duration and reset counter.",
                verification="net accounts  -> Lockout threshold: 10",
                severity_rationale="Medium: enables unlimited online guessing; mitigated if MFA is enforced.",
                evidence=[ev], references=[cwe(307, "Improper Restriction of Excessive Authentication Attempts"),
                                           baseline("Account lockout threshold = 10", MS_BASELINE)]))
        elif threshold is not None and threshold > 10:
            findings.append(ctx.finding(
                self, title=f"Account lockout threshold is high ({threshold})", severity=Severity.LOW,
                status=FindingStatus.CONFIRMED, component="Account lockout policy",
                description=f"Accounts lock only after {threshold} failed attempts.",
                impact="More guesses per account before lockout.", confidence=Confidence.HIGH,
                remediation="Set the threshold to 10 or fewer.", verification="net accounts",
                severity_rationale="Low: lockout exists but is lenient.",
                evidence=[ev], references=[baseline("Account lockout threshold = 10", MS_BASELINE)]))
        if history is not None and history < 24:
            findings.append(ctx.finding(
                self, title=f"Password history keeps only {history} password(s)", severity=Severity.LOW,
                status=FindingStatus.CONFIRMED, component="Password policy",
                description="Users can quickly cycle back to previously used passwords.",
                impact="Compromised old passwords may be reused.", confidence=Confidence.HIGH,
                remediation="Set 'Enforce password history' to 24.", verification="net accounts",
                severity_rationale="Low: limited impact on its own.",
                evidence=[ev], references=[baseline("Enforce password history = 24", MS_BASELINE)]))
        if not findings:
            ctx.note("Password length, history and lockout meet the baseline")
        return findings


class LocalAccountsCheck(WindowsCheck):
    check_id = "WIN-ACCT-002"
    title = "Guest and local user accounts"
    description = "Reviews local accounts for an enabled Guest, accounts without passwords and stale accounts."
    STALE_DAYS = 90
    PS = ("Get-LocalUser | Select-Object Name,Enabled,@{n='SID';e={$_.SID.Value}},PasswordRequired,"
          "@{n='LastLogonDays';e={ if($_.LastLogon){[int]((Get-Date)-$_.LastLogon).TotalDays}else{$null} }}")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        users = [u for u in run_ps(ctx, self.PS, "local users") if isinstance(u, dict)]
        enabled = [u for u in users if u.get("Enabled")]
        ev = ctx.evidence("Local accounts (no password data collected)", "Get-LocalUser", users)
        findings = []
        rid = lambda u: str(u.get("SID", "")).rsplit("-", 1)[-1]  # noqa: E731
        guest = [u["Name"] for u in enabled if rid(u) == "501"]
        nopw = [u["Name"] for u in enabled if u.get("PasswordRequired") is False and rid(u) != "501"]
        admin = [u["Name"] for u in enabled if rid(u) == "500"]
        stale = [u["Name"] for u in enabled if rid(u) not in ("500", "501")
                 and (u.get("LastLogonDays") is None or (as_int(u.get("LastLogonDays")) or 0) > self.STALE_DAYS)]
        if guest:
            findings.append(ctx.finding(
                self, title="The Guest account is enabled", severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
                component=f"Local account {guest[0]}", description="The built-in Guest account (RID 501) is enabled.",
                impact="Allows unauthenticated or anonymous-like access to the system and shares.",
                confidence=Confidence.HIGH, remediation="Disable the Guest account ('Accounts: Guest account status' = "
                                                        "Disabled).",
                verification="Get-LocalUser | Where SID -like '*-501' | Select Enabled  -> False",
                severity_rationale="Medium: provides access without individual accountability.",
                evidence=[ev], references=[baseline("Accounts: Guest account status = Disabled", CIS_WIN)]))
        if nopw:
            findings.append(ctx.finding(
                self, title=f"{len(nopw)} enabled account(s) may have no password requirement",
                severity=Severity.MEDIUM, status=FindingStatus.POTENTIAL, component="Local accounts",
                description=f"PasswordRequired is False for: {', '.join(nopw)}. Such accounts may have a blank "
                            "password.",
                impact="Accounts with blank passwords can be used by anyone with local (or network, if allowed) "
                       "access.",
                confidence=Confidence.MEDIUM,
                remediation="Set strong passwords and clear the 'password not required' flag "
                            "(net user <name> /passwordreq:yes, run by an administrator).",
                verification="Get-LocalUser | Select Name,PasswordRequired",
                severity_rationale="Medium/potential: the flag permits but does not prove a blank password.",
                evidence=[ev], references=[cwe(521, "Weak Password Requirements")], manual_validation_required=True))
        if admin:
            findings.append(ctx.finding(
                self, title="The built-in Administrator account is enabled", severity=Severity.LOW,
                status=FindingStatus.CONFIRMED, component=f"Local account {admin[0]}",
                description="The RID-500 Administrator account is enabled. It is a well-known target and is not "
                            "subject to account lockout.",
                impact="Password guessing against a known, lockout-exempt account.", confidence=Confidence.HIGH,
                remediation="Disable it, or manage its password with Windows LAPS and rename it.",
                verification="Get-LocalUser | Where SID -like '*-500' | Select Enabled",
                severity_rationale="Low: acceptable when LAPS manages a unique strong password.",
                evidence=[ev], references=[baseline("Accounts: Administrator account status = Disabled", CIS_WIN)]))
        if stale:
            findings.append(ctx.finding(
                self, title=f"{len(stale)} enabled local account(s) unused for over {self.STALE_DAYS} days",
                severity=Severity.LOW, status=FindingStatus.CONFIRMED, component="Local accounts",
                description=f"Enabled accounts with no logon in {self.STALE_DAYS}+ days (or never): {', '.join(stale)}.",
                impact="Dormant accounts are attractive targets and often have outdated passwords.",
                confidence=Confidence.MEDIUM,
                remediation="Disable or remove accounts that are no longer required.",
                verification="Get-LocalUser | Select Name,Enabled,LastLogon",
                severity_rationale="Low: hygiene issue; risk depends on password strength.",
                evidence=[ev], references=[cwe(1188, "Initialization of a Resource with an Insecure Default")],
                manual_validation_required=True))
        if not findings:
            ctx.note(f"{len(enabled)} enabled local account(s); no account issues found")
        return findings


class LocalAdminsCheck(WindowsCheck):
    check_id = "WIN-ACCT-003"
    title = "Local Administrators group membership"
    description = "Lists members of the local Administrators group and flags excessive membership."
    MAX_EXTRA = 2
    PS = ("Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name,"
          "@{n='ObjectClass';e={[string]$_.ObjectClass}},@{n='Source';e={[string]$_.PrincipalSource}},"
          "@{n='SID';e={$_.SID.Value}}")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        members = [m for m in run_ps(ctx, self.PS, "local Administrators group") if isinstance(m, dict)]
        expected = [m for m in members if str(m.get("SID", "")).endswith(("-500", "-512"))]
        extra = [m for m in members if m not in expected]
        ev = ctx.evidence("Administrators group members", "Get-LocalGroupMember -SID S-1-5-32-544", members)
        findings = [ctx.finding(
            self, title=f"Local Administrators group has {len(members)} member(s)", severity=Severity.INFO,
            status=FindingStatus.INFORMATIONAL, component="BUILTIN\\Administrators",
            description="Members: " + ", ".join(str(m.get("Name")) for m in members),
            impact="Every member has full control of this computer.", confidence=Confidence.HIGH,
            remediation="Confirm each member is approved.", verification="Get-LocalGroupMember -SID S-1-5-32-544",
            severity_rationale="Informational inventory.", evidence=[ev])]
        if len(extra) > self.MAX_EXTRA:
            findings.append(ctx.finding(
                self, title=f"{len(extra)} accounts/groups have local administrator rights", severity=Severity.MEDIUM,
                status=FindingStatus.POTENTIAL, component="BUILTIN\\Administrators",
                description="Besides the built-in Administrator and Domain Admins, these principals are local "
                            "administrators: " + ", ".join(str(m.get("Name")) for m in extra),
                impact="Each additional administrator increases the chance that a compromised account yields full "
                       "control and credential theft for lateral movement.",
                confidence=Confidence.MEDIUM,
                remediation="Remove standing administrator rights from user accounts; use separate admin accounts, "
                            "Windows LAPS, and just-in-time elevation.",
                verification="Get-LocalGroupMember -SID S-1-5-32-544",
                severity_rationale="Medium/potential: excessive privilege is a common lateral-movement enabler, "
                                   "but some memberships may be approved.",
                evidence=[ev], references=[cwe(250, "Execution with Unnecessary Privileges")],
                manual_validation_required=True))
        return findings


# --------------------------------------------------------------------------
# Patching
# --------------------------------------------------------------------------

class PatchStatusCheck(WindowsCheck):
    check_id = "WIN-PATCH-001"
    title = "Security update recency"
    description = "Checks when updates were last installed, the Windows Update service and pending reboots."
    timeout_seconds = 180  # Get-HotFix (WMI) can be slow on servers with long update histories
    PS = ("$h=@(Get-HotFix | Select-Object HotFixID,Description,@{n='InstalledOn';e={ if($_.InstalledOn)"
          "{$_.InstalledOn.ToString('yyyy-MM-dd')}else{$null} }}); "
          "$v=Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
          "$s=$null; try { $s=[string](Get-Service -Name wuauserv -ErrorAction Stop).StartType } catch {}; "
          "$rb=Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'; "
          "[pscustomobject]@{HotFixes=$h; DisplayVersion=$v.DisplayVersion; Build=$v.CurrentBuildNumber; UBR=$v.UBR; "
          "WuStart=$s; RebootRequired=$rb}")

    def __init__(self, today: date | None = None) -> None:
        self.today = today

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        rows = run_ps(ctx, self.PS, "installed updates", timeout=150)
        d = rows[0] if rows and isinstance(rows[0], dict) else {}
        today = self.today or date.today()
        hotfixes = [h for h in (d.get("HotFixes") or []) if isinstance(h, dict)]
        dates = sorted(datetime.strptime(h["InstalledOn"], "%Y-%m-%d").date() for h in hotfixes
                       if isinstance(h.get("InstalledOn"), str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", h["InstalledOn"]))
        latest = dates[-1] if dates else None
        age = (today - latest).days if latest else None
        build = f"{d.get('Build')}.{d.get('UBR')}" if d.get("Build") else "unknown"
        data = {"os_build": build, "display_version": d.get("DisplayVersion"), "hotfix_count": len(hotfixes),
                "latest_install": latest.isoformat() if latest else None, "days_since_latest": age,
                "windows_update_start_type": d.get("WuStart"), "reboot_required": d.get("RebootRequired"),
                "recent_hotfixes": sorted(hotfixes, key=lambda h: str(h.get("InstalledOn")), reverse=True)[:10]}
        ev = ctx.evidence("Update history", "Get-HotFix; CurrentVersion registry; wuauserv", data)
        ctx.limitation("Offline mode: missing updates are inferred from install dates, not compared with the "
                       "Microsoft update catalogue (Module E adds catalogue data).", "dependency")
        findings = []
        common = dict(component=f"Windows Update (build {build})", evidence=[ev],
                      references=[url("https://msrc.microsoft.com/update-guide", "Microsoft Security Update Guide")])
        if age is None:
            findings.append(ctx.finding(
                self, title="Update installation dates are unavailable", severity=Severity.LOW,
                status=FindingStatus.INCONCLUSIVE,
                description="Get-HotFix returned no install dates, so patch recency cannot be assessed.",
                impact="Missing security updates may go unnoticed.", confidence=Confidence.LOW,
                remediation="Check Settings > Windows Update > Update history, or your patch management console.",
                verification="Get-HotFix | Sort InstalledOn", severity_rationale="Low/inconclusive.",
                manual_validation_required=True, **common))
        elif age > 35:
            sev = Severity.HIGH if age > 90 else Severity.MEDIUM
            findings.append(ctx.finding(
                self, title=f"No updates installed in the last {age} days", severity=sev,
                status=FindingStatus.POTENTIAL,
                description=f"The most recent update was installed on {latest}. Microsoft releases security "
                            "updates monthly, so at least one cumulative update has likely been missed.",
                impact="Publicly known vulnerabilities fixed by missed updates may be exploitable.",
                confidence=Confidence.MEDIUM,
                remediation="Install the latest cumulative update via Windows Update/WSUS/Intune, then reboot.",
                verification=f"Get-HotFix | Sort InstalledOn -Descending | Select -First 1  (build {build}); "
                             "compare the build with the Microsoft release information page.",
                severity_rationale=f"{sev.value.capitalize()}/potential: >35 days implies a missed monthly release, "
                                   ">90 days implies several. Potential because servicing-stack or WSUS-managed "
                                   "installs may not appear in Get-HotFix.",
                manual_validation_required=True, **common))
        if str(d.get("WuStart") or "").lower() == "disabled":
            findings.append(ctx.finding(
                self, title="Windows Update service is disabled", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, description="The wuauserv service start type is Disabled.",
                impact="The system cannot receive updates through Windows Update/WSUS.", confidence=Confidence.HIGH,
                remediation="Set the Windows Update service to Manual (default) unless another patching tool "
                            "deploys updates by other means.",
                verification="Get-Service wuauserv | Select StartType",
                severity_rationale="Medium: breaks the standard patch path.", **common))
        if d.get("RebootRequired") is True:
            findings.append(ctx.finding(
                self, title="A reboot is pending to complete update installation", severity=Severity.LOW,
                status=FindingStatus.CONFIRMED,
                description="Windows Update reports RebootRequired; installed fixes are not active until restart.",
                impact="Vulnerabilities remain exploitable until the reboot.", confidence=Confidence.HIGH,
                remediation="Schedule a reboot in the next maintenance window.",
                verification="Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\"
                             "Auto Update\\RebootRequired'  -> False",
                severity_rationale="Low: fixes are staged and only need a restart.", **common))
        if not findings:
            ctx.note(f"Last update installed {age} day(s) ago (build {build})")
        return findings


# --------------------------------------------------------------------------
# BitLocker
# --------------------------------------------------------------------------

class BitLockerCheck(WindowsCheck):
    check_id = "WIN-BL-001"
    title = "BitLocker drive encryption"
    description = "Checks that the operating system volume (and fixed data volumes) are encrypted."
    requires_admin = True
    admin_reason = "BitLocker volume status (Get-BitLockerVolume) is only readable by administrators."
    PS = ("if(-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) "
          "{ [pscustomobject]@{Available=$false} } else { Get-BitLockerVolume | Select-Object MountPoint,"
          "@{n='VolumeType';e={[string]$_.VolumeType}},@{n='VolumeStatus';e={[string]$_.VolumeStatus}},"
          "@{n='ProtectionStatus';e={[string]$_.ProtectionStatus}},"
          "@{n='EncryptionMethod';e={[string]$_.EncryptionMethod}},EncryptionPercentage }")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        rows = [r for r in run_ps(ctx, self.PS, "BitLocker status") if isinstance(r, dict)]
        ev = ctx.evidence("BitLocker volumes", "Get-BitLockerVolume", rows)
        workstation = not ctx.os_info.is_server
        sev_os = Severity.HIGH if workstation else Severity.MEDIUM
        refs = [cwe(311, "Missing Encryption of Sensitive Data")]
        if rows and rows[0].get("Available") is False:
            return [ctx.finding(
                self, title="BitLocker is not available on this system", severity=Severity.LOW if not workstation
                else Severity.MEDIUM, status=FindingStatus.POTENTIAL, component="Disk encryption",
                description="The BitLocker module is not installed (common on Windows Server without the "
                            "BitLocker feature).",
                impact="If no other encryption is used, data on stolen or decommissioned disks is readable.",
                confidence=Confidence.MEDIUM,
                remediation="Install the BitLocker feature and encrypt volumes, or document alternative encryption "
                            "(hypervisor/SAN/self-encrypting drives).",
                verification="Confirm the encryption method with the platform owner.",
                severity_rationale="Potential: other encryption layers may exist; physical access is required.",
                evidence=[ev], references=refs, manual_validation_required=True)]
        findings = []
        for v in rows:
            protected = str(v.get("ProtectionStatus", "")).lower() == "on"
            is_os = str(v.get("VolumeType", "")).lower() == "operatingsystem"
            if not protected:
                sev = sev_os if is_os else Severity.LOW
                suspended = str(v.get("VolumeStatus", "")).lower() == "fullyencrypted"
                findings.append(ctx.finding(
                    self, title=f"Volume {v.get('MountPoint')} is not protected by BitLocker"
                                + (" (protection suspended)" if suspended else ""),
                    severity=sev, status=FindingStatus.CONFIRMED,
                    component=f"{'OS' if is_os else 'Data'} volume {v.get('MountPoint')}",
                    description=f"BitLocker protection is off (VolumeStatus {v.get('VolumeStatus')}, "
                                f"{v.get('EncryptionPercentage')}% encrypted).",
                    impact="Anyone with physical access to the disk can read its data offline.",
                    confidence=Confidence.HIGH,
                    remediation="Enable BitLocker with a TPM protector and escrow recovery keys to AD/Entra ID; "
                                "resume protection if suspended (Resume-BitLocker, run by an administrator).",
                    verification=f"manage-bde -status {v.get('MountPoint')}  -> Protection On",
                    severity_rationale=f"{sev.value.capitalize()}: requires physical access; laptops/workstations "
                                       "are at greater theft risk than data-centre servers; data volumes rated Low.",
                    evidence=[ev], references=refs))
            elif str(v.get("EncryptionMethod", "")).lower() in ("aes128", "aes256"):
                findings.append(ctx.finding(
                    self, title=f"Volume {v.get('MountPoint')} uses legacy AES-CBC BitLocker encryption",
                    severity=Severity.LOW, status=FindingStatus.CONFIRMED, component=f"Volume {v.get('MountPoint')}",
                    description=f"EncryptionMethod is {v.get('EncryptionMethod')} (CBC without diffuser).",
                    impact="Weaker resistance to ciphertext manipulation than XTS-AES.", confidence=Confidence.HIGH,
                    remediation="Re-encrypt with XTS-AES 128/256 when convenient.",
                    verification="Get-BitLockerVolume | Select MountPoint,EncryptionMethod",
                    severity_rationale="Low: data remains encrypted.",
                    evidence=[ev], references=[cwe(326, "Inadequate Encryption Strength")]))
        if not findings:
            ctx.note("All BitLocker volumes are protected")
        return findings


# --------------------------------------------------------------------------
# Services
# --------------------------------------------------------------------------

def unquoted_service_path(path: str) -> str | None:
    """Return the executable part of an unquoted path containing spaces, else None."""
    p = (path or "").strip()
    if not p or p.startswith('"'):
        return None
    m = re.search(r"\.exe\b", p, re.IGNORECASE)
    if not m:
        return None
    exe = p[: m.end()]
    if " " not in exe:
        return None
    return exe


RISKY_WINDOWS_SERVICES = {
    "tlntsvr": (Severity.HIGH, "Telnet server provides cleartext remote shell access."),
    "remoteregistry": (Severity.LOW, "Remote Registry allows remote reading of registry data by "
                                     "authenticated users."),
    "simptcp": (Severity.LOW, "Simple TCP/IP Services (echo, chargen...) are obsolete and abusable for "
                              "amplification."),
    "ftpsvc": (Severity.LOW, "IIS FTP may transmit credentials in cleartext unless FTPS is enforced."),
    "snmp": (Severity.LOW, "SNMP v1/v2c uses cleartext community strings."),
}


class ServicesCheck(WindowsCheck):
    check_id = "WIN-SVC-001"
    title = "Risky services and unquoted service paths"
    description = "Flags risky running services and services with unquoted executable paths (CWE-428)."
    PS = "Get-CimInstance -ClassName Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        services = [s for s in run_ps(ctx, self.PS, "services") if isinstance(s, dict)]
        findings = []
        for svc in services:
            name = str(svc.get("Name", ""))
            key = name.lower()
            running = str(svc.get("State", "")).lower() == "running" or str(svc.get("StartMode", "")).lower() == "auto"
            risk = RISKY_WINDOWS_SERVICES.get(key)
            if key == "spooler" and ctx.os_info.is_server:
                risk = (Severity.LOW, "The Print Spooler has a history of critical flaws (e.g. PrintNightmare "
                                      "CVE-2021-34527); Microsoft advises disabling it on servers that do not print, "
                                      "especially domain controllers.")
            if risk and running:
                sev, why = risk
                findings.append(ctx.finding(
                    self, title=f"Service '{svc.get('DisplayName') or name}' is running/automatic", severity=sev,
                    status=FindingStatus.POTENTIAL, component=f"Service {name}",
                    description=why, impact="Unneeded services increase the attack surface.",
                    confidence=Confidence.MEDIUM,
                    remediation=f"If '{name}' is not required for this system's role, set it to Disabled via Group "
                                "Policy or your configuration management (Services > Startup type = Disabled).",
                    verification=f"Get-Service {name} | Select Status,StartType",
                    severity_rationale=f"{sev.value.capitalize()}/potential: the service may be required; risk "
                                       "depends on exposure and configuration.",
                    evidence=[ctx.evidence("Service configuration", "Win32_Service", svc)],
                    references=[cwe(1188, "Initialization of a Resource with an Insecure Default")],
                    manual_validation_required=True))
            exe = unquoted_service_path(str(svc.get("PathName") or ""))
            if exe and not exe.lower().startswith(("c:\\windows\\",)):
                findings.append(ctx.finding(
                    self, title=f"Unquoted service path: {name}", severity=Severity.MEDIUM,
                    status=FindingStatus.POTENTIAL, component=f"Service {name} ({svc.get('StartName')})",
                    description=f"The service executable path '{exe}' contains spaces and is not quoted, so Windows "
                                "tries each space-separated prefix as a program (e.g. C:\\Program.exe).",
                    impact="If any parent directory is writable by non-administrators, an attacker can plant an "
                           "executable that runs with the service account's privileges (often SYSTEM).",
                    confidence=Confidence.MEDIUM,
                    remediation="Quote the ImagePath value in HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
                                f"{name} (or reinstall/update the vendor software).",
                    verification=f"Get-CimInstance Win32_Service | Where Name -eq '{name}' | Select PathName -> "
                                 "the path starts with a quote; icacls on each parent folder shows no write "
                                 "access for Users.",
                    severity_rationale="Medium/potential: privilege escalation only if a parent folder is writable "
                                       "by non-admins; WIN-PERM-001 checks binary ACLs.",
                    evidence=[ctx.evidence("Service path", "Win32_Service.PathName",
                                           {"PathName": svc.get("PathName"), "StartName": svc.get("StartName")})],
                    references=[cwe(428, "Unquoted Search Path or Element")], manual_validation_required=True))
        if not findings:
            ctx.note(f"{len(services)} services reviewed; no risky services or unquoted paths")
        return findings


class ServiceBinaryPermissionsCheck(WindowsCheck):
    check_id = "WIN-PERM-001"
    title = "Service executable permissions"
    description = "Checks whether non-administrators can modify executables run by services."
    timeout_seconds = 300  # one ACL read per service binary
    PS = ("$risky='S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4'; $out=@(); "
          "Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName } | ForEach-Object { "
          "$svc=$_.Name; $pn=$_.PathName.Trim(); "
          "if($pn.Substring(0,1) -eq [string][char]34){ $e=$pn.IndexOf([char]34,1); if($e -lt 1){ return }; "
          "$exe=$pn.Substring(1,$e-1) } else { $i=$pn.ToLower().IndexOf('.exe'); if($i -lt 0){ return }; "
          "$exe=$pn.Substring(0,$i+4) }; "
          "if(Test-Path -LiteralPath $exe){ $acl=Get-Acl -LiteralPath $exe; foreach($a in $acl.Access){ "
          "try { $sid=$a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } "
          "catch { continue }; $r=$a.FileSystemRights.ToString(); "
          "if(($risky -contains $sid) -and ([string]$a.AccessControlType -eq 'Allow') -and "
          "($r -match 'FullControl|Modify|(^|, )Write(,|$)|WriteData|AppendData|ChangePermissions|TakeOwnership')){ "
          "$out+=[pscustomobject]@{Service=$svc;Path=$exe;Identity=$a.IdentityReference.Value;Sid=$sid;Rights=$r} } } } }; "
          "$out")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        rows = [r for r in run_ps(ctx, self.PS, "service binary ACLs", timeout=180) if isinstance(r, dict)]
        findings = []
        by_path: dict[str, list[dict]] = {}
        for r in rows:
            by_path.setdefault(str(r.get("Path")), []).append(r)
        for path, aces in sorted(by_path.items()):
            services = sorted({str(a.get("Service")) for a in aces})
            findings.append(ctx.finding(
                self, title=f"Non-administrators can modify service executable {path}", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, component="Services: " + ", ".join(services),
                description="The file ACL grants write/modify rights to "
                            + ", ".join(sorted({str(a.get('Identity')) for a in aces})) + ".",
                impact="Any local user can replace the executable and gain the service account's privileges "
                       "(commonly SYSTEM) at the next service start.",
                confidence=Confidence.HIGH,
                remediation="Remove write permissions for Everyone/Users/Authenticated Users/Interactive "
                            "(icacls \"<path>\" /remove:g ..., run by an administrator) and contact the vendor.",
                verification=f"icacls \"{path}\"  -> only Administrators/SYSTEM/TrustedInstaller have write access",
                severity_rationale="High: a reliable local privilege-escalation path, directly observed in the ACL.",
                evidence=[ctx.evidence("Risky access control entries", "Get-Acl", aces)],
                references=[cwe(732, "Incorrect Permission Assignment for Critical Resource")]))
        if not findings:
            ctx.note("No service executables are writable by non-administrators")
        return findings


# --------------------------------------------------------------------------
# Credential protection / LSA
# --------------------------------------------------------------------------

class CredentialProtectionCheck(WindowsCheck):
    check_id = "WIN-LSA-001"
    title = "Credential protection settings (LSA, NTLM, WDigest, LLMNR)"
    description = "Checks settings that protect credentials in memory and on the network."
    SPEC = {
        "lsa": (HKLM + "\\Control\\Lsa", ["RunAsPPL", "LmCompatibilityLevel", "NoLMHash", "RestrictAnonymousSAM",
                                          "LsaCfgFlags"]),
        "wd": (HKLM + "\\Control\\SecurityProviders\\WDigest", ["UseLogonCredential"]),
        "dns": ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", ["EnableMulticast"]),
    }

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        r = read_registry(ctx, self.SPEC, "LSA settings")
        v = {k: as_int(val) for k, val in r.items()}
        ev = ctx.evidence("Credential protection registry values (missing = Windows default)", "registry", v)
        findings = []

        def add(title, sev, status, desc, impact, fix, check, rationale, refs, manual=False):
            findings.append(ctx.finding(
                self, title=title, severity=sev, status=status, component="Local Security Authority",
                description=desc, impact=impact, confidence=Confidence.HIGH if not manual else Confidence.MEDIUM,
                remediation=fix, verification=check, severity_rationale=rationale, evidence=[ev], references=refs,
                manual_validation_required=manual))

        if v.get("wd.UseLogonCredential") == 1:
            add("WDigest stores credentials in clear text in memory", Severity.HIGH, FindingStatus.CONFIRMED,
                "UseLogonCredential = 1 makes LSASS keep reversible copies of logon passwords.",
                "Anyone who dumps LSASS memory (e.g. after a malware infection) obtains plaintext passwords.",
                "Set HKLM\\...\\SecurityProviders\\WDigest\\UseLogonCredential = 0 (MS Security Guide: WDigest "
                "Authentication = Disabled).", "UseLogonCredential = 0 or absent",
                "High: directly exposes passwords to a common post-exploitation technique.",
                [cwe(522, "Insufficiently Protected Credentials"),
                 baseline("WDigest Authentication = Disabled", MS_BASELINE)])
        lm = v.get("lsa.LmCompatibilityLevel")
        if lm is not None and lm < 3:
            add(f"LAN Manager authentication level allows LM/NTLMv1 (level {lm})", Severity.HIGH,
                FindingStatus.CONFIRMED, "The host sends LM or NTLMv1 responses, which can be cracked or relayed easily.",
                "Captured authentication can be cracked to recover passwords or NTLM hashes.",
                "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM "
                "& NTLM' (5) after confirming legacy compatibility.", "LmCompatibilityLevel = 5",
                "High: NTLMv1/LM are cryptographically broken.",
                [cwe(327, "Use of a Broken or Risky Cryptographic Algorithm"),
                 baseline("Network security: LAN Manager authentication level = Send NTLMv2 response only. "
                          "Refuse LM & NTLM", MS_BASELINE)])
        elif lm in (3, 4):
            add(f"LAN Manager authentication level is {lm} (baseline is 5)", Severity.LOW, FindingStatus.CONFIRMED,
                "The host sends NTLMv2 only but, as a server, still accepts LM/NTLMv1 responses.",
                "Legacy clients can authenticate with weak protocols.", "Set LmCompatibilityLevel to 5.",
                "LmCompatibilityLevel = 5", "Low: outgoing authentication is already NTLMv2.",
                [baseline("Network security: LAN Manager authentication level = 5", MS_BASELINE)])
        if v.get("lsa.NoLMHash") == 0:
            add("LM password hashes are stored", Severity.MEDIUM, FindingStatus.CONFIRMED,
                "NoLMHash = 0: Windows stores LM hashes on password change.",
                "LM hashes are trivially crackable if the SAM/AD database is stolen.",
                "Set 'Network security: Do not store LAN Manager hash value on next password change' = Enabled, "
                "then have users change passwords.", "NoLMHash = 1",
                "Medium: requires prior theft of the credential database.",
                [cwe(916, "Use of Password Hash With Insufficient Computational Effort")])
        if v.get("lsa.RunAsPPL") not in (1, 2):
            add("LSA protection (RunAsPPL) is not configured", Severity.LOW, FindingStatus.POTENTIAL,
                "LSASS is not configured to run as a protected process. (New Windows 11 22H2+ installs may enable "
                "it automatically; verify with the event log.)",
                "Credential-dumping tools can read LSASS memory once an attacker has administrator rights.",
                "Enable 'Configure LSASS to run as a protected process' (Administrative Templates > System > "
                "Local Security Authority) after testing driver/plug-in compatibility.",
                "RunAsPPL = 1 or 2; Event ID 12 (Wininit) at boot confirms LSA protection.",
                "Low/potential: hardening against post-exploitation; requires admin access first.",
                [baseline("Configure LSASS to run as a protected process = Enabled", MS_BASELINE)], manual=True)
        if v.get("lsa.RestrictAnonymousSAM") == 0:
            add("Anonymous enumeration of SAM accounts is allowed", Severity.MEDIUM, FindingStatus.CONFIRMED,
                "RestrictAnonymousSAM = 0 lets anonymous users list local accounts.",
                "Attackers learn valid account names for password spraying.",
                "Set 'Network access: Do not allow anonymous enumeration of SAM accounts' = Enabled.",
                "RestrictAnonymousSAM = 1", "Medium: information disclosure that aids targeted attacks.",
                [cwe(200, "Exposure of Sensitive Information to an Unauthorized Actor")])
        if v.get("dns.EnableMulticast") != 0:
            add("LLMNR name resolution is not disabled", Severity.LOW, FindingStatus.POTENTIAL,
                "The 'Turn off multicast name resolution' policy is not enabled (Windows default: LLMNR on).",
                "Attackers on the local network can answer LLMNR queries and capture NTLM authentication "
                "(poisoning/relay).",
                "Enable 'Turn off multicast name resolution' (Administrative Templates > Network > DNS Client) and "
                "disable NetBIOS over TCP/IP where possible.", "EnableMulticast = 0 under the DNSClient policy key",
                "Low/potential: requires a local network attacker; impact grows if SMB signing is not required.",
                [cwe(300, "Channel Accessible by Non-Endpoint")], manual=True)
        if not findings:
            ctx.note("Credential protection settings meet the baseline")
        return findings


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------

class SchannelProtocolsCheck(WindowsCheck):
    check_id = "WIN-TLS-001"
    title = "Legacy SSL/TLS protocols (SCHANNEL)"
    description = "Flags SSL 2.0/3.0 and TLS 1.0/1.1 explicitly enabled for server use."
    PROTOCOLS = {"SSL 2.0": Severity.HIGH, "SSL 3.0": Severity.HIGH, "TLS 1.0": Severity.MEDIUM,
                 "TLS 1.1": Severity.MEDIUM}
    BASE = HKLM + "\\Control\\SecurityProviders\\SCHANNEL\\Protocols"

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        spec = {p.replace(" ", "_"): (f"{self.BASE}\\{p}\\Server", ["Enabled", "DisabledByDefault"])
                for p in self.PROTOCOLS}
        r = read_registry(ctx, spec, "SCHANNEL protocol settings")
        findings, explicit_off = [], []
        for proto, sev in self.PROTOCOLS.items():
            enabled = as_int(r.get(f"{proto.replace(' ', '_')}.Enabled"))
            if enabled is None:
                continue
            if enabled != 0:
                findings.append(ctx.finding(
                    self, title=f"{proto} is explicitly enabled for server connections", severity=sev,
                    status=FindingStatus.CONFIRMED, component=f"SCHANNEL {proto}",
                    description=f"SCHANNEL\\Protocols\\{proto}\\Server\\Enabled = {enabled}. Services using "
                                "Windows TLS (IIS, RDP, WinRM, SQL Server...) may negotiate this protocol.",
                    impact="Deprecated protocols are vulnerable to downgrade and decryption attacks "
                           "(e.g. POODLE, BEAST).",
                    confidence=Confidence.HIGH,
                    remediation=f"Set Enabled = 0 and DisabledByDefault = 1 for {proto} (Server and Client), "
                                "test application compatibility, then reboot.",
                    verification=f"Scan the service with a TLS scanner (Module D) to confirm {proto} is refused.",
                    severity_rationale=f"{sev.value.capitalize()}: SSL is broken; TLS 1.0/1.1 are deprecated "
                                       "(RFC 8996).",
                    evidence=[ctx.evidence("SCHANNEL registry", "registry", r)],
                    references=[cwe(327, "Use of a Broken or Risky Cryptographic Algorithm"),
                                url("https://datatracker.ietf.org/doc/html/rfc8996", "RFC 8996")]))
            else:
                explicit_off.append(proto)
        if not findings:
            ctx.note("No legacy protocol explicitly enabled (unset protocols follow the OS default; "
                     f"explicitly disabled: {', '.join(explicit_off) or 'none'})")
        return findings


class MachineCertificatesCheck(WindowsCheck):
    check_id = "WIN-TLS-002"
    title = "Machine certificate validity"
    description = "Checks certificates with private keys in LocalMachine\\My for expiry and weak algorithms."
    PS = ("Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.HasPrivateKey } | Select-Object "
          "Subject,Issuer,Thumbprint,@{n='NotAfter';e={$_.NotAfter.ToString('yyyy-MM-dd')}},"
          "@{n='SigAlg';e={$_.SignatureAlgorithm.FriendlyName}},"
          "@{n='KeyBits';e={ try { $_.PublicKey.Key.KeySize } catch { $null } }},"
          "@{n='KeyAlg';e={$_.PublicKey.Oid.FriendlyName}}")

    def __init__(self, today: date | None = None) -> None:
        self.today = today

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        rows = [r for r in run_ps(ctx, self.PS, "machine certificates") if isinstance(r, dict)]
        certs = []
        for r in rows:
            try:
                not_after = datetime.strptime(str(r.get("NotAfter")), "%Y-%m-%d").date()
            except ValueError:
                continue
            certs.append({"subject": r.get("Subject"), "issuer": r.get("Issuer"), "not_after": not_after,
                          "signature_algorithm": str(r.get("SigAlg") or ""), "key_bits": as_int(r.get("KeyBits")),
                          "key_type": str(r.get("KeyAlg") or ""), "source": f"Cert:\\LocalMachine\\My\\{r.get('Thumbprint')}"})
        findings = evaluate_certificates(ctx, self, certs, self.today)
        if not findings:
            ctx.note(f"{len(certs)} machine certificate(s) valid with acceptable algorithms")
        return findings


# --------------------------------------------------------------------------
# Audit policy
# --------------------------------------------------------------------------

# Subcategory GUID -> (name, required bits: 1=success, 2=failure)
AUDIT_REQUIREMENTS = {
    "{0CCE923F-69AE-11D9-BED3-505054503030}": ("Credential Validation", 3),
    "{0CCE9235-69AE-11D9-BED3-505054503030}": ("User Account Management", 3),
    "{0CCE9237-69AE-11D9-BED3-505054503030}": ("Security Group Management", 1),
    "{0CCE9215-69AE-11D9-BED3-505054503030}": ("Logon", 3),
    "{0CCE9217-69AE-11D9-BED3-505054503030}": ("Account Lockout", 2),
    "{0CCE921B-69AE-11D9-BED3-505054503030}": ("Special Logon", 1),
    "{0CCE922F-69AE-11D9-BED3-505054503030}": ("Audit Policy Change", 1),
    "{0CCE922B-69AE-11D9-BED3-505054503030}": ("Process Creation", 1),
}
_INCLUSION_TEXT = {"no auditing": 0, "success": 1, "failure": 2, "success and failure": 3}


def parse_auditpol_csv(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
    for row in reader:
        guid = (row.get("Subcategory GUID") or "").strip().upper()
        if not guid:
            continue
        value = as_int((row.get("Setting Value") or "").strip())
        if value is None:
            value = _INCLUSION_TEXT.get((row.get("Inclusion Setting") or "").strip().lower())
        if value is not None:
            out[guid] = value
    return out


class AuditPolicyCheck(WindowsCheck):
    check_id = "WIN-AUDIT-001"
    title = "Security audit policy"
    description = "Checks that key security events (logons, account changes, process creation) are audited."
    requires_admin = True
    admin_reason = "auditpol /get requires an elevated session."
    required_tools = ("auditpol",)

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        res = ctx.runner.run(["auditpol", "/get", "/category:*", "/r"])
        if not res.ok:
            raise SkipCheck(f"auditpol failed: {res.error_detail or res.stderr.strip()[:200]}")
        settings = parse_auditpol_csv(res.stdout)
        if not settings:
            raise SkipCheck("auditpol output could not be parsed.", "error")
        gaps = []
        for guid, (name, required) in AUDIT_REQUIREMENTS.items():
            have = settings.get(guid, 0)
            if have & required != required:
                gaps.append({"subcategory": name, "configured": have, "required": required})
        if not gaps:
            ctx.note("All key audit subcategories are enabled")
            return []
        label = {0: "No Auditing", 1: "Success", 2: "Failure", 3: "Success and Failure"}
        return [ctx.finding(
            self, title=f"{len(gaps)} key audit subcategories are not fully audited", severity=Severity.MEDIUM,
            status=FindingStatus.CONFIRMED, component="Advanced Audit Policy",
            description="Missing: " + "; ".join(f"{g['subcategory']} (has {label[g['configured']]}, needs "
                                                f"{label[g['required']]})" for g in gaps),
            impact="Attacks such as password guessing, account creation or malicious process execution may leave "
                   "no trace in the Security log, hindering detection and investigation.",
            confidence=Confidence.HIGH,
            remediation="Configure Advanced Audit Policy via Group Policy (Computer Configuration > Windows Settings "
                        "> Security Settings > Advanced Audit Policy Configuration) per the Microsoft baseline, and "
                        "forward Security logs to your SIEM.",
            verification="auditpol /get /category:*", severity_rationale="Medium: reduces detection capability; "
                                                                         "does not by itself enable compromise.",
            evidence=[ctx.evidence("Audit gaps", "auditpol /get /category:* /r", gaps)],
            references=[cwe(778, "Insufficient Logging"),
                        baseline("Advanced Audit Policy Configuration", MS_BASELINE)])]


def build_module() -> Module:
    return Module(
        module_id="windows_audit",
        name="B. Windows security audit",
        description="Firewall, antivirus, SMB, RDP, UAC, accounts, patching, BitLocker, services, permissions, "
                    "credential protection, TLS and audit policy.",
        category="local",
        checks=[FirewallProfilesCheck(), DefenderCheck(), SmbCheck(), RdpCheck(), UacCheck(), PasswordPolicyCheck(),
                LocalAccountsCheck(), LocalAdminsCheck(), PatchStatusCheck(), BitLockerCheck(), ServicesCheck(),
                ServiceBinaryPermissionsCheck(), CredentialProtectionCheck(), SchannelProtocolsCheck(),
                MachineCertificatesCheck(), AuditPolicyCheck()],
    )

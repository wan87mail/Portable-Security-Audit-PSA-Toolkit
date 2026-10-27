"""Module C: Linux security audit (read-only).

Configuration is read through :class:`~psatoolkit.core.hostfs.HostFS`; the
few commands used are allow-listed read-only queries (``sshd -T``, ``ufw
status``, ``nft list ruleset``, ``apt list --upgradable``, ``lsblk``,
``systemctl list-units``, ``openssl x509``). The toolkit never runs ``apt
update`` (it writes the package cache) or changes any configuration.

Secrets: ``/etc/shadow`` is read only to derive per-account flags (empty or
weakly hashed password); hash values are never stored, logged or reported.
"""

from __future__ import annotations

import json
import os
import re
import stat as st
import time
from datetime import date, datetime
from fnmatch import fnmatch
from typing import Any, Callable

from psatoolkit.core.engine import AssessmentContext, Check, Module, SkipCheck
from psatoolkit.core.hostfs import HostFS
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Severity
from psatoolkit.modules._common import CIS_UBUNTU, baseline, cwe, mode_str, parse_kv_lines, url
from psatoolkit.modules.certificates import evaluate_certificates

LINUX = frozenset({"linux"})


class LinuxCheck(Check):
    supported_os = LINUX


# --------------------------------------------------------------------------
# Patch status
# --------------------------------------------------------------------------

def parse_apt_upgradable(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\S+?)/(\S+)\s+(\S+)\s+(\S+)(?:\s+\[upgradable from: ([^\]]+)\])?", line.strip())
        if not m:
            continue
        suites = m.group(2).split(",")
        out.append({"package": m.group(1), "suites": suites, "candidate": m.group(3),
                    "installed": m.group(5), "security": any(s.endswith("-security") for s in suites)})
    return out


class PatchStatusCheck(LinuxCheck):
    check_id = "LNX-PATCH-001"
    title = "Pending security updates"
    description = "Uses the local package manager cache to list pending (security) updates."
    STALE_CACHE_DAYS = 7

    def __init__(self, now: Callable[[], float] = time.time) -> None:
        self.now = now

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        if ctx.runner.is_available("apt"):
            findings = self._apt(ctx)
        elif ctx.runner.is_available("dnf"):
            findings = self._dnf(ctx)
        else:
            raise SkipCheck("No supported package manager (apt or dnf) is available.", "dependency")
        if ctx.fs.exists("/var/run/reboot-required") or ctx.fs.exists("/run/reboot-required"):
            pkgs = (ctx.fs.try_read("/run/reboot-required.pkgs")[0] or "").split()
            findings.append(ctx.finding(
                self, title="A reboot is required to activate installed updates", severity=Severity.LOW,
                status=FindingStatus.CONFIRMED, component="System updates",
                description="The system reports /run/reboot-required" +
                            (f" for: {', '.join(sorted(set(pkgs))[:20])}." if pkgs else "."),
                impact="Updated kernels/libraries are not in use until the reboot, so the fixed vulnerabilities "
                       "remain exploitable.", confidence=Confidence.HIGH,
                remediation="Reboot during the next maintenance window (or use live patching for the kernel).",
                verification="ls /run/reboot-required  -> No such file",
                severity_rationale="Low: updates are already installed; only a restart is outstanding.",
                evidence=[ctx.evidence("Reboot marker", "/run/reboot-required", {"packages": pkgs})]))
        return findings

    def _cache_age_days(self, ctx: AssessmentContext) -> float | None:
        for path in ("/var/lib/apt/periodic/update-success-stamp", "/var/cache/apt/pkgcache.bin",
                     "/var/lib/apt/lists"):
            s = ctx.fs.lstat(path)
            if s:
                return (self.now() - s.st_mtime) / 86400
        return None

    def _apt(self, ctx: AssessmentContext) -> list[Finding]:
        res = ctx.runner.run(["apt", "list", "--upgradable"])
        if not res.ok:
            raise SkipCheck(f"'apt list --upgradable' failed: {res.error_detail or res.stderr.strip()[:200]}")
        pkgs = parse_apt_upgradable(res.stdout)
        security = [p for p in pkgs if p["security"]]
        age = self._cache_age_days(ctx)
        stale = age is not None and age > self.STALE_CACHE_DAYS
        if stale:
            ctx.limitation(f"Package lists were last refreshed {age:.0f} days ago; the toolkit does not run "
                           "'apt update' (it modifies the system), so newer updates may be missing.", "dependency")
        auto, _ = ctx.fs.try_read("/etc/apt/apt.conf.d/20auto-upgrades")
        auto_on = bool(auto and re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', auto))
        data = {"upgradable": len(pkgs), "security": len(security), "cache_age_days": round(age, 1) if age else None,
                "unattended_upgrades": auto_on, "packages": pkgs[:200]}
        ev = ctx.evidence("Pending updates (from the local package cache)", "apt list --upgradable", data)
        findings = []
        refs = [url("https://ubuntu.com/security/notices", "Ubuntu Security Notices")]
        if security:
            sev = Severity.HIGH if len(security) >= 10 else Severity.MEDIUM
            findings.append(ctx.finding(
                self, title=f"{len(security)} security update(s) pending", severity=sev,
                status=FindingStatus.CONFIRMED, component="APT packages",
                description="Updates from the -security pocket are available but not installed: "
                            + ", ".join(p["package"] for p in security[:15]) + ("..." if len(security) > 15 else ""),
                impact="The installed package versions contain vulnerabilities fixed by these updates; some may "
                       "be remotely exploitable.", confidence=Confidence.HIGH if not stale else Confidence.MEDIUM,
                remediation="Apply updates in a maintenance window: sudo apt update && sudo apt upgrade (or via "
                            "Landscape/your patch tool). Review Ubuntu Security Notices for urgency.",
                verification="apt list --upgradable 2>/dev/null | grep -c -- -security  -> 0",
                severity_rationale=f"{sev.value.capitalize()}: pending security fixes are confirmed by the package "
                                   "manager; 10 or more suggests patching is not occurring. Individual CVE "
                                   "exploitability is assessed in Module E.",
                evidence=[ev], references=refs))
        elif stale:
            findings.append(ctx.finding(
                self, title=f"Package information is {age:.0f} days old; patch status is uncertain",
                severity=Severity.LOW, status=FindingStatus.INCONCLUSIVE, component="APT package cache",
                description="No pending security updates are listed, but the package lists have not been refreshed "
                            f"for {age:.0f} days.", impact="Missing updates may go unnoticed.",
                confidence=Confidence.LOW, remediation="Ensure 'apt update' runs regularly (unattended-upgrades or "
                                                       "patch management) and re-run this assessment.",
                verification="stat /var/lib/apt/periodic/update-success-stamp",
                severity_rationale="Low/inconclusive: stale data, not a confirmed gap.",
                evidence=[ev], references=refs, manual_validation_required=True))
        if not auto_on:
            findings.append(ctx.finding(
                self, title="Automatic security updates are not enabled", severity=Severity.LOW,
                status=FindingStatus.POTENTIAL, component="unattended-upgrades",
                description="/etc/apt/apt.conf.d/20auto-upgrades does not enable Unattended-Upgrade.",
                impact="Security fixes depend entirely on manual patching.", confidence=Confidence.MEDIUM,
                remediation="Enable unattended-upgrades (sudo dpkg-reconfigure -plow unattended-upgrades) or "
                            "document the alternative patch process.",
                verification="cat /etc/apt/apt.conf.d/20auto-upgrades",
                severity_rationale="Low/potential: acceptable when centralized patch management exists.",
                evidence=[ev], references=[baseline("Ensure updates, patches, and additional security software "
                                                    "are installed", CIS_UBUNTU)], manual_validation_required=True))
        if not findings:
            ctx.note(f"No pending security updates ({len(pkgs)} non-security update(s))")
        return findings

    def _dnf(self, ctx: AssessmentContext) -> list[Finding]:
        res = ctx.runner.run(["dnf", "-q", "--cacheonly", "check-update"])
        if res.error or res.timed_out or res.returncode not in (0, 100):
            raise SkipCheck("'dnf check-update' failed (the local metadata cache may be empty).")
        updates = [l for l in res.stdout.splitlines() if len(l.split()) == 3]
        sec = ctx.runner.run(["dnf", "-q", "--cacheonly", "updateinfo", "list", "--security"])
        security = [l for l in sec.stdout.splitlines() if l.strip()] if sec.ok else []
        ev = ctx.evidence("Pending updates (cache only)", "dnf --cacheonly check-update / updateinfo",
                          {"updates": len(updates), "security_advisories": security[:100]})
        if not security:
            ctx.note(f"No pending security advisories ({len(updates)} update(s) pending)")
            return []
        sev = Severity.HIGH if len(security) >= 10 else Severity.MEDIUM
        return [ctx.finding(
            self, title=f"{len(security)} security advisory update(s) pending", severity=sev,
            status=FindingStatus.CONFIRMED, component="DNF packages",
            description="dnf reports security advisories that apply to installed packages.",
            impact="Installed packages contain vulnerabilities fixed by these updates.", confidence=Confidence.MEDIUM,
            remediation="Apply updates in a maintenance window: sudo dnf upgrade --security.",
            verification="dnf updateinfo list --security  -> empty",
            severity_rationale=f"{sev.value.capitalize()}: confirmed by package metadata.", evidence=[ev])]


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------

SSHD_DEFAULTS = {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
                 "permitemptypasswords": "no", "x11forwarding": "no", "maxauthtries": "6"}
WEAK_SSH = {
    "ciphers": ("-cbc", "arcfour", "3des", "blowfish", "cast128"),
    "macs": ("hmac-md5", "hmac-sha1", "umac-64", "hmac-ripemd160"),
    "kexalgorithms": ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                      "diffie-hellman-group-exchange-sha1"),
}


def parse_sshd_config(fs: HostFS, path: str = "/etc/ssh/sshd_config") -> tuple[dict[str, str], list[str], list[str]]:
    """Parse sshd_config like sshd: first value wins, Include is expanded, parsing stops at Match.

    Returns (settings, files_read, files_unreadable).
    """
    settings: dict[str, str] = {}
    read: list[str] = []
    unreadable: list[str] = []
    stopped = [False]

    def parse(file_path: str, depth: int) -> None:
        if depth > 5 or stopped[0]:
            return
        text, err = fs.try_read(file_path)
        if text is None:
            if err != "missing":
                unreadable.append(file_path)
            return
        read.append(file_path)
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = re.split(r"\s+|=", line, maxsplit=1)
            key = parts[0].lower()
            value = parts[1].strip() if len(parts) > 1 else ""
            if key == "match":
                stopped[0] = True
                return
            if key == "include":
                for pattern in value.split():
                    full = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                    directory, base = full.rsplit("/", 1)
                    for inc in sorted(fs.glob(directory, base)) if any(c in base for c in "*?[") else [full]:
                        parse(inc, depth + 1)
                        if stopped[0]:
                            return
                continue
            settings.setdefault(key, value)

    parse(path, 0)
    return settings, read, unreadable


class SshConfigCheck(LinuxCheck):
    check_id = "LNX-SSH-001"
    title = "SSH server configuration"
    description = "Checks root login, password and empty-password authentication, forwarding and algorithms."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        if not ctx.fs.exists("/etc/ssh/sshd_config") and not ctx.fs.exists("/usr/sbin/sshd"):
            ctx.note("OpenSSH server is not installed")
            return []
        source, confidence = "sshd -T (effective configuration)", Confidence.HIGH
        cfg: dict[str, str] = {}
        if ctx.host.elevated and ctx.runner.is_available("sshd"):
            res = ctx.runner.run(["sshd", "-T"])
            if res.ok:
                cfg = parse_kv_lines(res.stdout, comment="")
                cfg = {k.lower(): v for k, v in cfg.items()}
        explicit = set(cfg)
        if not cfg:
            cfg, read, unreadable = parse_sshd_config(ctx.fs)
            explicit = set(cfg)
            source = "sshd_config files: " + ", ".join(read)
            confidence = Confidence.MEDIUM
            if unreadable:
                confidence = Confidence.LOW
                ctx.limitation("Unreadable sshd configuration file(s): " + ", ".join(unreadable) +
                               ". Run as root for the effective configuration (sshd -T).", "privilege")
            elif not ctx.host.elevated:
                ctx.limitation("Parsed sshd_config files; 'sshd -T' (needs root) would confirm effective values.",
                               "privilege")
            for k, v in SSHD_DEFAULTS.items():
                cfg.setdefault(k, v)

        def val(key: str) -> str:
            value = cfg.get(key) or SSHD_DEFAULTS.get(key) or ""
            return value.split()[0].lower() if value else ""

        shown = {k: cfg.get(k) for k in ("permitrootlogin", "passwordauthentication", "permitemptypasswords",
                                          "x11forwarding", "maxauthtries", "ciphers", "macs", "kexalgorithms")
                 if k in cfg}
        ev = ctx.evidence("SSH server settings", source, shown)
        findings = []
        status = FindingStatus.CONFIRMED

        def add(title, sev, desc, impact, fix, verify, rationale, refs):
            findings.append(ctx.finding(
                self, title=title, severity=sev, status=status, component="OpenSSH server (sshd)",
                description=desc, impact=impact, confidence=confidence, remediation=fix, verification=verify,
                severity_rationale=rationale, evidence=[ev], references=refs,
                manual_validation_required=confidence == Confidence.LOW))

        verify = "sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords)'"
        if val("permitemptypasswords") == "yes":
            sev = Severity.CRITICAL if val("passwordauthentication") == "yes" else Severity.HIGH
            add("SSH permits login to accounts with empty passwords", sev,
                "PermitEmptyPasswords yes allows password logins for accounts whose password is empty.",
                "Anyone who can reach SSH can log in to such accounts without credentials.",
                "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config(.d) and reload sshd.", verify,
                f"{sev.value.capitalize()}: remote unauthenticated access is possible if any account has an empty "
                "password (see LNX-ACCT-001).",
                [cwe(258, "Empty Password in Configuration File"),
                 baseline("Ensure sshd PermitEmptyPasswords is disabled", CIS_UBUNTU)])
        if val("permitrootlogin") == "yes":
            add("SSH permits direct root login", Severity.HIGH,
                "PermitRootLogin yes allows root to log in with any method, including passwords.",
                "Attackers can target the most privileged account directly, and actions lose individual "
                "accountability.",
                "Set 'PermitRootLogin no' (or 'prohibit-password' if key-based root automation is required) and "
                "use sudo from named accounts.", verify,
                "High: remotely reachable path to full control.",
                [cwe(250, "Execution with Unnecessary Privileges"),
                 baseline("Ensure sshd PermitRootLogin is disabled", CIS_UBUNTU)])
        if val("passwordauthentication") == "yes":
            add("SSH accepts password authentication", Severity.MEDIUM,
                "PasswordAuthentication is yes" + (" (OpenSSH default; not set explicitly)"
                                                   if "passwordauthentication" not in explicit else "") + ".",
                "Passwords can be brute-forced or sprayed over the network; keys or certificates resist this.",
                "Prefer key/certificate authentication: set 'PasswordAuthentication no' after deploying keys, or "
                "enforce MFA and fail2ban-style rate limiting if passwords are required.", verify,
                "Medium: increases exposure to credential attacks; mitigated by strong password policy and "
                "network restrictions.",
                [cwe(307, "Improper Restriction of Excessive Authentication Attempts")])
        if val("x11forwarding") == "yes":
            add("SSH X11 forwarding is enabled", Severity.LOW, "X11Forwarding yes.",
                "A compromised server can attack the X11 display of connecting clients.",
                "Set 'X11Forwarding no' unless required.", "sudo sshd -T | grep x11forwarding",
                "Low: requires users to connect with X11 forwarding.",
                [baseline("Ensure sshd X11Forwarding is disabled", CIS_UBUNTU)])
        tries = val("maxauthtries")
        if tries.isdigit() and int(tries) > 4:
            add(f"SSH MaxAuthTries is {tries}", Severity.LOW, f"Clients may attempt {tries} authentications per "
                                                               "connection.",
                "More password guesses per connection.", "Set 'MaxAuthTries 4' or lower.",
                "sudo sshd -T | grep maxauthtries", "Low: minor brute-force hardening.",
                [baseline("Ensure sshd MaxAuthTries is set to 4 or less", CIS_UBUNTU)])
        for key, bad in WEAK_SSH.items():
            if key not in cfg:
                continue
            weak = [a for a in cfg[key].split(",") if any(b in a.lower() for b in bad)]
            if weak:
                add(f"SSH allows weak {key}: {', '.join(weak)}", Severity.MEDIUM,
                    f"The {key} list contains deprecated algorithms.",
                    "Weak algorithms reduce the protection of SSH sessions against decryption or tampering.",
                    f"Remove {', '.join(weak)} from '{key}' in sshd_config.", f"sudo sshd -T | grep ^{key}",
                    "Medium: deprecated cryptography on a remote access service.",
                    [cwe(327, "Use of a Broken or Risky Cryptographic Algorithm")])
        if not findings:
            ctx.note("SSH configuration meets the checked baseline items")
        return findings


# --------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------

def nft_input_filtering(ruleset: str) -> bool:
    """True if any nftables input-hook chain drops by default or contains rules."""
    for m in re.finditer(r"chain\s+\S+\s*\{(.*?)\n\s*\}", ruleset, re.S):
        body = m.group(1)
        if "hook input" not in body:
            continue
        if re.search(r"policy\s+drop", body):
            return True
        rules = [l.strip() for l in body.splitlines()
                 if l.strip() and not l.strip().startswith(("type ", "policy"))]
        if rules:
            return True
    return False


def iptables_input_filtering(rules: str) -> bool:
    lines = [l.strip() for l in rules.splitlines()]
    return any(l in ("-P INPUT DROP", "-P INPUT REJECT") for l in lines) or any(l.startswith("-A INPUT ") for l in lines)


class FirewallCheck(LinuxCheck):
    check_id = "LNX-FW-001"
    title = "Host firewall status"
    description = "Determines whether ufw, firewalld, nftables or iptables filter inbound traffic."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        details: dict[str, Any] = {}
        active = False
        default_allow = False
        runner = ctx.runner
        if ctx.host.elevated:
            if runner.is_available("ufw"):
                r = runner.run(["ufw", "status", "verbose"])
                if r.ok:
                    details["ufw"] = r.stdout.strip()[:2000]
                    if "Status: active" in r.stdout:
                        active = True
                        default_allow = bool(re.search(r"Default:\s*allow \(incoming\)", r.stdout))
            if runner.is_available("nft"):
                r = runner.run(["nft", "list", "ruleset"])
                if r.ok:
                    details["nft_input_filtering"] = nft_input_filtering(r.stdout)
                    active = active or details["nft_input_filtering"]
            if runner.is_available("iptables"):
                r = runner.run(["iptables", "-S"])
                if r.ok:
                    details["iptables_input_filtering"] = iptables_input_filtering(r.stdout)
                    active = active or details["iptables_input_filtering"]
            confidence, status = Confidence.HIGH, FindingStatus.CONFIRMED
        else:
            ctx.limitation("Firewall rule sets are readable only by root; service state was used instead.",
                           "privilege")
            conf, _ = ctx.fs.try_read("/etc/ufw/ufw.conf")
            details["ufw_conf_enabled"] = bool(conf and re.search(r"^ENABLED=yes", conf, re.M))
            active = details["ufw_conf_enabled"]
            if runner.is_available("systemctl"):
                for unit in ("ufw", "firewalld", "nftables"):
                    r = runner.run(["systemctl", "is-active", unit])
                    details[f"{unit}_service"] = r.stdout.strip() or r.error or "unknown"
                    if unit != "ufw" and r.stdout.strip() == "active":
                        active = True
            confidence, status = Confidence.MEDIUM, FindingStatus.POTENTIAL
        ev = ctx.evidence("Firewall state", "ufw / nft / iptables / systemctl", details)
        if not active:
            return [ctx.finding(
                self, title="No active host firewall was found", severity=Severity.MEDIUM, status=status,
                component="Host firewall", description="Neither ufw, firewalld, nftables nor iptables filters "
                                                       "inbound traffic.",
                impact="Every listening service is reachable from the network; a newly started service is exposed "
                       "immediately.", confidence=confidence,
                remediation="Enable a default-deny inbound firewall, e.g. 'sudo ufw default deny incoming; sudo ufw "
                            "allow OpenSSH; sudo ufw enable' (plan this change so remote access is not lost).",
                verification="sudo ufw status verbose  (or sudo nft list ruleset)",
                severity_rationale="Medium: removes a defence-in-depth layer; network firewalls may still protect "
                                   "the host" + ("" if status == FindingStatus.CONFIRMED
                                                 else "; potential because rule sets require root to read") + ".",
                evidence=[ev], references=[cwe(284, "Improper Access Control"),
                                           baseline("Ensure a single firewall configuration utility is in use",
                                                    CIS_UBUNTU)],
                manual_validation_required=status != FindingStatus.CONFIRMED)]
        if default_allow:
            return [ctx.finding(
                self, title="ufw allows incoming connections by default", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="ufw",
                description="ufw is active but the default incoming policy is allow.",
                impact="Services not covered by explicit rules are reachable.", confidence=Confidence.HIGH,
                remediation="sudo ufw default deny incoming (after adding allow rules for required services).",
                verification="sudo ufw status verbose  -> Default: deny (incoming)",
                severity_rationale="Medium: firewall present but not default-deny.", evidence=[ev],
                references=[baseline("Ensure ufw default deny firewall policy", CIS_UBUNTU)])]
        ctx.note("A host firewall filters inbound traffic")
        return []


# --------------------------------------------------------------------------
# Accounts and privileges
# --------------------------------------------------------------------------

def parse_passwd(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        f = line.split(":")
        if len(f) >= 7 and f[2].lstrip("-").isdigit():
            out.append({"user": f[0], "uid": int(f[2]), "gid": f[3], "home": f[5], "shell": f[6]})
    return out


def parse_group(text: str) -> dict[str, dict[str, Any]]:
    out = {}
    for line in text.splitlines():
        f = line.split(":")
        if len(f) >= 4:
            out[f[0]] = {"gid": f[2], "members": [m for m in f[3].split(",") if m]}
    return out


PRIVILEGED_GROUPS = ("sudo", "wheel", "admin", "root", "docker", "lxd", "disk", "shadow")


class PrivilegedAccountsCheck(LinuxCheck):
    check_id = "LNX-PRIV-001"
    title = "Privileged accounts and groups"
    description = "Finds UID 0 accounts besides root and lists members of privileged groups."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        passwd, err = ctx.fs.try_read("/etc/passwd")
        if passwd is None:
            raise SkipCheck(f"/etc/passwd is not readable ({err}).", "platform")
        users = parse_passwd(passwd)
        groups = parse_group(ctx.fs.try_read("/etc/group")[0] or "")
        privileged = {}
        for g in PRIVILEGED_GROUPS:
            if g in groups:
                members = set(groups[g]["members"]) | {u["user"] for u in users if u["gid"] == groups[g]["gid"]}
                members.discard("root")
                if members:
                    privileged[g] = sorted(members)
        findings = []
        uid0 = [u["user"] for u in users if u["uid"] == 0 and u["user"] != "root"]
        if uid0:
            findings.append(ctx.finding(
                self, title=f"Additional account(s) with UID 0: {', '.join(uid0)}", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, component="/etc/passwd",
                description="These accounts have user ID 0 and therefore full root privileges.",
                impact="Hidden root-equivalent accounts are a classic persistence technique and bypass sudo "
                       "logging and accountability.", confidence=Confidence.HIGH,
                remediation="Investigate who created the account(s); remove them or assign a unique non-zero UID.",
                verification="awk -F: '$3==0' /etc/passwd  -> only root",
                severity_rationale="High: unauthorized full-privilege access, possibly an indicator of compromise.",
                evidence=[ctx.evidence("UID 0 accounts", "/etc/passwd", uid0)],
                references=[cwe(269, "Improper Privilege Management"),
                            baseline("Ensure root is the only UID 0 account", CIS_UBUNTU)]))
        dangerous = {g: m for g, m in privileged.items() if g in ("docker", "lxd", "disk", "shadow")}
        if dangerous:
            findings.append(ctx.finding(
                self, title="Users are members of root-equivalent groups ("
                            + ", ".join(sorted(dangerous)) + ")", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="/etc/group",
                description="Membership of docker/lxd (container control), disk (raw disk access) or shadow "
                            "(password hash access) effectively grants root or credential access: "
                            + "; ".join(f"{g}: {', '.join(m)}" for g, m in dangerous.items()),
                impact="Members can escalate to root without sudo and without audit trail.",
                confidence=Confidence.HIGH,
                remediation="Remove users who do not need these groups; use rootless containers or sudo rules "
                            "with logging instead.",
                verification="getent group docker lxd disk shadow",
                severity_rationale="Medium: requires an existing account but provides a reliable escalation path.",
                evidence=[ctx.evidence("Privileged group membership", "/etc/group", dangerous)],
                references=[cwe(250, "Execution with Unnecessary Privileges")]))
        admins = {g: m for g, m in privileged.items() if g in ("sudo", "wheel", "admin", "root")}
        findings.append(ctx.finding(
            self, title=f"{len({u for m in admins.values() for u in m})} account(s) in administrative groups",
            severity=Severity.INFO, status=FindingStatus.INFORMATIONAL, component="/etc/group",
            description="Administrative group members: " + ("; ".join(f"{g}: {', '.join(m)}" for g, m in admins.items())
                                                            or "none besides root"),
            impact="Members can typically obtain root through sudo.", confidence=Confidence.HIGH,
            remediation="Confirm each member is an approved administrator.", verification="getent group sudo wheel",
            severity_rationale="Informational inventory; sudo rules are reviewed in LNX-SUDO-001.",
            evidence=[ctx.evidence("Privileged groups", "/etc/group", privileged)]))
        return findings


def parse_sudoers(text: str) -> tuple[list[str], list[str]]:
    """Return (rules, defaults) with continuation lines joined and comments removed."""
    text = re.sub(r"\\\n", " ", text)
    rules, defaults = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "@include")) or line.startswith("@"):
            continue
        if re.match(r"^(User|Runas|Host|Cmnd)_Alias\b", line):
            continue
        if line.startswith("Defaults"):
            defaults.append(line)
        elif "=" in line:
            rules.append(line)
    return rules, defaults


class SudoersCheck(LinuxCheck):
    check_id = "LNX-SUDO-001"
    title = "Sudo rules"
    description = "Reviews sudoers for rules granting all users sudo, password-less full root, or no authentication."
    requires_admin = True
    admin_reason = "/etc/sudoers and /etc/sudoers.d are readable only by root (mode 0440)."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        files = ["/etc/sudoers"] + [p for p in ctx.fs.glob("/etc/sudoers.d", "*")
                                    if not p.endswith("~") and "." not in p.rsplit("/", 1)[1]]
        rules: list[tuple[str, str]] = []
        defaults: list[tuple[str, str]] = []
        for f in files:
            text, err = ctx.fs.try_read(f)
            if text is None:
                if err != "missing":
                    ctx.limitation(f"{f} could not be read ({err}).", "privilege")
                continue
            r, d = parse_sudoers(text)
            rules += [(f, x) for x in r]
            defaults += [(f, x) for x in d]
        if not rules and not defaults:
            raise SkipCheck("No sudoers rules could be read.", "privilege")
        findings = []
        all_users = [(f, r) for f, r in rules if r.split()[0] == "ALL"]
        nopasswd_all = [(f, r) for f, r in rules if "NOPASSWD:" in r and re.search(r"(^|[\s:,])ALL\s*$", r)
                        and r.split()[0] != "ALL"]
        no_auth = [(f, d) for f, d in defaults if "!authenticate" in d]
        fmt = lambda items: [{"file": f, "line": l} for f, l in items]  # noqa: E731
        if all_users:
            findings.append(ctx.finding(
                self, title="Sudo rule applies to every user", severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                component="sudoers", description="A rule beginning with 'ALL' lets any account run sudo commands.",
                impact="Any compromised account, including service accounts, can run the permitted commands as root.",
                confidence=Confidence.HIGH, remediation="Restrict sudo rules to named administrators or an admin group.",
                verification="sudo grep -rE '^ALL' /etc/sudoers /etc/sudoers.d",
                severity_rationale="High: collapses the boundary between users and root.",
                evidence=[ctx.evidence("Rules", "sudoers", fmt(all_users))],
                references=[cwe(269, "Improper Privilege Management")]))
        if nopasswd_all:
            findings.append(ctx.finding(
                self, title=f"{len(nopasswd_all)} sudo rule(s) grant full root without a password",
                severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED, component="sudoers",
                description="NOPASSWD rules allow all commands: "
                            + "; ".join(r for _f, r in nopasswd_all[:10]),
                impact="Anyone who gains a shell as these principals (e.g. through a stolen SSH key or a web "
                       "application) becomes root without knowing any password.", confidence=Confidence.HIGH,
                remediation="Require authentication (remove NOPASSWD) or limit NOPASSWD to specific, safe commands "
                            "for automation accounts.",
                verification="sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d",
                severity_rationale="Medium: requires prior account compromise; common on cloud images.",
                evidence=[ctx.evidence("Rules", "sudoers", fmt(nopasswd_all))],
                references=[cwe(306, "Missing Authentication for Critical Function")]))
        if no_auth:
            findings.append(ctx.finding(
                self, title="sudo authentication is disabled by a Defaults entry", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="sudoers",
                description="Defaults !authenticate disables password prompts for matching sudo rules.",
                impact="Same as password-less sudo for every affected rule.", confidence=Confidence.HIGH,
                remediation="Remove '!authenticate' from Defaults.", verification="sudo grep -rn authenticate /etc/sudoers*",
                severity_rationale="Medium: removes re-authentication for privilege use.",
                evidence=[ctx.evidence("Defaults", "sudoers", fmt(no_auth))],
                references=[cwe(306, "Missing Authentication for Critical Function")]))
        if not findings:
            ctx.note(f"{len(rules)} sudo rule(s) reviewed; no high-risk rules")
        return findings


_HASH_IDS = {"1": "md5", "5": "sha256", "6": "sha512", "y": "yescrypt", "gy": "gost-yescrypt", "7": "scrypt",
             "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt"}


def password_algorithm(field: str) -> str:
    """Classify a shadow password field without exposing it."""
    if field == "":
        return "empty"
    if field[0] in "!*":
        return "locked"
    m = re.match(r"^\$([^$]+)\$", field)
    if not m:
        return "des" if len(field) == 13 else "other"
    return _HASH_IDS.get(m.group(1), "other")


def shadow_flags(text: str) -> list[dict[str, Any]]:
    """Derive per-account flags from /etc/shadow WITHOUT retaining hash values."""
    out = []
    for line in text.splitlines():
        fields = line.split(":")
        if len(fields) >= 2:
            out.append({"user": fields[0], "password": password_algorithm(fields[1])})
    return out


class EmptyPasswordsCheck(LinuxCheck):
    check_id = "LNX-ACCT-001"
    title = "Accounts with empty or weakly hashed passwords"
    description = "Derives flags from /etc/shadow; password hashes are never stored or reported."
    requires_admin = True
    admin_reason = "/etc/shadow is readable only by root."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        text, err = ctx.fs.try_read("/etc/shadow")
        if text is None:
            raise SkipCheck(f"/etc/shadow could not be read ({err}).", "privilege")
        flags = shadow_flags(text)
        del text
        findings = []
        empty = [f["user"] for f in flags if f["password"] == "empty"]
        weak = [f for f in flags if f["password"] in ("md5", "des")]
        if empty:
            findings.append(ctx.finding(
                self, title=f"{len(empty)} account(s) have an empty password", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, component="/etc/shadow",
                description=f"Accounts with no password: {', '.join(empty)}.",
                impact="These accounts can be used without credentials wherever password login is permitted "
                       "(console, su, and SSH if PermitEmptyPasswords is enabled).", confidence=Confidence.HIGH,
                remediation="Lock the accounts (sudo passwd -l <user>) or set strong passwords.",
                verification="sudo awk -F: '($2==\"\"){print $1}' /etc/shadow  -> no output",
                severity_rationale="High: credential-free access; Critical if SSH permits empty passwords "
                                   "(see LNX-SSH-001).",
                evidence=[ctx.evidence("Accounts with empty password field (no hashes collected)", "/etc/shadow",
                                       empty)],
                references=[cwe(521, "Weak Password Requirements"),
                            baseline("Ensure password fields are not empty", CIS_UBUNTU)]))
        if weak:
            findings.append(ctx.finding(
                self, title=f"{len(weak)} account(s) use obsolete password hashing (MD5/DES)", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="/etc/shadow",
                description="Accounts: " + ", ".join(f"{w['user']} ({w['password']})" for w in weak),
                impact="If /etc/shadow is stolen, these hashes can be cracked quickly.", confidence=Confidence.HIGH,
                remediation="Set ENCRYPT_METHOD SHA512 or YESCRYPT in /etc/login.defs and have the users change "
                            "their passwords.", verification="Hash prefix becomes $6$ or $y$ after a password change.",
                severity_rationale="Medium: requires prior theft of /etc/shadow.",
                evidence=[ctx.evidence("Hash algorithm per account (no hashes collected)", "/etc/shadow", weak)],
                references=[cwe(916, "Use of Password Hash With Insufficient Computational Effort")]))
        if not findings:
            ctx.note(f"{len(flags)} account(s) checked; no empty or weakly hashed passwords")
        return findings


class PasswordPolicyCheck(LinuxCheck):
    check_id = "LNX-ACCT-002"
    title = "Password quality and lockout policy"
    description = "Checks PAM password quality, login failure lockout and the password hashing method."
    PAM_PASSWORD = ("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth")
    PAM_AUTH = ("/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        pam_pw = "\n".join(ctx.fs.try_read(p)[0] or "" for p in self.PAM_PASSWORD)
        pam_auth = "\n".join(ctx.fs.try_read(p)[0] or "" for p in self.PAM_AUTH)
        if not pam_pw.strip() and not pam_auth.strip():
            raise SkipCheck("PAM configuration files were not found.", "platform")
        active = lambda text, mod: any(mod in l and not l.strip().startswith("#") for l in text.splitlines())  # noqa: E731
        quality = active(pam_pw, "pam_pwquality.so") or active(pam_pw, "pam_cracklib.so")
        minlen = None
        if quality:
            m = re.search(r"minlen=(\d+)", pam_pw)
            conf = parse_kv_lines(ctx.fs.try_read("/etc/security/pwquality.conf")[0] or "", sep="=")
            minlen = int(m.group(1)) if m else int(conf.get("minlen", "8")) if conf.get("minlen", "8").isdigit() else 8
        lockout = active(pam_auth, "pam_faillock.so") or active(pam_auth, "pam_tally2.so")
        defs = parse_kv_lines(ctx.fs.try_read("/etc/login.defs")[0] or "")
        method = defs.get("ENCRYPT_METHOD", "").upper()
        data = {"password_quality_module": quality, "minlen": minlen, "lockout_module": lockout,
                "encrypt_method": method or None}
        ev = ctx.evidence("PAM and login.defs settings", "/etc/pam.d/*, /etc/security/pwquality.conf, /etc/login.defs",
                          data)
        findings = []
        if not quality:
            findings.append(ctx.finding(
                self, title="No password quality (complexity/length) module is configured", severity=Severity.LOW,
                status=FindingStatus.POTENTIAL, component="PAM password stack",
                description="Neither pam_pwquality nor pam_cracklib is active; pam_unix only enforces a very short "
                            "minimum length.", impact="Users can set short or trivially guessable passwords.",
                confidence=Confidence.MEDIUM,
                remediation="Install libpam-pwquality and set minlen = 14 in /etc/security/pwquality.conf.",
                verification="grep pam_pwquality /etc/pam.d/common-password",
                severity_rationale="Low/potential: impact depends on whether passwords are used at all (SSH keys, "
                                   "central identity).",
                evidence=[ev], references=[cwe(521, "Weak Password Requirements"),
                                           baseline("Ensure password creation requirements are configured",
                                                    CIS_UBUNTU)], manual_validation_required=True))
        elif minlen is not None and minlen < 14:
            sev = Severity.MEDIUM if minlen < 8 else Severity.LOW
            findings.append(ctx.finding(
                self, title=f"Minimum password length is {minlen}", severity=sev, status=FindingStatus.CONFIRMED,
                component="pam_pwquality", description=f"Password quality enforces minlen = {minlen}.",
                impact="Shorter passwords are easier to guess or crack.", confidence=Confidence.MEDIUM,
                remediation="Set minlen = 14 in /etc/security/pwquality.conf.",
                verification="grep minlen /etc/security/pwquality.conf",
                severity_rationale=f"{sev.value.capitalize()}: below the CIS recommendation of 14.",
                evidence=[ev], references=[cwe(521, "Weak Password Requirements")]))
        if not lockout:
            findings.append(ctx.finding(
                self, title="No account lockout after failed logins (pam_faillock)", severity=Severity.LOW,
                status=FindingStatus.POTENTIAL, component="PAM auth stack",
                description="pam_faillock/pam_tally2 is not active.",
                impact="Passwords can be guessed repeatedly on local and PAM-based remote logins.",
                confidence=Confidence.MEDIUM,
                remediation="Configure pam_faillock (deny=5, unlock_time=900) per your distribution's guidance, "
                            "taking care not to lock out administrators.",
                verification="grep pam_faillock /etc/pam.d/common-auth",
                severity_rationale="Low/potential: SSH key-only access or rate limiting may mitigate.",
                evidence=[ev], references=[cwe(307, "Improper Restriction of Excessive Authentication Attempts")],
                manual_validation_required=True))
        if method in ("MD5", "DES"):
            findings.append(ctx.finding(
                self, title=f"Passwords are hashed with {method}", severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED, component="/etc/login.defs",
                description=f"ENCRYPT_METHOD {method} produces weak password hashes.",
                impact="Stolen hashes can be cracked quickly.", confidence=Confidence.HIGH,
                remediation="Set ENCRYPT_METHOD YESCRYPT (or SHA512) in /etc/login.defs.",
                verification="grep ENCRYPT_METHOD /etc/login.defs", severity_rationale="Medium: weak credential storage.",
                evidence=[ev], references=[cwe(916, "Use of Password Hash With Insufficient Computational Effort")]))
        if not findings:
            ctx.note("Password quality, lockout and hashing are configured")
        return findings


# --------------------------------------------------------------------------
# File permissions
# --------------------------------------------------------------------------

SYSTEM_DIRS = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/boot", "/var/spool/cron")
STICKY_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


class WorldWritableCheck(LinuxCheck):
    check_id = "LNX-PERM-001"
    title = "World-writable files and directories in system locations"
    description = "Searches system directories for files/directories any user can modify."
    MAX_REPORTED = 200
    timeout_seconds = 600  # full filesystem sweep; slow on cold caches and large servers

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        hits: list[dict[str, str]] = []

        def visit(path: str, s: os.stat_result) -> None:
            if st.S_ISLNK(s.st_mode) or not (s.st_mode & st.S_IWOTH):
                return
            if st.S_ISDIR(s.st_mode) and s.st_mode & st.S_ISVTX:
                return  # sticky world-writable dirs (like /tmp) are expected
            if st.S_ISREG(s.st_mode) or st.S_ISDIR(s.st_mode):
                hits.append({"path": path, "mode": mode_str(s.st_mode), "type": "dir" if st.S_ISDIR(s.st_mode)
                             else "file", "uid": str(s.st_uid)})

        tops = [d for d in SYSTEM_DIRS if (s := ctx.fs.lstat(d)) and st.S_ISDIR(s.st_mode)]
        stats = ctx.fs.walk(tops, visit, stop=ctx.stop)
        if stats.truncated:
            ctx.limitation(f"File sweep stopped after {stats.visited} entries; results are partial.", "timeout")
        if stats.denied and not ctx.host.elevated:
            ctx.limitation(f"{stats.denied} director(ies) could not be read without root.", "privilege")
        no_sticky = []
        for d in STICKY_DIRS:
            s = ctx.fs.lstat(d)
            if s and st.S_ISDIR(s.st_mode) and s.st_mode & st.S_IWOTH and not s.st_mode & st.S_ISVTX:
                no_sticky.append({"path": d, "mode": mode_str(s.st_mode)})
        findings = []
        if hits:
            findings.append(ctx.finding(
                self, title=f"{len(hits)} world-writable item(s) in system directories", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, component="Filesystem permissions",
                description="Any local user can modify: " + ", ".join(h["path"] for h in hits[:10])
                            + (" ..." if len(hits) > 10 else ""),
                impact="Modifying system binaries, libraries, configuration or cron files allows privilege "
                       "escalation to root or persistence.", confidence=Confidence.HIGH,
                remediation="Remove the world-write bit (sudo chmod o-w <path>) after confirming nothing depends "
                            "on it; investigate how the permission was introduced.",
                verification="sudo find " + " ".join(tops) + " -xdev -perm -0002 ! -type l ! -perm -1000",
                severity_rationale="High: direct local privilege-escalation or tampering path, directly observed.",
                evidence=[ctx.evidence(f"World-writable items (first {self.MAX_REPORTED})", "filesystem walk",
                                       hits[: self.MAX_REPORTED])],
                references=[cwe(732, "Incorrect Permission Assignment for Critical Resource")]))
        if no_sticky:
            findings.append(ctx.finding(
                self, title="Shared temporary directory lacks the sticky bit", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, component=", ".join(d["path"] for d in no_sticky),
                description="World-writable temporary directories without the sticky bit let users delete or "
                            "replace each other's files.",
                impact="Attackers can tamper with temporary files of privileged processes (symlink/race attacks).",
                confidence=Confidence.HIGH, remediation="sudo chmod +t " + " ".join(d["path"] for d in no_sticky),
                verification="stat -c %a /tmp  -> 1777", severity_rationale="High: enables cross-user tampering.",
                evidence=[ctx.evidence("Directory modes", "stat", no_sticky)],
                references=[cwe(379, "Creation of Temporary File in Directory with Insecure Permissions")]))
        if not findings:
            ctx.note(f"{stats.visited} entries scanned; no world-writable system files")
        return findings


# path pattern -> (forbidden permission bits, severity, explanation)
SENSITIVE_FILES: list[tuple[str, int, Severity, str]] = [
    ("/etc/shadow", 0o007, Severity.CRITICAL, "contains password hashes and must not be accessible to other users"),
    ("/etc/gshadow", 0o007, Severity.HIGH, "contains group password hashes"),
    ("/etc/passwd", 0o022, Severity.HIGH, "defines accounts and UIDs; write access allows creating root accounts"),
    ("/etc/group", 0o022, Severity.HIGH, "defines group membership including sudo/wheel"),
    ("/etc/sudoers", 0o022, Severity.HIGH, "defines sudo rights"),
    ("/etc/ssh/sshd_config", 0o022, Severity.HIGH, "controls SSH authentication"),
    ("/etc/ssh/ssh_host_*_key", 0o077, Severity.HIGH, "is an SSH host private key; disclosure enables server "
                                                       "impersonation"),
    ("/etc/crontab", 0o022, Severity.HIGH, "runs commands as root on a schedule"),
    ("/etc/cron.d/*", 0o022, Severity.HIGH, "runs scheduled commands, often as root"),
    ("/boot/grub/grub.cfg", 0o022, Severity.MEDIUM, "controls the boot process"),
    ("/root", 0o007, Severity.LOW, "is root's home directory"),
]


class SensitiveFilePermissionsCheck(LinuxCheck):
    check_id = "LNX-PERM-002"
    title = "Permissions on sensitive configuration files"
    description = "Verifies ownership and permissions of account, sudo, SSH, cron and boot files."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        findings, checked = [], 0
        for pattern, forbidden, sev, why in SENSITIVE_FILES:
            directory, base = pattern.rsplit("/", 1)
            paths = ctx.fs.glob(directory, base) if any(c in base for c in "*?[") else [pattern]
            for path in paths:
                s = ctx.fs.lstat(path)
                if s is None or st.S_ISLNK(s.st_mode):
                    continue
                checked += 1
                bad_bits = s.st_mode & forbidden
                wrong_owner = s.st_uid != 0
                if not bad_bits and not wrong_owner:
                    continue
                problems = []
                if bad_bits & 0o004 or bad_bits & 0o040:
                    problems.append("readable by group/other")
                if bad_bits & 0o022:
                    problems.append("writable by group/other")
                if bad_bits & 0o011 and not problems:
                    problems.append("accessible by group/other")
                if wrong_owner:
                    problems.append(f"owned by UID {s.st_uid} instead of root")
                severity = sev if bad_bits else Severity.MEDIUM
                findings.append(ctx.finding(
                    self, title=f"Insecure permissions on {path}", severity=severity,
                    status=FindingStatus.CONFIRMED, component=path,
                    description=f"{path} {why}; it is " + " and ".join(problems)
                                + f" (mode {mode_str(s.st_mode)}, uid {s.st_uid}).",
                    impact="Unauthorized users may read secrets or alter security-relevant configuration.",
                    confidence=Confidence.HIGH,
                    remediation=f"Restore ownership and mode, e.g. sudo chown root {path} && sudo chmod "
                                f"go-{'rwx' if forbidden & 0o007 == 0o007 else 'w'} {path}, then investigate the cause.",
                    verification=f"stat -c '%U %a' {path}",
                    severity_rationale=f"{severity.value.capitalize()}: based on what the file protects; ownership "
                                       "issues alone are rated Medium.",
                    evidence=[ctx.evidence("File metadata", "lstat", {"path": path, "mode": mode_str(s.st_mode),
                                                                      "uid": s.st_uid, "gid": s.st_gid})],
                    references=[cwe(732, "Incorrect Permission Assignment for Critical Resource")]))
        if not findings:
            ctx.note(f"{checked} sensitive file(s) have correct ownership and permissions")
        return findings


KNOWN_SUID = {
    "passwd", "sudo", "sudoedit", "su", "mount", "umount", "chsh", "chfn", "newgrp", "gpasswd", "pkexec",
    "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "snap-confine", "unix_chkpwd", "chage", "expiry", "crontab", "wall", "write", "write.ul", "bsd-write",
    "ssh-agent", "pam_extrausers_chkpwd", "Xorg.wrap", "mount.nfs", "umount.nfs", "mount.cifs", "at", "ping",
    "ping6", "dotlockfile", "plocate", "mlocate", "locate", "utempter", "newuidmap", "newgidmap",
    "chrome-sandbox", "chromium-sandbox", "usernetctl", "userhelper", "pam_timestamp_check", "postdrop",
    "postqueue", "mount.ecryptfs_private", "lxc-user-nic", "qemu-bridge-helper", "ksu", "doas", "mail-lock",
    "mail-unlock", "mail-touchlock", "screen", "vmware-user-suid-wrapper", "traceroute6.iputils", "ntfs-3g",
    "Xorg", "sg", "lockdev", "staprun", "landscape-sysinfo", "netreport",
}
GTFOBINS = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "find", "vim", "vi", "vim.basic", "vim.tiny", "nano",
    "less", "more", "awk", "gawk", "mawk", "nawk", "perl", "ruby", "php", "lua", "node", "nmap", "cp", "mv",
    "env", "tar", "zip", "unzip", "rsync", "dd", "tee", "sed", "git", "gdb", "strace", "busybox", "socat", "nc",
    "netcat", "wget", "curl", "openssl", "xxd", "base64", "docker", "systemctl", "journalctl", "man", "ed",
    "install", "chmod", "chown", "taskset", "nice", "timeout", "stdbuf", "xargs", "ionice", "flock", "make",
    "expect", "tclsh", "wish", "run-parts", "start-stop-daemon", "capsh", "setarch", "unshare", "nohup",
}
SUID_TOPS = ("/usr", "/bin", "/sbin", "/opt", "/srv", "/home", "/tmp", "/var/tmp", "/root")
USER_WRITABLE_AREAS = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/")


class SuidBinariesCheck(LinuxCheck):
    check_id = "LNX-SUID-001"
    title = "SUID/SGID binaries"
    description = "Lists set-user-ID/set-group-ID programs and flags dangerous or unexpected ones."
    timeout_seconds = 600  # full filesystem sweep; slow on cold caches and large servers

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        found: list[dict[str, str]] = []

        def visit(path: str, s: os.stat_result) -> None:
            if st.S_ISREG(s.st_mode) and s.st_mode & (st.S_ISUID | st.S_ISGID):
                found.append({"path": path, "mode": mode_str(s.st_mode), "uid": str(s.st_uid),
                              "suid": bool(s.st_mode & st.S_ISUID), "sgid": bool(s.st_mode & st.S_ISGID)})

        tops = [d for d in SUID_TOPS if (s := ctx.fs.lstat(d)) and st.S_ISDIR(s.st_mode)]
        stats = ctx.fs.walk(tops, visit, stop=ctx.stop)
        if stats.truncated:
            ctx.limitation(f"SUID sweep stopped after {stats.visited} entries; results are partial.", "timeout")
        name = lambda p: p.rsplit("/", 1)[-1]  # noqa: E731
        is_gtfo = lambda f: name(f["path"]) in GTFOBINS or re.fullmatch(r"python[\d.]*", name(f["path"]))  # noqa: E731
        dangerous = [f for f in found if f["suid"] and f["uid"] == "0" and is_gtfo(f)]
        odd_place = [f for f in found if f["path"].startswith(USER_WRITABLE_AREAS) and f not in dangerous]
        unknown = [f for f in found if f not in dangerous and f not in odd_place and name(f["path"]) not in KNOWN_SUID]
        findings = []
        refs = [cwe(250, "Execution with Unnecessary Privileges"),
                url("https://gtfobins.github.io/", "GTFOBins")]
        if dangerous:
            findings.append(ctx.finding(
                self, title="SUID-root programs that allow trivial root escalation", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, component="SUID binaries",
                description="These programs are SUID root and can spawn shells or write files: "
                            + ", ".join(f["path"] for f in dangerous),
                impact="Any local user can obtain a root shell.", confidence=Confidence.HIGH,
                remediation="Remove the SUID bit (sudo chmod u-s <path>) and investigate how it was set; it may "
                            "indicate compromise.", verification="find / -xdev -perm -4000 -type f",
                severity_rationale="High: well-documented, reliable privilege escalation.",
                evidence=[ctx.evidence("Dangerous SUID binaries", "filesystem walk", dangerous)], references=refs))
        if odd_place:
            findings.append(ctx.finding(
                self, title="SUID/SGID files in user-writable locations", severity=Severity.HIGH,
                status=FindingStatus.POTENTIAL, component="SUID binaries",
                description="Set-ID files found under home or temporary directories: "
                            + ", ".join(f["path"] for f in odd_place[:20]),
                impact="Set-ID programs outside system directories are a common backdoor technique.",
                confidence=Confidence.MEDIUM, remediation="Investigate each file's origin; remove set-ID bits or the "
                                                          "files. Mount /home and /tmp with nosuid.",
                verification="findmnt -no OPTIONS /tmp  -> includes nosuid",
                severity_rationale="High/potential: strong indicator of tampering, pending investigation.",
                evidence=[ctx.evidence("Set-ID files", "filesystem walk", odd_place)], references=refs,
                manual_validation_required=True))
        if unknown:
            findings.append(ctx.finding(
                self, title=f"{len(unknown)} unexpected SUID/SGID binaries to review", severity=Severity.LOW,
                status=FindingStatus.POTENTIAL, component="SUID binaries",
                description="Not on the list of commonly expected set-ID programs: "
                            + ", ".join(f["path"] for f in unknown[:20]) + (" ..." if len(unknown) > 20 else ""),
                impact="Each set-ID program is privileged attack surface; vendor packages may be legitimate.",
                confidence=Confidence.MEDIUM,
                remediation="Confirm each binary belongs to an installed package (dpkg -S <path>) and is needed.",
                verification="dpkg -S <path>; ls -l <path>",
                severity_rationale="Low/potential: review item, not a confirmed weakness.",
                evidence=[ctx.evidence("Unexpected set-ID files", "filesystem walk", unknown)], references=refs,
                manual_validation_required=True))
        ctx.note(f"{len(found)} set-ID file(s) found in {stats.visited} entries")
        return findings


# --------------------------------------------------------------------------
# Services
# --------------------------------------------------------------------------

RISKY_UNITS: dict[str, tuple[Severity, str]] = {
    "telnet": (Severity.HIGH, "Telnet sends credentials and sessions in cleartext."),
    "rsh": (Severity.HIGH, "rsh relies on cleartext, host-based trust."),
    "rlogin": (Severity.HIGH, "rlogin relies on cleartext, host-based trust."),
    "rexec": (Severity.HIGH, "rexec sends credentials in cleartext."),
    "ypserv": (Severity.HIGH, "NIS serves account data with weak protection."),
    "inetd": (Severity.MEDIUM, "inetd/xinetd often enables legacy cleartext services; review its configuration."),
    "xinetd": (Severity.MEDIUM, "inetd/xinetd often enables legacy cleartext services; review its configuration."),
    "tftp": (Severity.MEDIUM, "TFTP has no authentication."),
    "vsftpd": (Severity.MEDIUM, "FTP sends credentials in cleartext unless TLS is enforced."),
    "proftpd": (Severity.MEDIUM, "FTP sends credentials in cleartext unless TLS is enforced."),
    "pure-ftpd": (Severity.MEDIUM, "FTP sends credentials in cleartext unless TLS is enforced."),
    "ypbind": (Severity.MEDIUM, "NIS client; NIS is obsolete and weakly protected."),
    "snmpd": (Severity.LOW, "SNMP v1/v2c uses cleartext community strings; prefer SNMPv3."),
    "rpcbind": (Severity.LOW, "rpcbind is only needed for NFS/NIS; it exposes RPC information."),
    "avahi-daemon": (Severity.LOW, "mDNS/zeroconf is rarely needed on servers and advertises services."),
    "cups": (Severity.LOW, "A print service is rarely needed on servers."),
    "nfs-server": (Severity.LOW, "NFS exports must be restricted to approved clients."),
}
SERVER_ONLY = {"avahi-daemon", "cups"}


class ServicesCheck(LinuxCheck):
    check_id = "LNX-SVC-001"
    title = "Unnecessary or insecure services"
    description = "Lists running systemd services and sockets and flags legacy or risky ones."
    required_tools = ("systemctl",)

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        res = ctx.runner.run(["systemctl", "list-units", "--type=service,socket", "--state=running,listening",
                              "--no-legend", "--plain", "--no-pager"])
        if not res.ok:
            raise SkipCheck("systemd is not running or not accessible (e.g. inside a container).", "platform")
        units = [l.split()[0] for l in res.stdout.splitlines() if l.strip()]
        findings = []
        for unit in units:
            base = re.sub(r"(@.*)?\.(service|socket)$", "", unit)
            key = next((k for k in RISKY_UNITS if base == k or base.startswith(k + "-") or base == k + "d"), None)
            if key is None or (key in SERVER_ONLY and not ctx.os_info.is_server):
                continue
            sev, why = RISKY_UNITS[key]
            findings.append(ctx.finding(
                self, title=f"Service {unit} is running", severity=sev, status=FindingStatus.POTENTIAL,
                component=unit, description=why, impact="Unneeded or legacy services enlarge the attack surface.",
                confidence=Confidence.MEDIUM,
                remediation=f"If not required: sudo systemctl disable --now {unit} (and remove the package). "
                            "Otherwise restrict and harden it.",
                verification=f"systemctl is-active {unit}  -> inactive",
                severity_rationale=f"{sev.value.capitalize()}/potential: the service may be required for this "
                                   "system's role.",
                evidence=[ctx.evidence("Running unit", "systemctl list-units", unit)],
                references=[cwe(1188, "Initialization of a Resource with an Insecure Default"),
                            baseline("Ensure insecure/unneeded services are not in use", CIS_UBUNTU)],
                manual_validation_required=True))
        if not findings:
            ctx.note(f"{len(units)} running unit(s); no legacy or risky services")
        return findings


# --------------------------------------------------------------------------
# Encryption, MAC, kernel, TLS
# --------------------------------------------------------------------------

def root_is_encrypted(lsblk: dict[str, Any]) -> bool | None:
    """True/False if the device chain under '/' is (not) dm-crypt/LUKS; None if '/' is not a block device."""
    def walk(node: dict[str, Any], chain: list[dict[str, Any]]) -> bool | None:
        chain = chain + [node]
        mounts = node.get("mountpoints") or [node.get("mountpoint")]
        if "/" in mounts:
            return any(n.get("type") == "crypt" or n.get("fstype") == "crypto_LUKS" for n in chain)
        for child in node.get("children") or []:
            r = walk(child, chain)
            if r is not None:
                return r
        return None

    for dev in lsblk.get("blockdevices", []):
        r = walk(dev, [])
        if r is not None:
            return r
    return None


class DiskEncryptionCheck(LinuxCheck):
    check_id = "LNX-ENC-001"
    title = "Disk encryption of the root filesystem"
    description = "Determines whether the root filesystem sits on a LUKS/dm-crypt device."
    required_tools = ("lsblk",)

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        res = ctx.runner.run(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"])
        if not res.ok:
            raise SkipCheck("lsblk failed.", "dependency")
        try:
            tree = json.loads(res.stdout)
        except ValueError:
            raise SkipCheck("lsblk output could not be parsed.", "error") from None
        encrypted = root_is_encrypted(tree)
        if encrypted is None:
            raise SkipCheck("The root filesystem is not a local block device (container, overlay or network "
                            "storage); assess encryption on the underlying host or storage.", "platform")
        if encrypted:
            ctx.note("Root filesystem is on an encrypted (LUKS/dm-crypt) device")
            return []
        desktop = not ctx.os_info.is_server
        sev = Severity.MEDIUM if desktop else Severity.LOW
        return [ctx.finding(
            self, title="Root filesystem is not encrypted at the OS level", severity=sev,
            status=FindingStatus.POTENTIAL if not desktop else FindingStatus.CONFIRMED,
            component="Block devices", description="No LUKS/dm-crypt layer was found beneath '/'.",
            impact="Data on stolen, lost or decommissioned disks can be read offline.",
            confidence=Confidence.MEDIUM if not desktop else Confidence.HIGH,
            remediation="Use LUKS full-disk encryption for laptops/desktops (requires reinstall or migration); for "
                        "servers confirm hypervisor, SAN or self-encrypting-drive encryption.",
            verification="lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT shows a 'crypt' device above '/'.",
            severity_rationale="Medium for portable/desktop systems; Low/potential for servers where storage-layer "
                               "encryption is common and not visible to the OS.",
            evidence=[ctx.evidence("Block device tree", "lsblk -J", tree)],
            references=[cwe(311, "Missing Encryption of Sensitive Data")],
            manual_validation_required=not desktop)]


class MandatoryAccessControlCheck(LinuxCheck):
    check_id = "LNX-MAC-001"
    title = "AppArmor / SELinux status"
    description = "Checks that a mandatory access control system is enabled and enforcing."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        aa_enabled = (ctx.fs.try_read("/sys/module/apparmor/parameters/enabled")[0] or "").strip() == "Y"
        profiles, perr = ctx.fs.try_read("/sys/kernel/security/apparmor/profiles")
        enforce = complain = None
        if profiles is not None:
            enforce = profiles.count("(enforce)")
            complain = profiles.count("(complain)")
        elif aa_enabled and perr == "denied":
            ctx.limitation("AppArmor profile modes are readable only by root.", "privilege")
        se_enforce = (ctx.fs.try_read("/sys/fs/selinux/enforce")[0] or "").strip()
        se_cfg = parse_kv_lines(ctx.fs.try_read("/etc/selinux/config")[0] or "", sep="=").get("SELINUX")
        data = {"apparmor_enabled": aa_enabled, "apparmor_enforce_profiles": enforce,
                "apparmor_complain_profiles": complain, "selinux_enforce": se_enforce or None,
                "selinux_config": se_cfg}
        ev = ctx.evidence("MAC status", "/sys/module/apparmor, /sys/kernel/security/apparmor, /sys/fs/selinux", data)
        common = dict(component="Mandatory access control", evidence=[ev],
                      references=[cwe(284, "Improper Access Control"),
                                  baseline("Ensure AppArmor is enabled / all profiles are enforcing", CIS_UBUNTU)])
        if se_enforce == "1":
            ctx.note("SELinux is enforcing")
            return []
        if se_enforce == "0":
            return [ctx.finding(
                self, title="SELinux is in permissive mode", severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED,
                description="SELinux logs policy violations but does not block them.",
                impact="Compromised services are not confined.", confidence=Confidence.HIGH,
                remediation="Resolve logged denials, then set SELINUX=enforcing in /etc/selinux/config and reboot.",
                verification="getenforce  -> Enforcing", severity_rationale="Medium: confinement is not applied.",
                **common)]
        if aa_enabled:
            if enforce == 0:
                return [ctx.finding(
                    self, title="AppArmor is enabled but no profiles are enforcing", severity=Severity.MEDIUM,
                    status=FindingStatus.CONFIRMED,
                    description=f"{complain} profile(s) in complain mode; none enforcing.",
                    impact="Services are not confined.", confidence=Confidence.HIGH,
                    remediation="Put profiles into enforce mode (sudo aa-enforce /etc/apparmor.d/*) after testing.",
                    verification="sudo aa-status", severity_rationale="Medium: confinement is not applied.", **common)]
            ctx.note("AppArmor is enabled" + (f" with {enforce} enforcing profile(s)" if enforce is not None else ""))
            return []
        return [ctx.finding(
            self, title="No mandatory access control (AppArmor/SELinux) is active", severity=Severity.MEDIUM,
            status=FindingStatus.CONFIRMED, description="Neither AppArmor nor SELinux is enabled.",
            impact="A compromised service has the full privileges of its user account, without additional "
                   "confinement.", confidence=Confidence.HIGH,
            remediation="Enable AppArmor (Ubuntu/Debian: apt install apparmor; kernel parameter apparmor=1) or "
                        "SELinux (RHEL family) and enforce the distribution profiles.",
            verification="cat /sys/module/apparmor/parameters/enabled  -> Y, or getenforce -> Enforcing",
            severity_rationale="Medium: defence-in-depth control missing.", **common)]


# sysctl path -> (bad values, severity, title, explanation, recommended)
SYSCTL_RULES: list[tuple[str, set[str], Severity, str, str, str]] = [
    ("kernel/randomize_va_space", {"0"}, Severity.HIGH, "ASLR is disabled",
     "Address space layout randomization makes memory-corruption exploits unreliable.", "2"),
    ("kernel/randomize_va_space", {"1"}, Severity.LOW, "ASLR is only partially enabled",
     "Heap (brk) randomization is off.", "2"),
    ("net/ipv4/conf/all/accept_source_route", {"1"}, Severity.MEDIUM, "Source-routed packets are accepted",
     "Source routing lets attackers choose the packet path to bypass controls.", "0"),
    ("fs/protected_symlinks", {"0"}, Severity.LOW, "Symlink protection is disabled",
     "Protects against symlink attacks in world-writable sticky directories.", "1"),
    ("fs/protected_hardlinks", {"0"}, Severity.LOW, "Hardlink protection is disabled",
     "Prevents users from hard-linking files they do not own.", "1"),
    ("fs/suid_dumpable", {"1", "2"}, Severity.LOW, "Core dumps of SUID programs are allowed",
     "Core dumps of privileged programs can leak secrets.", "0"),
    ("kernel/kptr_restrict", {"0"}, Severity.LOW, "Kernel pointers are exposed",
     "Kernel addresses help attackers defeat KASLR.", "1"),
    ("kernel/dmesg_restrict", {"0"}, Severity.LOW, "Kernel log is readable by all users",
     "dmesg can disclose kernel addresses and hardware details.", "1"),
    ("kernel/yama/ptrace_scope", {"0"}, Severity.LOW, "Unrestricted ptrace is allowed",
     "Any process can inspect other processes of the same user (credential theft from memory).", "1"),
    ("kernel/unprivileged_bpf_disabled", {"0"}, Severity.LOW, "Unprivileged eBPF is allowed",
     "Unprivileged eBPF has been a recurring kernel privilege-escalation vector.", "1 or 2"),
    ("net/ipv4/tcp_syncookies", {"0"}, Severity.LOW, "TCP SYN cookies are disabled",
     "SYN cookies mitigate SYN-flood denial of service.", "1"),
    ("net/ipv4/conf/all/accept_redirects", {"1"}, Severity.LOW, "ICMP redirects are accepted",
     "Redirects can be abused to reroute traffic.", "0"),
    ("net/ipv4/conf/all/send_redirects", {"1"}, Severity.LOW, "ICMP redirects are sent",
     "Only routers should send redirects.", "0"),
]


class KernelHardeningCheck(LinuxCheck):
    check_id = "LNX-KERN-001"
    title = "Kernel security parameters (sysctl)"
    description = "Compares selected kernel parameters with hardening recommendations."

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        values, deviations = {}, []
        for path, bad, sev, title, why, rec in SYSCTL_RULES:
            text, _ = ctx.fs.try_read(f"/proc/sys/{path}")
            if text is None:
                continue
            value = text.strip()
            values[path.replace("/", ".")] = value
            if value in bad:
                deviations.append({"parameter": path.replace("/", "."), "value": value, "recommended": rec,
                                   "severity": sev, "title": title, "why": why})
        if not values:
            raise SkipCheck("/proc/sys is not readable.", "platform")
        ev = ctx.evidence("Kernel parameters", "/proc/sys", values)
        findings = []
        for d in [d for d in deviations if d["severity"] != Severity.LOW]:
            findings.append(ctx.finding(
                self, title=d["title"], severity=d["severity"], status=FindingStatus.CONFIRMED,
                component=d["parameter"], description=f"{d['parameter']} = {d['value']}. {d['why']}",
                impact="Weakens kernel-level defences against exploitation or network attacks.",
                confidence=Confidence.HIGH,
                remediation=f"Set {d['parameter']} = {d['recommended']} in /etc/sysctl.d/99-hardening.conf and "
                            "apply with 'sudo sysctl --system'.",
                verification=f"sysctl {d['parameter']}",
                severity_rationale=f"{d['severity'].value.capitalize()}: directly observed kernel setting.",
                evidence=[ev], references=[baseline(f"Ensure {d['parameter']} is configured", CIS_UBUNTU)]))
        low = [d for d in deviations if d["severity"] == Severity.LOW]
        if low:
            findings.append(ctx.finding(
                self, title=f"{len(low)} kernel hardening parameter(s) deviate from recommendations",
                severity=Severity.LOW, status=FindingStatus.CONFIRMED, component="sysctl",
                description="; ".join(f"{d['parameter']}={d['value']} (recommended {d['recommended']}): {d['why']}"
                                      for d in low),
                impact="Each setting removes a layer of defence in depth.", confidence=Confidence.HIGH,
                remediation="Add the recommended values to /etc/sysctl.d/99-hardening.conf and run "
                            "'sudo sysctl --system' (check application compatibility first).",
                verification="sysctl " + " ".join(d["parameter"] for d in low),
                severity_rationale="Low: hardening settings; none is exploitable on its own.",
                evidence=[ev], references=[baseline("Ensure kernel parameters are configured", CIS_UBUNTU)]))
        if not findings:
            ctx.note(f"{len(values)} kernel parameters match recommendations")
        return findings


CERT_DIRS = ("/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/letsencrypt/live", "/etc/letsencrypt/archive",
             "/etc/pki/tls/certs", "/etc/postfix", "/etc/dovecot", "/etc/haproxy", "/etc/ssl/localcerts")
CERT_PATTERNS = ("*.crt", "*.pem", "*.cer")
MAX_CERTS = 100


def parse_openssl_x509(text: str) -> dict[str, Any] | None:
    end = re.search(r"notAfter=(.+)", text)
    if not end:
        return None
    try:
        not_after = datetime.strptime(" ".join(end.group(1).split()), "%b %d %H:%M:%S %Y %Z").date()
    except ValueError:
        return None
    subject = re.search(r"^subject=\s*(.+)$", text, re.M)
    issuer = re.search(r"^issuer=\s*(.+)$", text, re.M)
    sig = re.search(r"Signature Algorithm:\s*(\S+)", text)
    bits = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
    key = re.search(r"Public Key Algorithm:\s*(\S+)", text)
    return {"subject": subject.group(1).strip() if subject else "", "issuer": issuer.group(1).strip() if issuer else "",
            "not_after": not_after, "signature_algorithm": sig.group(1) if sig else "",
            "key_bits": int(bits.group(1)) if bits else None, "key_type": key.group(1) if key else ""}


class CertificateFilesCheck(LinuxCheck):
    check_id = "LNX-TLS-001"
    title = "Service TLS certificates"
    description = "Checks certificates used by common services (web, mail, proxy) for expiry and weak algorithms."
    required_tools = ("openssl",)

    def __init__(self, today: date | None = None) -> None:
        self.today = today

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        paths: list[str] = []

        def visit(path: str, s: os.stat_result) -> None:
            n = path.rsplit("/", 1)[-1]
            if st.S_ISREG(s.st_mode) and any(fnmatch(n, p) for p in CERT_PATTERNS) and "ca-bundle" not in n \
                    and "ca-certificates" not in n and "privkey" not in n and len(paths) < MAX_CERTS:
                paths.append(path)

        tops = [d for d in CERT_DIRS if ctx.fs.is_dir(d)]
        if not tops:
            ctx.note("No service certificate directories found")
            return []
        stats = ctx.fs.walk(tops, visit, max_entries=20_000, stop=ctx.stop)
        if stats.denied and not ctx.host.elevated:
            ctx.limitation("Some certificate directories (e.g. /etc/letsencrypt) are readable only by root.",
                           "privilege")
        certs, seen = [], set()
        for path in paths:
            # openssl reads the file; the toolkit itself never opens files that may hold private keys.
            res = ctx.runner.run(["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-enddate",
                                  "-text"])
            info = parse_openssl_x509(res.stdout) if res.ok else None
            if info is None:
                continue
            key = (info["subject"], info["not_after"])
            if key in seen:
                continue
            seen.add(key)
            certs.append({**info, "source": path})
        findings = evaluate_certificates(ctx, self, certs, self.today)
        if not findings:
            ctx.note(f"{len(certs)} service certificate(s) valid with acceptable algorithms")
        return findings


def build_module() -> Module:
    return Module(
        module_id="linux_audit",
        name="C. Linux security audit",
        description="Patches, SSH, firewall, accounts, sudo, permissions, SUID, services, encryption, "
                    "AppArmor/SELinux, kernel parameters and certificates.",
        category="local",
        checks=[PatchStatusCheck(), SshConfigCheck(), FirewallCheck(), PrivilegedAccountsCheck(), SudoersCheck(),
                EmptyPasswordsCheck(), PasswordPolicyCheck(), WorldWritableCheck(), SensitiveFilePermissionsCheck(),
                SuidBinariesCheck(), ServicesCheck(), DiskEncryptionCheck(), MandatoryAccessControlCheck(),
                KernelHardeningCheck(), CertificateFilesCheck()],
    )

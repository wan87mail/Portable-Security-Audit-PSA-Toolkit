"""Module A: system information and asset discovery.

Inventory checks that describe the asset: identification, network
interfaces and connections, listening ports, exposed risky services and
installed software. Security-control status (patches, AV, firewall,
encryption) is assessed by the OS-specific modules B and C.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import json
from collections import Counter

from psatoolkit.core.engine import AssessmentContext, Check, Module, SkipCheck
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Reference, ReferenceKind, Severity
from psatoolkit.core.osdetect import SUPPORTED, UNSUPPORTED
from psatoolkit.modules._common import (TCP_ESTABLISHED, Listener, cwe, is_loopback, linux_socket_table,
                                        listeners, run_ps)


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
                evidence=[ctx.evidence("OS build reported by the platform API", "sys.getwindowsversion()",
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


class NetworkInterfacesCheck(Check):
    check_id = "SYS-NET-001"
    title = "Network interfaces and active connections"
    description = "Lists interfaces, addresses and a summary of established connections."
    supported_os = frozenset({"windows", "linux"})

    WINDOWS_PS = ("Get-NetIPAddress | Where-Object { $_.AddressState -ne 'Invalid' } | "
                  "Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressFamily")
    WINDOWS_CONN_PS = ("Get-NetTCPConnection -State Established | "
                       "Select-Object RemoteAddress,RemotePort,OwningProcess")

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        if ctx.os_info.family == "windows":
            interfaces = [{"interface": r.get("InterfaceAlias"), "address": r.get("IPAddress"),
                           "prefix": r.get("PrefixLength"),
                           "family": {2: "IPv4", 23: "IPv6"}.get(r.get("AddressFamily"), r.get("AddressFamily"))}
                          for r in run_ps(ctx, self.WINDOWS_PS, "IP addresses") if isinstance(r, dict)]
            conns = [(str(r.get("RemoteAddress")), r.get("RemotePort"))
                     for r in run_ps(ctx, self.WINDOWS_CONN_PS, "TCP connections") if isinstance(r, dict)]
            source = "Get-NetIPAddress; Get-NetTCPConnection"
        else:
            interfaces = self._linux_interfaces(ctx)
            conns = [(r["remote"], r["rport"]) for r in linux_socket_table(ctx)
                     if r["proto"].startswith("tcp") and r["state"] == TCP_ESTABLISHED]
            source = "ip -j addr (or /sys/class/net); /proc/net/tcp*"
        remote = Counter(addr for addr, _port in conns if not is_loopback(addr))
        data = {"interfaces": interfaces,
                "established_tcp_connections": len(conns),
                "remote_hosts": len(remote),
                "top_remote_hosts": [{"address": a, "connections": n} for a, n in remote.most_common(20)]}
        ctx.note(f"{len(interfaces)} interface address(es), {len(conns)} established TCP connection(s)")
        return [ctx.finding(
            self, title="Network interfaces and connections inventory",
            severity=Severity.INFO, status=FindingStatus.INFORMATIONAL, component="Network configuration",
            description=f"{len(interfaces)} interface address(es); {len(conns)} established TCP "
                        f"connection(s) to {len(remote)} remote host(s).",
            impact="None by itself. Use it to confirm the host's network placement matches the asset record.",
            confidence=Confidence.HIGH,
            remediation="Review unexpected interfaces (e.g. bridges, VPN adapters) and unexpected remote peers.",
            verification="Compare with the network diagram / CMDB entry for this host.",
            severity_rationale="Informational inventory.",
            evidence=[ctx.evidence("Interfaces and connection summary", source, data)])]

    @staticmethod
    def _linux_interfaces(ctx: AssessmentContext) -> list[dict]:
        res = ctx.runner.run(["ip", "-j", "addr"])
        if res.ok:
            try:
                out = []
                for iface in json.loads(res.stdout):
                    for a in iface.get("addr_info", []):
                        out.append({"interface": iface.get("ifname"), "state": iface.get("operstate"),
                                    "address": a.get("local"), "prefix": a.get("prefixlen"),
                                    "family": "IPv6" if a.get("family") == "inet6" else "IPv4"})
                return out
            except (ValueError, AttributeError):
                pass
        ctx.limitation("'ip' is unavailable; IPv4 addresses could not be listed (interface names only).")
        out = []
        for name in ctx.fs.listdir("/sys/class/net"):
            state = (ctx.fs.try_read(f"/sys/class/net/{name}/operstate")[0] or "").strip()
            out.append({"interface": name, "state": state, "address": None})
        return out


class ListeningPortsCheck(Check):
    check_id = "SYS-PORTS-001"
    title = "Listening ports and services"
    description = "Inventory of TCP/UDP ports listening on this host, with owning process where visible."
    supported_os = frozenset({"windows", "linux"})

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        found = listeners(ctx)
        exposed = [l for l in found if not l.loopback]
        if ctx.os_info.family == "linux" and not ctx.host.elevated and any(not l.process for l in found):
            ctx.limitation("Process names for sockets owned by other users require root.", "privilege")
        ctx.note(f"{len(found)} listening socket(s), {len(exposed)} reachable beyond loopback")
        return [ctx.finding(
            self, title=f"{len(exposed)} network service(s) listening beyond loopback",
            severity=Severity.INFO, status=FindingStatus.INFORMATIONAL, component="Listening sockets",
            description=f"{len(found)} listening socket(s) found; {len(exposed)} accept connections from "
                        "other hosts (bound to all interfaces or a non-loopback address).",
            impact="Every exposed service is part of the attack surface and must be justified and patched.",
            confidence=Confidence.HIGH,
            remediation="Disable services that are not required, bind internal-only services to 127.0.0.1, "
                        "and restrict the rest with the host firewall.",
            verification="Linux: 'sudo ss -tulpn'. Windows: 'Get-NetTCPConnection -State Listen'.",
            severity_rationale="Informational inventory; risky services are reported separately (SYS-PORTS-002).",
            evidence=[ctx.evidence("Listening sockets", "/proc/net/* or Get-NetTCPConnection/Get-NetUDPEndpoint",
                                   [l.to_dict() for l in found])])]


S = Severity
# (transport, port) -> (service, severity, why it is risky, applies to OS families)
RISKY_SERVICES: dict[tuple[str, int], tuple[str, Severity, str, frozenset[str]]] = {
    ("tcp", 21): ("FTP", S.MEDIUM, "FTP sends credentials and data in cleartext.", frozenset({"linux", "windows"})),
    ("tcp", 23): ("Telnet", S.HIGH, "Telnet provides a cleartext remote shell.", frozenset({"linux", "windows"})),
    ("udp", 69): ("TFTP", S.MEDIUM, "TFTP transfers files without authentication.", frozenset({"linux", "windows"})),
    ("udp", 161): ("SNMP", S.MEDIUM, "SNMP v1/v2c community strings travel in cleartext and often grant broad "
                                     "read access.", frozenset({"linux", "windows"})),
    ("tcp", 512): ("rexec", S.HIGH, "Berkeley r-services use cleartext, host-based trust.", frozenset({"linux"})),
    ("tcp", 513): ("rlogin", S.HIGH, "Berkeley r-services use cleartext, host-based trust.", frozenset({"linux"})),
    ("tcp", 514): ("rsh", S.HIGH, "Berkeley r-services use cleartext, host-based trust.", frozenset({"linux"})),
    ("tcp", 111): ("RPC portmapper", S.LOW, "Discloses RPC services; UDP portmapper is abused for "
                                            "amplification.", frozenset({"linux"})),
    ("tcp", 873): ("rsync daemon", S.MEDIUM, "rsync modules are frequently exposed without authentication.",
                   frozenset({"linux"})),
    ("tcp", 2049): ("NFS", S.LOW, "NFS exports rely on network-level trust; verify export restrictions.",
                    frozenset({"linux"})),
    ("tcp", 2375): ("Docker API (unencrypted)", S.HIGH, "An unauthenticated Docker API gives root-equivalent "
                                                        "control of the host.", frozenset({"linux", "windows"})),
    ("tcp", 3306): ("MySQL/MariaDB", S.MEDIUM, "Databases should not be reachable from other hosts unless "
                                               "required.", frozenset({"linux", "windows"})),
    ("tcp", 5432): ("PostgreSQL", S.MEDIUM, "Databases should not be reachable from other hosts unless "
                                            "required.", frozenset({"linux", "windows"})),
    ("tcp", 1433): ("Microsoft SQL Server", S.MEDIUM, "Databases should not be reachable from other hosts "
                                                      "unless required.", frozenset({"linux", "windows"})),
    ("tcp", 1521): ("Oracle listener", S.MEDIUM, "Databases should not be reachable from other hosts unless "
                                                 "required.", frozenset({"linux", "windows"})),
    ("tcp", 27017): ("MongoDB", S.MEDIUM, "MongoDB has historically been deployed without authentication.",
                     frozenset({"linux", "windows"})),
    ("tcp", 6379): ("Redis", S.MEDIUM, "Redis often runs without authentication; exposed instances are "
                                       "routinely abused.", frozenset({"linux", "windows"})),
    ("tcp", 11211): ("Memcached", S.MEDIUM, "Memcached has no authentication by default; UDP is abused for "
                                            "amplification.", frozenset({"linux", "windows"})),
    ("tcp", 9200): ("Elasticsearch", S.MEDIUM, "Older Elasticsearch defaults allow unauthenticated access.",
                    frozenset({"linux", "windows"})),
    ("tcp", 5984): ("CouchDB", S.MEDIUM, "Database HTTP API exposed to the network.", frozenset({"linux", "windows"})),
    **{("tcp", p): ("VNC", S.MEDIUM, "VNC authentication is weak and traffic is often unencrypted.",
                    frozenset({"linux", "windows"})) for p in range(5900, 5904)},
    ("tcp", 445): ("Samba (SMB)", S.LOW, "File sharing exposed; verify shares and SMB protocol settings.",
                   frozenset({"linux"})),
}


class ExposedRiskyServicesCheck(Check):
    check_id = "SYS-PORTS-002"
    title = "Risky services exposed to the network"
    description = "Flags well-known risky or sensitive services that listen beyond loopback."
    supported_os = frozenset({"windows", "linux"})

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        grouped: dict[tuple[str, int], list[Listener]] = {}
        for l in listeners(ctx):
            key = (l.proto.rstrip("6"), l.port)
            info = RISKY_SERVICES.get(key)
            if l.loopback or info is None or ctx.os_info.family not in info[3]:
                continue
            grouped.setdefault(key, []).append(l)
        findings = []
        for (transport, port), socks in sorted(grouped.items(), key=lambda kv: kv[0][1]):
            service, severity, why, _os = RISKY_SERVICES[(transport, port)]
            procs = sorted({s.process for s in socks if s.process})
            findings.append(ctx.finding(
                self, title=f"{service} is listening on {transport}/{port} beyond loopback",
                severity=severity, status=FindingStatus.POTENTIAL,
                component=f"{service} ({transport}/{port}{', ' + ', '.join(procs) if procs else ''})",
                description=f"{service} accepts connections on "
                            f"{', '.join(sorted({s.address for s in socks}))}. {why}",
                impact="If reachable from untrusted networks, attackers may intercept credentials, access data "
                       "or exploit the service.",
                confidence=Confidence.MEDIUM,
                remediation=f"Confirm {service} is required. If not, disable it. Otherwise bind it to a "
                            "management interface or 127.0.0.1, require authentication/encryption, and "
                            "restrict access with the host and network firewalls.",
                verification=f"From another host on the same network segment, confirm {transport}/{port} is "
                             "unreachable (or only reachable from approved sources).",
                severity_rationale=f"{severity.value.capitalize()}: based on the service's typical risk. Marked "
                                   "potential because firewall rules or service authentication may already "
                                   "mitigate exposure.",
                evidence=[ctx.evidence("Listening sockets", "socket inventory", [s.to_dict() for s in socks])],
                references=[cwe(319, "Cleartext Transmission of Sensitive Information")]
                if "cleartext" in why else [cwe(284, "Improper Access Control")],
                manual_validation_required=True))
        if not findings:
            ctx.note("No well-known risky services listen beyond loopback")
        return findings


WINDOWS_SOFTWARE_PS = ("$k='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                       "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; "
                       "Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | "
                       "Select-Object DisplayName,DisplayVersion,Publisher")
DPKG_FORMAT = "${binary:Package}\t${Version}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n"
RPM_FORMAT = "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"


def parse_dpkg_inventory(text: str) -> list[dict[str, str]]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].startswith("ii"):
            continue
        pkg = {"name": parts[0], "version": parts[1]}
        source = parts[3].strip() if len(parts) > 3 else ""
        if source and source != parts[0].split(":")[0]:
            pkg["source"] = source
            pkg["source_version"] = (parts[4].strip() if len(parts) > 4 else "") or parts[1]
        pkgs.append(pkg)
    return pkgs


def parse_rpm_inventory(text: str) -> list[dict[str, str]]:
    pkgs = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        version = parts[1].replace("(none):", "")
        pkg = {"name": parts[0], "version": version}
        if len(parts) > 2 and parts[2].endswith(".src.rpm"):
            source = parts[2][: -len(".src.rpm")].rsplit("-", 2)[0]
            if source and source != parts[0]:
                pkg["source"] = source
                pkg["source_version"] = version
        pkgs.append(pkg)
    return pkgs


def collect_software(ctx: AssessmentContext) -> tuple[list[dict[str, str]], str, str]:
    """Return (packages, description of source, version scheme 'dpkg'|'rpm'|'generic')."""
    if ctx.os_info.family == "windows":
        rows = run_ps(ctx, WINDOWS_SOFTWARE_PS, "installed programs")
        items = sorted({(str(r.get("DisplayName")), str(r.get("DisplayVersion") or ""),
                         str(r.get("Publisher") or "")) for r in rows if isinstance(r, dict)})
        return ([{"name": n, "version": v, "publisher": p} for n, v, p in items],
                "Uninstall registry keys (machine-wide; per-user installs not included)", "generic")
    res = ctx.runner.run(["dpkg-query", "-W", "-f", DPKG_FORMAT])
    if res.ok:
        return parse_dpkg_inventory(res.stdout), "dpkg-query", "dpkg"
    res = ctx.runner.run(["rpm", "-qa", "--qf", RPM_FORMAT])
    if res.ok:
        return parse_rpm_inventory(res.stdout), "rpm", "rpm"
    raise SkipCheck("No supported package manager (dpkg or rpm) was found.", "dependency")


class SoftwareInventoryCheck(Check):
    check_id = "SYS-SW-001"
    title = "Installed software inventory"
    description = "Lists installed packages/programs (name and version) for patch and licence review."
    supported_os = frozenset({"windows", "linux"})
    MAX_ITEMS = 5000
    WINDOWS_PS = WINDOWS_SOFTWARE_PS

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        packages, source, _scheme = collect_software(ctx)
        total = len(packages)
        ctx.note(f"{total} installed package(s)")
        return [ctx.finding(
            self, title=f"{total} installed software package(s) inventoried",
            severity=Severity.INFO, status=FindingStatus.INFORMATIONAL, component="Software inventory",
            description=f"{total} packages/programs were found via {source}."
                        + (f" The evidence lists the first {self.MAX_ITEMS}." if total > self.MAX_ITEMS else ""),
            impact="None by itself. Unneeded software enlarges the attack surface and patching workload.",
            confidence=Confidence.HIGH,
            remediation="Remove software that is not required and confirm the rest is covered by patching.",
            verification="Compare against the approved software list for this system role.",
            severity_rationale="Informational inventory; vulnerability matching is performed in Module E.",
            evidence=[ctx.evidence("Installed software", source, packages[: self.MAX_ITEMS])])]


def build_module() -> Module:
    return Module(
        module_id="system_info",
        name="A. System information and asset discovery",
        description="Asset identification, network, listening ports, exposed services and software inventory.",
        category="local",
        checks=[AssetIdentificationCheck(), PlatformSupportCheck(), NetworkInterfacesCheck(),
                ListeningPortsCheck(), ExposedRiskyServicesCheck(), SoftwareInventoryCheck()],
    )

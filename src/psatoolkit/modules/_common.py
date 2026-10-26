"""Shared helpers for assessment modules.

Everything here is read-only: PowerShell queries use only ``Get-*`` cmdlets
(enforced again by the command policy), and Linux data comes from
:class:`~psatoolkit.core.hostfs.HostFS` or allow-listed commands.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import struct
from dataclasses import asdict, dataclass
from typing import Any

from psatoolkit.core.engine import AssessmentContext, SkipCheck
from psatoolkit.core.models import Reference, ReferenceKind

# --------------------------------------------------------------------------
# References
# --------------------------------------------------------------------------


def cwe(number: int, name: str) -> Reference:
    return Reference(ReferenceKind.CWE, f"CWE-{number}", f"MITRE CWE: {name}")


def baseline(title: str, source: str) -> Reference:
    return Reference(ReferenceKind.BASELINE, title, source)


def url(link: str, source: str) -> Reference:
    return Reference(ReferenceKind.URL, link, source)


MS_BASELINE = "Microsoft Security Baseline (Windows 11 / Server 2022)"
CIS_WIN = "CIS Microsoft Windows Benchmark (title only; content licensed separately)"
CIS_UBUNTU = "CIS Ubuntu Linux Benchmark (title only; content licensed separately)"


# --------------------------------------------------------------------------
# PowerShell (Windows)
# --------------------------------------------------------------------------

_PS_PREAMBLE = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
                "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ")


def ps_command(script: str) -> list[str]:
    """Build the argument list for a read-only PowerShell query returning JSON.

    Scripts are constants written in this code base; operator input is never
    interpolated into them. Double quotes are avoided so Windows argument
    quoting cannot change the script.
    """
    if '"' in script:
        raise ValueError("PowerShell scripts must not contain double quotes")
    body = (_PS_PREAMBLE + "$r = & { " + script + " }; "
            "ConvertTo-Json -InputObject @($r) -Depth 5 -Compress")
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", body]


def run_ps(ctx: AssessmentContext, script: str, what: str, timeout: float | None = None) -> list[Any]:
    """Run a PowerShell query and return its JSON output as a list.

    Raises :class:`SkipCheck` when PowerShell is unavailable or the query fails,
    so the check is reported as a limitation rather than a false finding.
    """
    res = ctx.runner.run(ps_command(script), timeout=timeout)
    if res.error == "policy_denied":
        raise RuntimeError(f"internal error: query blocked by read-only policy: {res.error_detail}")
    if not res.ok:
        detail = res.error_detail or (res.stderr.strip().splitlines() or ["no output"])[0]
        if res.timed_out:
            detail = "timed out"
        raise SkipCheck(f"Could not query {what}: {detail[:300]}", "dependency")
    text = res.stdout.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise SkipCheck(f"Could not parse {what} output.", "error") from None
    items = data if isinstance(data, list) else [data]
    return [i for i in items if i is not None]


def ps_registry_script(spec: dict[str, tuple[str, list[str]]]) -> str:
    """Script reading registry values: ``{alias: (path, [value names])}`` -> ``{'alias.Name': value}``."""
    lines = ["$o=[ordered]@{}"]
    for alias, (path, names) in spec.items():
        safe_path = path.replace("'", "''")
        lines.append(f"$p=Get-ItemProperty -LiteralPath '{safe_path}' -ErrorAction SilentlyContinue")
        for name in names:
            safe = name.replace("'", "''")
            lines.append(f"$o['{alias}.{safe}']=if($p){{$p.'{safe}'}}else{{$null}}")
    lines.append("[pscustomobject]$o")
    return "; ".join(lines)


def read_registry(ctx: AssessmentContext, spec: dict[str, tuple[str, list[str]]], what: str) -> dict[str, Any]:
    rows = run_ps(ctx, ps_registry_script(spec), what)
    return rows[0] if rows and isinstance(rows[0], dict) else {}


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value)
    return None


# --------------------------------------------------------------------------
# Network sockets
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Listener:
    proto: str          # tcp, tcp6, udp, udp6
    address: str
    port: int
    process: str = ""
    pid: int | None = None

    @property
    def loopback(self) -> bool:
        return is_loopback(self.address)

    @property
    def wildcard(self) -> bool:
        return self.address in ("0.0.0.0", "::", "*", "")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scope"] = "loopback" if self.loopback else ("all interfaces" if self.wildcard else "specific interface")
        return d


def is_loopback(address: str) -> bool:
    addr = address.split("%")[0].strip("[]")
    if addr in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def _hex_ip(hex_addr: str) -> str:
    raw = bytes.fromhex(hex_addr)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", struct.unpack(">I", raw)[0]))
    # IPv6: four 32-bit words, each in host (little-endian) order.
    words = struct.unpack(">4I", raw)
    return socket.inet_ntop(socket.AF_INET6, struct.pack("<4I", *words))


TCP_LISTEN, TCP_ESTABLISHED, UDP_UNCONNECTED = "0A", "01", "07"


def parse_proc_net(text: str, proto: str) -> list[dict[str, Any]]:
    """Parse ``/proc/net/{tcp,tcp6,udp,udp6}`` into dicts with addresses, state and inode."""
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            laddr, lport = parts[1].split(":")
            raddr, rport = parts[2].split(":")
            rows.append({"proto": proto, "local": _hex_ip(laddr), "lport": int(lport, 16),
                         "remote": _hex_ip(raddr), "rport": int(rport, 16), "state": parts[3].upper(),
                         "uid": int(parts[7]), "inode": int(parts[9])})
        except (ValueError, OSError):
            continue
    return rows


def linux_socket_table(ctx: AssessmentContext) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        text, _err = ctx.fs.try_read(f"/proc/net/{proto}")
        if text:
            rows.extend(parse_proc_net(text, proto))
    return rows


def linux_inode_owners(ctx: AssessmentContext, max_pids: int = 5000) -> dict[int, tuple[int, str]]:
    """Map socket inode -> (pid, process name). Complete only when running as root."""
    owners: dict[int, tuple[int, str]] = {}
    pids = [p for p in ctx.fs.listdir("/proc") if p.isdigit()][:max_pids]
    for pid in pids:
        fds = ctx.fs.listdir(f"/proc/{pid}/fd")
        if not fds:
            continue
        name = (ctx.fs.try_read(f"/proc/{pid}/comm")[0] or "?").strip()
        for fd in fds:
            target = ctx.fs.readlink(f"/proc/{pid}/fd/{fd}") or ""
            m = re.fullmatch(r"socket:\[(\d+)\]", target)
            if m:
                owners.setdefault(int(m.group(1)), (int(pid), name))
    return owners


def linux_listeners(ctx: AssessmentContext) -> list[Listener]:
    table = linux_socket_table(ctx)
    if not table:
        raise SkipCheck("Cannot read /proc/net socket tables.", "platform")
    owners = linux_inode_owners(ctx)
    out = set()
    for r in table:
        listening = (r["proto"].startswith("tcp") and r["state"] == TCP_LISTEN) or \
                    (r["proto"].startswith("udp") and r["state"] == UDP_UNCONNECTED and r["rport"] == 0)
        if listening:
            pid, name = owners.get(r["inode"], (None, ""))
            out.add(Listener(r["proto"], r["local"], r["lport"], name, pid))
    return sorted(out, key=lambda l: (l.proto, l.port, l.address))


WINDOWS_LISTENERS_PS = (
    "$n=@{}; Get-Process | ForEach-Object { $n[[int]$_.Id]=$_.ProcessName }; "
    "$t=Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{proto='tcp';"
    "address=$_.LocalAddress;port=[int]$_.LocalPort;pid=[int]$_.OwningProcess;process=$n[[int]$_.OwningProcess]} }; "
    "$u=Get-NetUDPEndpoint | ForEach-Object { [pscustomobject]@{proto='udp';"
    "address=$_.LocalAddress;port=[int]$_.LocalPort;pid=[int]$_.OwningProcess;process=$n[[int]$_.OwningProcess]} }; "
    "@($t)+@($u)")


def windows_listeners(ctx: AssessmentContext) -> list[Listener]:
    rows = run_ps(ctx, WINDOWS_LISTENERS_PS, "listening ports")
    out = set()
    for r in rows:
        if not isinstance(r, dict) or as_int(r.get("port")) is None:
            continue
        proto = str(r.get("proto", "tcp"))
        address = str(r.get("address") or "")
        if ":" in address:
            proto += "6"
        out.add(Listener(proto, address, int(r["port"]), str(r.get("process") or ""), as_int(r.get("pid"))))
    return sorted(out, key=lambda l: (l.proto, l.port, l.address))


def listeners(ctx: AssessmentContext) -> list[Listener]:
    if ctx.os_info.family == "windows":
        return windows_listeners(ctx)
    return linux_listeners(ctx)


# --------------------------------------------------------------------------
# Misc parsing
# --------------------------------------------------------------------------

def parse_kv_lines(text: str, sep: str | None = None, comment: str = "#") -> dict[str, str]:
    """Parse ``key value`` / ``key=value`` lines; later keys override earlier ones."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split(comment, 1)[0].strip() if comment else raw.strip()
        if not line:
            continue
        if sep:
            if sep not in line:
                continue
            k, v = line.split(sep, 1)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            k, v = parts
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def mode_str(mode: int) -> str:
    return oct(mode & 0o7777)[2:].zfill(4)

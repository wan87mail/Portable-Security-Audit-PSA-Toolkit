"""Operating system detection.

Detection is split into small pure functions that take their raw inputs as
arguments, so they can be unit-tested with mock data on any platform.
"""

from __future__ import annotations

import platform
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path

SUPPORTED = "supported"
BEST_EFFORT = "best-effort"
UNSUPPORTED = "unsupported"

# Windows build numbers -> product names. Workstation and server share kernels,
# so the edition string decides which table applies.
_WINDOWS_SERVER_BUILDS = {
    17763: "Windows Server 2019",
    20348: "Windows Server 2022",
    26100: "Windows Server 2025",
}
_SUPPORTED_UBUNTU = {"22.04", "24.04"}


@dataclass(frozen=True)
class OSInfo:
    family: str                  # "windows", "linux", "macos", "unknown"
    name: str                    # human readable, e.g. "Windows 11", "Ubuntu 24.04.1 LTS"
    version: str                 # e.g. "10.0.22631", "24.04"
    build: str
    architecture: str            # "x86_64", "arm64", ...
    is_server: bool
    support_level: str           # SUPPORTED, BEST_EFFORT, UNSUPPORTED
    distro_id: str = ""          # linux: "ubuntu", "debian", "rhel", ...
    distro_like: tuple[str, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)


def normalize_arch(machine: str) -> str:
    m = (machine or "").lower()
    if m in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    if m in ("x86", "i386", "i686"):
        return "x86"
    return m or "unknown"


def classify_windows(release: str, version: str, edition: str, machine: str) -> OSInfo:
    """Classify Windows from ``platform.win32_ver()`` / ``win32_edition()`` values.

    ``version`` looks like ``10.0.22631``. ``platform.release()`` reports "10"
    on Windows 11 for older Pythons, so the build number is authoritative.
    """
    parts = version.split(".")
    try:
        build = int(parts[2]) if len(parts) >= 3 else 0
    except ValueError:
        build = 0
    is_server = "server" in (edition or "").lower()
    notes: list[str] = []

    if is_server:
        name = _WINDOWS_SERVER_BUILDS.get(build)
        if name:
            support = SUPPORTED
        else:
            known = max((b for b in _WINDOWS_SERVER_BUILDS if b <= build), default=None)
            name = f"Windows Server (build {build})"
            support = BEST_EFFORT if known else UNSUPPORTED
            notes.append("Server build not in the tested list; checks run best-effort.")
    elif build >= 22000:
        name, support = "Windows 11", SUPPORTED
    elif build >= 10240:
        name, support = "Windows 10", SUPPORTED
    else:
        name, support = f"Windows {release or 'unknown'}", UNSUPPORTED
        notes.append("Windows versions before 10 are out of support and not assessed.")

    if edition:
        name = f"{name} ({edition})"
    return OSInfo(
        family="windows",
        name=name,
        version=version,
        build=str(build),
        architecture=normalize_arch(machine),
        is_server=is_server,
        support_level=support,
        notes=tuple(notes),
    )


def parse_os_release(text: str) -> dict[str, str]:
    """Parse the ``/etc/os-release`` key=value format (shell-quoted values)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def classify_linux(os_release: dict[str, str], kernel: str, machine: str,
                   has_desktop: bool = False) -> OSInfo:
    distro_id = os_release.get("ID", "linux").lower()
    like = tuple(os_release.get("ID_LIKE", "").lower().split())
    version_id = os_release.get("VERSION_ID", "")
    name = os_release.get("PRETTY_NAME") or os_release.get("NAME") or "Linux"
    notes: list[str] = []

    if distro_id == "ubuntu" and version_id in _SUPPORTED_UBUNTU:
        support = SUPPORTED
    elif distro_id in ("ubuntu", "debian") or "debian" in like or "ubuntu" in like:
        support = BEST_EFFORT
        notes.append("Debian-family distribution outside the tested list; checks run best-effort.")
    elif distro_id in ("rhel", "centos", "rocky", "almalinux", "fedora") or "rhel" in like or "fedora" in like:
        support = BEST_EFFORT
        notes.append("RHEL-family: package update checks use dnf/rpm; tested less extensively.")
    else:
        support = BEST_EFFORT
        notes.append("Unrecognised distribution; only generic Linux checks are reliable.")

    return OSInfo(
        family="linux",
        name=name,
        version=version_id,
        build=kernel,
        architecture=normalize_arch(machine),
        # Heuristic: a missing graphical target is the most reliable cheap signal.
        is_server=not has_desktop,
        support_level=support,
        distro_id=distro_id,
        distro_like=like,
        notes=tuple(notes),
    )


def _linux_has_desktop() -> bool:
    return any(Path(p).exists() for p in ("/usr/share/xsessions", "/usr/share/wayland-sessions"))


def detect_os(os_release_path: str = "/etc/os-release") -> OSInfo:
    """Detect the operating system this process is running on."""
    machine = platform.machine()
    if sys.platform.startswith("win"):
        release, version, _csd, _ptype = platform.win32_ver()
        try:
            edition = platform.win32_edition() or ""
        except Exception:  # pragma: no cover - very old Python builds
            edition = ""
        return classify_windows(release, version, edition, machine)
    if sys.platform.startswith("linux"):
        try:
            text = Path(os_release_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        return classify_linux(parse_os_release(text), platform.release(), machine,
                              _linux_has_desktop())
    if sys.platform == "darwin":
        return OSInfo("macos", f"macOS {platform.mac_ver()[0]}", platform.mac_ver()[0],
                      platform.release(), normalize_arch(machine), False, UNSUPPORTED,
                      notes=("macOS is not a supported target; only generic checks run.",))
    return OSInfo("unknown", platform.system() or "unknown", platform.version(),
                  platform.release(), normalize_arch(machine), False, UNSUPPORTED)


def get_hostname() -> str:
    try:
        return socket.gethostname() or "unknown-host"
    except OSError:
        return "unknown-host"

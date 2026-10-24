"""Privilege detection. The toolkit never attempts to elevate itself."""

from __future__ import annotations

import os
import sys

ELEVATION_HELP = {
    "windows": ("Right-click PortableSecurityAudit.exe and choose 'Run as administrator'. "
                "Elevation is needed to read security policy, BitLocker, Defender "
                "preferences and some service configuration."),
    "linux": ("Run with 'sudo ./PortableSecurityAudit.sh'. Root is needed to read "
              "sshd effective configuration, /etc/shadow metadata, sudoers.d and full "
              "file-permission sweeps."),
}


def is_elevated() -> bool:
    """True when running as root (POSIX) or as an elevated Administrator (Windows)."""
    if sys.platform.startswith("win"):
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def elevation_help(os_family: str) -> str:
    return ELEVATION_HELP.get(os_family, "Run the toolkit with administrative privileges.")

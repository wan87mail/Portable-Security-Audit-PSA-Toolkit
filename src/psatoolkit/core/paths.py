"""Locate the portable root (USB drive) and choose writable output locations."""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from psatoolkit.core.validation import ValidationError, validate_output_dir


class OutputDirError(Exception):
    pass


@dataclass(frozen=True)
class AppPaths:
    root: Path

    @property
    def config_dir(self) -> Path:
        return self.root / "config"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    @property
    def baselines_dir(self) -> Path:
        return self.root / "baselines"

    @property
    def checksums_dir(self) -> Path:
        return self.root / "checksums"

    @property
    def docs_dir(self) -> Path:
        return self.root / "docs"

    @property
    def vulndata_dir(self) -> Path:
        return self.root / "vulndata"

    def tools_dir(self, os_family: str) -> Path:
        return self.root / "tools" / os_family


ROOT_MARKER = Path("config") / "default.toml"


def discover_root() -> Path:
    """Locate the portable root.

    Frozen build: the nearest of the executable's folder, its parent or
    grandparent that contains config/default.toml (the Windows .exe sits in the
    drive root; the Linux build sits in linux/PortableSecurityAudit/). The
    environment is deliberately not consulted for frozen builds, so settings on
    the target machine cannot redirect the tool. Source runs: $PSA_HOME (set by
    the launcher), else the repository root.
    """
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        for candidate in (exe_dir, exe_dir.parent, exe_dir.parent.parent):
            if (candidate / ROOT_MARKER).is_file():
                return candidate
        return exe_dir
    env = os.environ.get("PSA_HOME")
    if env:
        return Path(env).expanduser().resolve()
    # src/psatoolkit/core/paths.py -> repository root
    return Path(__file__).resolve().parents[3]


def get_paths(root: Path | None = None) -> AppPaths:
    return AppPaths(root=(root or discover_root()))


def is_writable(directory: Path) -> bool:
    """Probe writability by actually creating (and removing) a file."""
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".psa-write-test-", dir=directory)
        os.close(fd)
        os.unlink(name)
        return True
    except OSError:
        return False


def choose_output_dir(paths: AppPaths, configured: str = "", override: str | None = None) -> Path:
    """Return a writable report directory.

    Priority: explicit override (CLI/GUI) > configured value > USB reports/.
    The tool never silently writes reports to the target's disk: if the USB
    is read-only, the operator must pick a location explicitly.
    """
    candidate_str = override if override else configured
    if candidate_str:
        try:
            candidate = validate_output_dir(candidate_str)
        except ValidationError as exc:
            raise OutputDirError(str(exc)) from None
    else:
        candidate = paths.reports_dir
    if not is_writable(candidate):
        raise OutputDirError(
            f"Output directory '{candidate}' is not writable (read-only USB or insufficient "
            "permissions). Choose another directory with --output or the GUI prompt.")
    return candidate


def free_space_mb(directory: Path) -> int | None:
    try:
        import shutil

        return shutil.disk_usage(directory).free // (1024 * 1024)
    except OSError:
        return None

"""Read-only view of the target's filesystem.

Linux checks read configuration through :class:`HostFS` instead of calling
``open()`` directly. The class has no write methods, never follows symlinks
when walking, and can be rooted at a fake directory tree in tests.
"""

from __future__ import annotations

import os
import stat as stat_mod
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable, Iterable

from psatoolkit.core.stop import StopToken

# Pseudo filesystems that must never be walked.
PSEUDO_DIRS = ("/proc", "/sys", "/dev", "/run", "/snap")


@dataclass
class WalkStats:
    visited: int = 0
    denied: int = 0
    truncated: bool = False


class HostFS:
    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root)
        self._real_root = str(self.root) == os.sep

    def _p(self, path: str) -> Path:
        if not path.startswith("/"):
            raise ValueError(f"HostFS paths must be absolute: {path!r}")
        return Path(path) if self._real_root else self.root / path.lstrip("/")

    def _host_path(self, real: str) -> str:
        if self._real_root:
            return real
        rel = os.path.relpath(real, self.root)
        return "/" if rel == "." else "/" + rel.replace(os.sep, "/")

    # -- reading ---------------------------------------------------------
    def read_text(self, path: str, max_bytes: int = 2_000_000) -> str:
        with open(self._p(path), "rb") as fh:
            return fh.read(max_bytes).decode("utf-8", errors="replace")

    def try_read(self, path: str, max_bytes: int = 2_000_000) -> tuple[str | None, str | None]:
        """Return ``(text, None)`` or ``(None, reason)`` with reason missing/denied/error."""
        try:
            return self.read_text(path, max_bytes), None
        except FileNotFoundError:
            return None, "missing"
        except PermissionError:
            return None, "denied"
        except OSError as exc:
            return None, f"error: {exc.strerror or exc}"

    def lstat(self, path: str) -> os.stat_result | None:
        try:
            return os.lstat(self._p(path))
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return self.lstat(path) is not None

    def is_dir(self, path: str) -> bool:
        st = self.lstat(path)
        return bool(st and stat_mod.S_ISDIR(st.st_mode))

    def listdir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(self._p(path)))
        except OSError:
            return []

    def glob(self, directory: str, pattern: str) -> list[str]:
        base = directory.rstrip("/") or ""
        return [f"{base}/{name}" for name in self.listdir(directory or "/") if fnmatch(name, pattern)]

    def readlink(self, path: str) -> str | None:
        try:
            return os.readlink(self._p(path))
        except OSError:
            return None

    # -- walking ---------------------------------------------------------
    def walk(self, tops: Iterable[str], visitor: Callable[[str, os.stat_result], None],
             max_entries: int = 300_000, stop: StopToken | None = None) -> WalkStats:
        """Visit every file and directory below ``tops`` without following symlinks.

        Stays on the filesystem of each top directory (like ``find -xdev``) and
        skips pseudo filesystems. ``visitor`` receives host-style absolute paths.
        """
        stats = WalkStats()
        for top in tops:
            real_top = self._p(top)
            try:
                top_dev = os.lstat(real_top).st_dev
            except OSError:
                continue
            stack = [str(real_top)]
            while stack:
                current = stack.pop()
                try:
                    entries = list(os.scandir(current))
                except PermissionError:
                    stats.denied += 1
                    continue
                except OSError:
                    continue
                for entry in entries:
                    if stats.visited >= max_entries:
                        stats.truncated = True
                        return stats
                    stats.visited += 1
                    if stop is not None and stats.visited % 2000 == 0:
                        stop.raise_if_stopped()
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    host_path = self._host_path(entry.path)
                    visitor(host_path, st)
                    if stat_mod.S_ISDIR(st.st_mode) and st.st_dev == top_dev \
                            and not any(host_path == p or host_path.startswith(p + "/") for p in PSEUDO_DIRS):
                        stack.append(entry.path)
        return stats

"""Test doubles: a fake command runner and an in-memory filesystem.

FakeRunner still enforces the real ReadOnlyPolicy, so every command a check
issues in tests is proven to pass the read-only allow-list.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat as st
from typing import Any, Callable

from conftest import LINUX_OS, WINDOWS_OS
from psatoolkit.core.authorization import TargetScope
from psatoolkit.core.config import AppConfig
from psatoolkit.core.engine import AssessmentContext, build_host_info
from psatoolkit.core.hostfs import HostFS, WalkStats
from psatoolkit.core.logging_setup import AuditLog
from psatoolkit.core.safe_exec import CommandResult, ReadOnlyPolicy
from psatoolkit.core.stop import StopToken

__all__ = ["FakeRunner", "FakeFS", "make_ctx", "fake_stat", "titles", "by_severity", "LINUX_OS", "WINDOWS_OS"]


class FakeRunner:
    def __init__(self, available: set[str] | None = None) -> None:
        self.rules: list[tuple[tuple[str, ...], str | None, dict[str, Any]]] = []
        self.calls: list[list[str]] = []
        self.policy = ReadOnlyPolicy.default()
        self.stop_token = StopToken()
        self.available = available

    def on(self, *prefix: str, contains: str | None = None, stdout: str = "", stderr: str = "",
           returncode: int = 0, error: str | None = None, timed_out: bool = False, json_: Any = None) -> "FakeRunner":
        if json_ is not None:
            stdout = json.dumps(json_)
        self.rules.append((prefix, contains, dict(stdout=stdout, stderr=stderr, returncode=returncode,
                                                  error=error, timed_out=timed_out)))
        return self

    def run(self, argv, timeout=None) -> CommandResult:
        argv = list(argv)
        self.policy.check(argv[0], argv[1:])     # PolicyViolation fails the test
        self.calls.append(argv)
        for prefix, contains, res in self.rules:
            if tuple(argv[: len(prefix)]) == prefix and (contains is None or contains in " ".join(argv)):
                return CommandResult(argv=argv, **res)
        return CommandResult(argv=argv, error="not_found", error_detail="no fake response")

    def is_available(self, name: str) -> bool:
        return True if self.available is None else name in self.available


def fake_stat(mode: int, uid: int = 0, gid: int = 0, mtime: float = 0.0, dev: int = 1) -> os.stat_result:
    return os.stat_result((mode, 1, dev, 1, uid, gid, 0, mtime, mtime, mtime))


class FakeFS(HostFS):
    """In-memory filesystem. Paths are absolute host paths."""

    def __init__(self) -> None:
        super().__init__("/")
        self.files: dict[str, tuple[str | None, os.stat_result]] = {}
        self.denied: set[str] = set()
        self.links: dict[str, str] = {}

    def add(self, path: str, content: str | None = "", mode: int = 0o644, uid: int = 0, gid: int = 0,
            mtime: float = 0.0) -> "FakeFS":
        self.files[path] = (content, fake_stat(st.S_IFREG | mode, uid, gid, mtime))
        return self

    def add_dir(self, path: str, mode: int = 0o755, uid: int = 0) -> "FakeFS":
        self.files[path] = (None, fake_stat(st.S_IFDIR | mode, uid))
        return self

    def _dirs(self) -> set[str]:
        out = {p for p, (_c, s) in self.files.items() if st.S_ISDIR(s.st_mode)}
        for p in list(self.files) + list(self.links):
            parts = p.strip("/").split("/")
            for i in range(1, len(parts)):
                out.add("/" + "/".join(parts[:i]))
        return out

    def try_read(self, path, max_bytes=2_000_000):
        if path in self.denied:
            return None, "denied"
        entry = self.files.get(path)
        if entry is None or entry[0] is None:
            return None, "missing"
        return entry[0][:max_bytes], None

    def read_text(self, path, max_bytes=2_000_000):
        text, err = self.try_read(path, max_bytes)
        if text is None:
            raise FileNotFoundError(path) if err == "missing" else PermissionError(path)
        return text

    def lstat(self, path):
        if path in self.files:
            return self.files[path][1]
        if path in self.links:
            return fake_stat(st.S_IFLNK | 0o777)
        if path in self._dirs():
            return fake_stat(st.S_IFDIR | 0o755)
        return None

    def listdir(self, path):
        prefix = path.rstrip("/") + "/"
        names = {p[len(prefix):].split("/")[0] for p in set(self.files) | set(self.links) | self._dirs()
                 if p.startswith(prefix) and p != path}
        return sorted(n for n in names if n)

    def readlink(self, path):
        return self.links.get(path)

    def walk(self, tops, visitor: Callable, max_entries=300_000, stop=None) -> WalkStats:
        stats = WalkStats()
        for top in tops:
            prefix = top.rstrip("/") + "/"
            for path in sorted(set(self.files) | self._dirs()):
                if path.startswith(prefix):
                    if path in self.denied:
                        stats.denied += 1
                        continue
                    stats.visited += 1
                    visitor(path, self.lstat(path))
        return stats


def make_ctx(os_info=LINUX_OS, runner: FakeRunner | None = None, fs: HostFS | None = None, elevated: bool = True,
             is_server: bool | None = None, config: AppConfig | None = None) -> AssessmentContext:
    if is_server is not None:
        os_info = dataclasses.replace(os_info, is_server=is_server)
    runner = runner or FakeRunner()
    return AssessmentContext(host=build_host_info(os_info, "test-host", elevated), os_info=os_info,
                             config=config or AppConfig(), runner=runner, stop=runner.stop_token,
                             audit=AuditLog(None), scope=TargetScope(), demo=False, fs=fs or FakeFS())


def titles(findings) -> list[str]:
    return [f.title for f in findings]


def by_severity(findings) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in findings:
        out.setdefault(f.severity.value, []).append(f.title)
    return out

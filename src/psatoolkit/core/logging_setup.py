"""Application logging and the tamper-evident audit log.

The audit log is JSON Lines. Every entry contains the SHA-256 of the previous
entry, so deleting or editing a line breaks the chain and is detected by
:func:`verify_audit_log`. (This is tamper-*evident*, not tamper-*proof*: copy
logs off the USB drive to protected storage after each engagement.)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from psatoolkit.core.redaction import redact

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path | None, assessment_id: str = "") -> None:
        self.path = path
        self.assessment_id = assessment_id
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        self.memory: list[dict[str, Any]] = []   # also kept in memory for the report
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **details: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "assessment_id": self.assessment_id,
                "event": event,
                "details": redact(details),
                "prev": self._prev,
            }
            entry["hash"] = _entry_hash(entry)
            self._prev = entry["hash"]
            self.memory.append(entry)
            if self.path is not None:
                try:
                    with self.path.open("a", encoding="utf-8") as fh:
                        fh.write(_canonical(entry) + "\n")
                except OSError as exc:
                    logging.getLogger(__name__).error("audit log write failed: %s", exc)
            return entry

    def __call__(self, event: str, details: dict[str, Any]) -> None:
        """Adapter so the log can be passed as a ``(event, details)`` callback."""
        self.write(event, **details)


def verify_audit_log(path: Path) -> tuple[bool, list[str]]:
    problems: list[str] = []
    prev = GENESIS
    expected_seq = 1
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, [f"cannot read {path}: {exc}"]
    for lineno, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"line {lineno}: not valid JSON")
            break
        if entry.get("seq") != expected_seq:
            problems.append(f"line {lineno}: sequence {entry.get('seq')} != {expected_seq}")
        if entry.get("prev") != prev:
            problems.append(f"line {lineno}: chain broken (previous hash mismatch)")
        if _entry_hash(entry) != entry.get("hash"):
            problems.append(f"line {lineno}: entry hash mismatch (modified)")
        prev = entry.get("hash", "")
        expected_seq += 1
    return not problems, problems


def setup_app_logging(logs_dir: Path | None, level: str = "INFO", console: bool = True) -> Path | None:
    """Configure the root logger. Returns the log file path, if one is used."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in list(root.handlers):
        root.removeHandler(handler)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if console:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        sh.setLevel(logging.WARNING)
        root.addHandler(sh)
    log_file = None
    if logs_dir is not None:
        try:
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / f"psa-{datetime.now(timezone.utc):%Y%m%d}.log"
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError:
            log_file = None
    return log_file

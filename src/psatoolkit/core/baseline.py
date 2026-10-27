"""Organisational security baselines (format "psa-baseline-1").

A baseline is a JSON *data* file: it never contains code or commands. Each
rule names one of a fixed set of read-only collectors (see COLLECTORS) and an
expected value. All parameters are validated against strict patterns before
use, so a baseline cannot inject PowerShell, shell syntax or path traversal,
and cannot read files that hold secrets.

Example rule::

    {"id": "SSH-01", "title": "SSH root login is disabled", "severity": "high",
     "check": {"type": "sshd", "key": "permitrootlogin", "default": "prohibit-password"},
     "expected": {"op": "in", "value": ["no", "prohibit-password"]},
     "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config.d/."}

Results are reported as deviations from the supplied baseline, never as
formal compliance or certification.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

FORMAT = "psa-baseline-1"
MAX_FILE_BYTES = 2_000_000
MAX_RULES = 2000
SEVERITIES = ("critical", "high", "medium", "low", "informational")
OPS = ("eq", "ne", "in", "not_in", "ge", "le", "gt", "lt", "exists", "absent", "contains", "not_contains",
       "mode_max")

_ID = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_LINUX_PATH = re.compile(r"^/[A-Za-z0-9._/@+-]{1,254}$")
_REG_PATH = re.compile(r"^HK(LM|CU):\\[A-Za-z0-9 _.\-\\{}()]{1,250}$")
_REG_NAME = re.compile(r"^[A-Za-z0-9 _.\-]{1,100}$")
_SIMPLE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,99}$")
_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:-]{0,99}$")
_SYSCTL = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_*-]+)+$")
_SSHD_KEY = re.compile(r"^[a-z0-9]{2,40}$")
_GUID = re.compile(r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$", re.I)

# Files a baseline may never read, even though the collectors only return one value.
SECRET_PATTERNS = ("/etc/shadow*", "/etc/gshadow*", "/etc/ssh/ssh_host_*_key", "/etc/ssl/private/*", "*.key",
                   "/root/*", "/home/*", "/proc/*/environ", "/etc/security/opasswd", "*/.ssh/*", "*.p12", "*.pfx")

# collector type -> (os family, {param: validator}, required params, needs admin)
COLLECTORS: dict[str, tuple[str, dict[str, Any], tuple[str, ...], bool]] = {
    "sshd": ("linux", {"key": _SSHD_KEY}, ("key",), False),
    "sysctl": ("linux", {"name": _SYSCTL}, ("name",), False),
    "file_kv": ("linux", {"path": _LINUX_PATH, "key": _SIMPLE, "separator": re.compile(r"^(=|:|whitespace)$")},
                ("path", "key"), False),
    "file_contains": ("linux", {"path": _LINUX_PATH, "text": re.compile(r"^[^\n\r]{1,200}$")}, ("path", "text"),
                      False),
    "file_mode": ("linux", {"path": _LINUX_PATH, "owner_uid": int}, ("path",), False),
    "package": ("any", {"name": _PACKAGE}, ("name",), False),
    "service": ("linux", {"unit": _UNIT, "property": re.compile(r"^(enabled|active)$")}, ("unit", "property"),
                False),
    "registry": ("windows", {"path": _REG_PATH, "name": _REG_NAME}, ("path", "name"), False),
    "net_accounts": ("windows", {"key": re.compile(r"^(min_length|history|lockout_threshold|max_age|"
                                                   r"lockout_duration)$")}, ("key",), False),
    "windows_service": ("windows", {"name": _SIMPLE, "property": re.compile(r"^(start_type|status)$")},
                        ("name", "property"), False),
    "auditpol": ("windows", {"guid": _GUID}, ("guid",), True),
}


READS_CONTENT = ("file_kv", "file_contains")   # file_mode only reads metadata


class BaselineError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    check_type: str
    params: dict[str, Any]
    op: str
    expected: Any
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    verification: str = ""
    reference: str = ""
    case_sensitive: bool = False

    @property
    def needs_admin(self) -> bool:
        return COLLECTORS[self.check_type][3]


@dataclass
class Baseline:
    name: str
    version: str
    source: str
    os_family: str
    distros: list[str]
    rules: list[Rule]
    path: Path | None = None
    sha256: str = ""
    description: str = ""
    warnings: list[str] = field(default_factory=list)

    def applies_to(self, os_family: str, distro: str = "") -> bool:
        if self.os_family not in (os_family, "any"):
            return False
        return not self.distros or distro in self.distros


def _text(d: dict[str, Any], key: str, where: str, max_len: int, required: bool = False) -> str:
    value = d.get(key, "")
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise BaselineError(f"{where}: '{key}' must be text")
    if required and not value.strip():
        raise BaselineError(f"{where}: '{key}' is required")
    if len(value) > max_len:
        raise BaselineError(f"{where}: '{key}' is longer than {max_len} characters")
    return value.strip()


def is_secret_path(path: str) -> bool:
    return any(fnmatch(path, pattern) for pattern in SECRET_PATTERNS)


def _validate_params(check_type: str, raw: dict[str, Any], where: str, baseline_os: str) -> dict[str, Any]:
    if check_type not in COLLECTORS:
        raise BaselineError(f"{where}: unknown check type '{check_type}' (allowed: {', '.join(sorted(COLLECTORS))})")
    os_family, validators, required, _admin = COLLECTORS[check_type]
    if os_family != "any" and baseline_os not in (os_family, "any"):
        raise BaselineError(f"{where}: check type '{check_type}' is only available on {os_family}")
    params: dict[str, Any] = {}
    for key, value in raw.items():
        if key in ("type", "default"):
            continue
        validator = validators.get(key)
        if validator is None:
            raise BaselineError(f"{where}: unknown parameter '{key}' for check type '{check_type}'")
        if validator is int:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise BaselineError(f"{where}: '{key}' must be a non-negative integer")
        elif not isinstance(value, str) or not validator.match(value):
            raise BaselineError(f"{where}: invalid value for '{key}': {str(value)[:80]!r}")
        params[key] = value
    missing = [k for k in required if k not in params]
    if missing:
        raise BaselineError(f"{where}: missing parameter(s) {', '.join(missing)}")
    path = params.get("path")
    if path is not None and ".." in path.split("/"):
        raise BaselineError(f"{where}: path traversal ('..') is not permitted")
    # '//etc/shadow', '/etc/./shadow' or a trailing '/' would slip past the secret-file patterns.
    if path is not None and (path.startswith("//") or posixpath.normpath(path) != path):
        raise BaselineError(f"{where}: path '{path}' must be written in canonical form "
                            f"(e.g. '{posixpath.normpath('/' + path.lstrip('/'))}')")
    if path is not None and check_type in READS_CONTENT and is_secret_path(path):
        raise BaselineError(f"{where}: reading the contents of '{path}' is not permitted (may contain secrets); "
                            "use file_mode to check its permissions instead")
    if "default" in raw:
        if not isinstance(raw["default"], (str, int, float, bool)):
            raise BaselineError(f"{where}: 'default' must be a single value")
        params["default"] = raw["default"]
    return params


def _validate_expected(raw: Any, check_type: str, where: str) -> tuple[str, Any]:
    if not isinstance(raw, dict) or raw.get("op") not in OPS:
        raise BaselineError(f"{where}: 'expected' needs an 'op' from {', '.join(OPS)}")
    op, value = raw["op"], raw.get("value")
    if op in ("exists", "absent"):
        return op, None
    if op in ("in", "not_in"):
        if not isinstance(value, list) or not value or len(value) > 100 or \
                not all(isinstance(v, (str, int, float, bool)) for v in value):
            raise BaselineError(f"{where}: '{op}' needs a non-empty list of simple values")
        return op, value
    if op == "mode_max":
        if check_type != "file_mode" or not isinstance(value, str) or not re.fullmatch(r"0?[0-7]{3,4}", value):
            raise BaselineError(f"{where}: 'mode_max' needs an octal mode like \"0644\" and check type file_mode")
        return op, int(value, 8)
    if check_type == "file_mode":
        raise BaselineError(f"{where}: file_mode rules use op 'mode_max'")
    if not isinstance(value, (str, int, float, bool)):
        raise BaselineError(f"{where}: '{op}' needs a single value")
    if op in ("ge", "le", "gt", "lt") and to_number(value) is None:
        raise BaselineError(f"{where}: '{op}' needs a numeric value")
    return op, value


def parse_baseline(data: dict[str, Any], path: Path | None = None) -> Baseline:
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise BaselineError(f"not a baseline file (expected \"format\": \"{FORMAT}\")")
    name = _text(data, "name", "baseline", 100, True)
    applies = data.get("applies_to") or {}
    if not isinstance(applies, dict):
        raise BaselineError("baseline: 'applies_to' must be an object")
    os_family = str(applies.get("os_family", "")).lower()
    if os_family not in ("windows", "linux", "any"):
        raise BaselineError("baseline: applies_to.os_family must be windows, linux or any")
    distros = applies.get("distro") or []
    if not isinstance(distros, list) or not all(isinstance(d, str) and _SIMPLE.match(d) for d in distros):
        raise BaselineError("baseline: applies_to.distro must be a list of distribution IDs")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise BaselineError("baseline: 'rules' must be a non-empty list")
    if len(raw_rules) > MAX_RULES:
        raise BaselineError(f"baseline: more than {MAX_RULES} rules")
    rules, seen = [], set()
    for i, r in enumerate(raw_rules, 1):
        where = f"rule #{i}"
        if not isinstance(r, dict):
            raise BaselineError(f"{where}: must be an object")
        rid = r.get("id")
        if not isinstance(rid, str) or not _ID.match(rid):
            raise BaselineError(f"{where}: 'id' must match [A-Za-z0-9._-]{{1,40}}")
        where = f"rule {rid}"
        if rid in seen:
            raise BaselineError(f"{where}: duplicate id")
        seen.add(rid)
        severity = str(r.get("severity", "medium")).lower()
        if severity not in SEVERITIES:
            raise BaselineError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
        check = r.get("check")
        if not isinstance(check, dict) or not isinstance(check.get("type"), str):
            raise BaselineError(f"{where}: 'check' needs a 'type'")
        params = _validate_params(check["type"], check, where, os_family)
        op, expected = _validate_expected(r.get("expected"), check["type"], where)
        rules.append(Rule(
            id=rid, title=_text(r, "title", where, 200, True), severity=severity, check_type=check["type"],
            params=params, op=op, expected=expected, description=_text(r, "description", where, 2000),
            rationale=_text(r, "rationale", where, 2000), remediation=_text(r, "remediation", where, 2000),
            verification=_text(r, "verification", where, 1000), reference=_text(r, "reference", where, 200),
            case_sensitive=bool(r.get("case_sensitive", False))))
    return Baseline(name=name, version=_text(data, "version", "baseline", 40) or "1",
                    source=_text(data, "source", "baseline", 300), os_family=os_family, distros=distros,
                    rules=rules, path=path, description=_text(data, "description", "baseline", 2000))


def read_baseline_bytes(path: Path) -> bytes:
    from psatoolkit.core.paths import read_limited
    try:
        return read_limited(path, MAX_FILE_BYTES)
    except OSError as exc:
        raise BaselineError(f"{path}: cannot read: {exc.strerror or exc}") from None


def load_baseline(path: Path) -> Baseline:
    return parse_baseline_bytes(read_baseline_bytes(path), path)


def parse_baseline_bytes(raw: bytes, path: Path) -> Baseline:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BaselineError(f"{path.name}: invalid JSON: {exc}") from None
    baseline = parse_baseline(data, path)
    baseline.sha256 = hashlib.sha256(raw).hexdigest()
    return baseline


def load_directory(directory: Path) -> tuple[list[Baseline], list[str]]:
    baselines, errors = [], []
    if not directory.is_dir():
        return baselines, errors
    for path in sorted(directory.glob("*.json")):
        try:
            baselines.append(load_baseline(path))
        except BaselineError as exc:
            errors.append(f"{path.name}: {exc}")
    return baselines, errors


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d+(\.\d+)?\s*", value):
        return float(value)
    return None


def _norm(value: Any, case_sensitive: bool) -> Any:
    num = to_number(value)
    if num is not None:
        return num
    if isinstance(value, str):
        text = value.strip()
        return text if case_sensitive else text.lower()
    return value


def evaluate(rule: Rule, actual: Any) -> bool:
    """True if ``actual`` satisfies the rule. ``actual`` None means 'not set / not present'."""
    op, exp = rule.op, rule.expected
    if op == "exists":
        return actual is not None
    if op == "absent":
        return actual is None
    if actual is None:
        return op in ("ne", "not_in", "not_contains")
    if op == "mode_max":
        return (int(actual) & ~exp & 0o7777) == 0
    a = _norm(actual, rule.case_sensitive)
    if op in ("in", "not_in"):
        member = a in [_norm(v, rule.case_sensitive) for v in exp]
        return member if op == "in" else not member
    if op in ("contains", "not_contains"):
        found = str(_norm(exp, rule.case_sensitive)) in str(a)
        return found if op == "contains" else not found
    e = _norm(exp, rule.case_sensitive)
    if op == "eq":
        return a == e
    if op == "ne":
        return a != e
    if not isinstance(a, float) or not isinstance(e, float):
        return False
    return {"ge": a >= e, "le": a <= e, "gt": a > e, "lt": a < e}[op]


def expected_text(rule: Rule) -> str:
    words = {"eq": "equal to", "ne": "not equal to", "in": "one of", "not_in": "none of", "ge": ">=", "le": "<=",
             "gt": ">", "lt": "<", "contains": "containing", "not_contains": "not containing"}
    if rule.op == "exists":
        return "present"
    if rule.op == "absent":
        return "absent"
    if rule.op == "mode_max":
        return f"permissions no wider than {oct(rule.expected)[2:].zfill(4)}"
    return f"{words[rule.op]} {rule.expected}"

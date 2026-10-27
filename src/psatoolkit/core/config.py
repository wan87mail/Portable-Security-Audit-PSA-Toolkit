"""Configuration loading with safe bounds.

Load order: ``config/default.toml`` -> ``config/local.toml`` -> an explicit
file passed on the command line. Numeric values are clamped to hard limits
that no configuration file can exceed.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from psatoolkit.core.validation import HARD_MAX_HOSTS, HARD_MAX_PORTS, ValidationError, parse_ports

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # Ubuntu 22.04 ships Python 3.10
    _toml = None

log = logging.getLogger(__name__)

SUPPORTED_REPORT_FORMATS = ("json", "html", "pdf", "csv")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


class ConfigError(Exception):
    pass


@dataclass
class ExecutionConfig:
    command_timeout_seconds: float = 30.0
    check_timeout_seconds: float = 120.0
    max_output_bytes: int = 2_000_000


@dataclass
class NetworkConfig:
    max_hosts_per_target: int = 256
    max_total_hosts: int = 256
    max_ports: int = 1024
    default_ports: str = "22,80,443,445,3389"
    connect_timeout_seconds: float = 1.5
    max_concurrency: int = 16
    rate_limit_per_second: int = 50
    require_dry_run_preview: bool = True


@dataclass
class ReportingConfig:
    formats: list[str] = field(default_factory=lambda: ["json", "html", "pdf", "csv"])
    include_raw_evidence: bool = True


@dataclass
class VulnDataConfig:
    directory: str = ""            # empty = <USB root>/vulndata
    max_age_days: int = 30


@dataclass
class BaselineConfig:
    directory: str = ""            # empty = <USB root>/baselines
    enabled: list[str] = field(default_factory=list)   # baseline names; empty = all applicable


@dataclass
class AppConfig:
    offline_mode: bool = True
    output_dir: str = ""
    log_level: str = "INFO"
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    vulndata: VulnDataConfig = field(default_factory=VulnDataConfig)
    baselines: BaselineConfig = field(default_factory=BaselineConfig)
    warnings: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


_SECTION = re.compile(r"^\[([A-Za-z0-9_.-]+)\]$")
_KEYVAL = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$")


def _strip_comment(line: str) -> str:
    in_str: str | None = None
    for i, ch in enumerate(line):
        if in_str:
            if ch == in_str:
                in_str = None
        elif ch in "\"'":
            in_str = ch
        elif ch == "#":
            return line[:i]
    return line


def parse_simple_toml(text: str) -> dict[str, Any]:
    """Parse the TOML subset used by PSA config files (Python 3.10 fallback).

    Supports ``[section]`` headers and single-line ``key = value`` pairs whose
    values are strings, integers, floats, booleans or flat arrays of those.
    """
    data: dict[str, Any] = {}
    current = data
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if m := _SECTION.match(line):
            current = data
            for part in m.group(1).split("."):
                current = current.setdefault(part, {})
            continue
        m = _KEYVAL.match(line)
        if not m:
            raise ValueError(f"line {lineno}: unsupported syntax")
        value = m.group(2).strip()
        try:
            parsed = {"true": True, "false": False}[value] if value in ("true", "false") \
                else ast.literal_eval(value)
        except (ValueError, SyntaxError):
            raise ValueError(f"line {lineno}: invalid value") from None
        if not isinstance(parsed, (str, int, float, bool, list)):
            raise ValueError(f"line {lineno}: unsupported value type")
        current[m.group(1)] = parsed
    return data


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read: {exc}") from None
    try:
        if _toml is not None:
            return _toml.loads(raw.decode("utf-8"))
        return parse_simple_toml(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:  # TOMLDecodeError subclasses ValueError
        raise ConfigError(f"{path}: invalid TOML: {exc}") from None


class _Builder:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.warnings: list[str] = []

    def get(self, section: str, key: str, default: Any, kind: type) -> Any:
        value = self.data.get(section, {}).get(key, default)
        if kind is bool:
            if not isinstance(value, bool):
                self.warnings.append(f"[{section}].{key} must be true/false; using {default}")
                return default
            return value
        if kind in (int, float):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                self.warnings.append(f"[{section}].{key} must be a number; using {default}")
                return default
            return kind(value)
        if kind is str:
            if not isinstance(value, str):
                self.warnings.append(f"[{section}].{key} must be a string; using {default!r}")
                return default
            return value
        return value

    def clamp(self, section: str, key: str, value: float, lo: float, hi: float) -> Any:
        if value < lo or value > hi:
            clamped = min(max(value, lo), hi)
            self.warnings.append(f"[{section}].{key}={value} is outside {lo}..{hi}; using {clamped}")
            return type(value)(clamped)
        return value


def build_config(data: dict[str, Any]) -> AppConfig:
    b = _Builder(data)
    cfg = AppConfig()
    cfg.offline_mode = b.get("general", "offline_mode", True, bool)
    cfg.output_dir = b.get("general", "output_dir", "", str)

    level = b.get("logging", "level", "INFO", str).upper()
    if level not in LOG_LEVELS:
        b.warnings.append(f"[logging].level '{level}' is unknown; using INFO")
        level = "INFO"
    cfg.log_level = level

    ex = cfg.execution
    ex.command_timeout_seconds = b.clamp("execution", "command_timeout_seconds",
                                         b.get("execution", "command_timeout_seconds", 30.0, float), 1.0, 600.0)
    ex.check_timeout_seconds = b.clamp("execution", "check_timeout_seconds",
                                       b.get("execution", "check_timeout_seconds", 120.0, float), 5.0, 3600.0)
    ex.max_output_bytes = b.clamp("execution", "max_output_bytes",
                                  b.get("execution", "max_output_bytes", 2_000_000, int), 10_000, 50_000_000)

    n = cfg.network
    n.max_hosts_per_target = b.clamp("network", "max_hosts_per_target",
                                     b.get("network", "max_hosts_per_target", 256, int), 1, HARD_MAX_HOSTS)
    n.max_total_hosts = b.clamp("network", "max_total_hosts",
                                b.get("network", "max_total_hosts", 256, int), 1, HARD_MAX_HOSTS)
    n.max_ports = b.clamp("network", "max_ports", b.get("network", "max_ports", 1024, int), 1, HARD_MAX_PORTS)
    n.connect_timeout_seconds = b.clamp("network", "connect_timeout_seconds",
                                        b.get("network", "connect_timeout_seconds", 1.5, float), 0.1, 30.0)
    n.max_concurrency = b.clamp("network", "max_concurrency", b.get("network", "max_concurrency", 16, int), 1, 64)
    n.rate_limit_per_second = b.clamp("network", "rate_limit_per_second",
                                      b.get("network", "rate_limit_per_second", 50, int), 1, 200)
    n.require_dry_run_preview = b.get("network", "require_dry_run_preview", True, bool)
    ports = b.get("network", "default_ports", n.default_ports, str)
    try:
        parse_ports(ports, n.max_ports)
        n.default_ports = ports
    except ValidationError as exc:
        b.warnings.append(f"[network].default_ports invalid ({exc}); using {n.default_ports}")

    formats = data.get("reporting", {}).get("formats", ["json"])
    if not isinstance(formats, list) or not formats:
        b.warnings.append("[reporting].formats must be a non-empty list; using ['json']")
        formats = ["json"]
    valid = [f.lower() for f in formats if isinstance(f, str) and f.lower() in SUPPORTED_REPORT_FORMATS]
    if len(valid) != len(formats):
        b.warnings.append(f"[reporting].formats: unsupported entries ignored (supported: {SUPPORTED_REPORT_FORMATS})")
    cfg.reporting.formats = valid or ["json"]
    cfg.reporting.include_raw_evidence = b.get("reporting", "include_raw_evidence", True, bool)

    cfg.vulndata.directory = b.get("vulnerability_data", "directory", "", str)
    cfg.vulndata.max_age_days = b.clamp("vulnerability_data", "max_age_days",
                                        b.get("vulnerability_data", "max_age_days", 30, int), 1, 3650)

    cfg.baselines.directory = b.get("baselines", "directory", "", str)
    enabled = data.get("baselines", {}).get("enabled", [])
    if not isinstance(enabled, list) or not all(isinstance(x, str) for x in enabled):
        b.warnings.append("[baselines].enabled must be a list of baseline names; using all applicable")
        enabled = []
    cfg.baselines.enabled = enabled

    cfg.warnings = b.warnings
    return cfg


def load_config(config_dir: Path, extra_file: Path | None = None) -> AppConfig:
    data: dict[str, Any] = {}
    sources: list[str] = []
    for path in (config_dir / "default.toml", config_dir / "local.toml"):
        if path.is_file():
            data = _deep_merge(data, _read_toml(path))
            sources.append(str(path))
    if extra_file is not None:
        if not extra_file.is_file():
            raise ConfigError(f"Configuration file '{extra_file}' does not exist")
        data = _deep_merge(data, _read_toml(extra_file))
        sources.append(str(extra_file))
    cfg = build_config(data)
    cfg.sources = sources
    for warning in cfg.warnings:
        log.warning("config: %s", warning)
    return cfg

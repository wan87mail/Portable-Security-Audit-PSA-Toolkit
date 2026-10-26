import pytest

from conftest import REPO_ROOT
from psatoolkit.core.config import ConfigError, build_config, load_config, parse_simple_toml


def test_default_config_loads_without_warnings(portable_root):
    cfg = load_config(portable_root / "config")
    assert cfg.offline_mode is True
    assert cfg.network.max_hosts_per_target == 256
    assert cfg.warnings == []


def test_local_override(portable_root):
    (portable_root / "config" / "local.toml").write_text("[network]\nmax_concurrency = 4\n")
    cfg = load_config(portable_root / "config")
    assert cfg.network.max_concurrency == 4
    assert cfg.network.rate_limit_per_second == 50   # untouched default


def test_values_are_clamped_to_hard_limits():
    cfg = build_config({"network": {"max_concurrency": 10_000, "rate_limit_per_second": 0,
                                    "max_hosts_per_target": 65536, "connect_timeout_seconds": 0},
                        "execution": {"command_timeout_seconds": 99999}})
    assert cfg.network.max_concurrency == 64
    assert cfg.network.rate_limit_per_second == 1
    assert cfg.network.max_hosts_per_target == 1024
    assert cfg.network.connect_timeout_seconds == 0.1
    assert cfg.execution.command_timeout_seconds == 600
    assert len(cfg.warnings) == 5


def test_wrong_types_fall_back_to_defaults():
    cfg = build_config({"general": {"offline_mode": "no"}, "network": {"max_ports": "lots", "default_ports": "1;id"},
                        "reporting": {"formats": ["json", "exe"]}, "logging": {"level": "LOUD"}})
    assert cfg.offline_mode is True
    assert cfg.network.max_ports == 1024
    assert ";" not in cfg.network.default_ports
    assert cfg.reporting.formats == ["json"]
    assert cfg.log_level == "INFO"
    assert len(cfg.warnings) == 5


def test_invalid_toml_raises(portable_root):
    (portable_root / "config" / "local.toml").write_text("[network\n")
    with pytest.raises(ConfigError):
        load_config(portable_root / "config")


def test_missing_explicit_file(portable_root):
    with pytest.raises(ConfigError):
        load_config(portable_root / "config", portable_root / "nope.toml")


def test_python310_fallback_parser_matches_tomllib():
    tomllib = pytest.importorskip("tomllib")
    text = (REPO_ROOT / "config" / "default.toml").read_text()
    assert parse_simple_toml(text) == tomllib.loads(text)
    assert parse_simple_toml('a = "x # not a comment" # real comment\n') == {"a": "x # not a comment"}
    with pytest.raises(ValueError):
        parse_simple_toml("x = __import__('os')")

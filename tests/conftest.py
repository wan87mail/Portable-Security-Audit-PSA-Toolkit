"""Shared fixtures. Tests use mock OS data and temporary portable roots only."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from psatoolkit.core.authorization import create_authorization
from psatoolkit.core.config import AppConfig
from psatoolkit.core.osdetect import SUPPORTED, OSInfo

REPO_ROOT = Path(__file__).resolve().parents[1]

# A harmless long-running command available on every supported OS (for stop/timeout tests).
if sys.platform.startswith("win"):
    LONG_COMMAND = ["ping", "-n", "30", "127.0.0.1"]
else:
    LONG_COMMAND = ["sleep", "20"]
LONG_COMMAND_POLICY_RULES = {LONG_COMMAND[0]: lambda args: None}

LINUX_OS = OSInfo(family="linux", name="Ubuntu 24.04 LTS", version="24.04", build="6.8.0",
                  architecture="x86_64", is_server=True, support_level=SUPPORTED, distro_id="ubuntu")
WINDOWS_OS = OSInfo(family="windows", name="Windows 11 (Professional)", version="10.0.22631",
                    build="22631", architecture="x86_64", is_server=False, support_level=SUPPORTED)


@pytest.fixture
def portable_root(tmp_path: Path) -> Path:
    """A temporary USB-like root containing the default configuration."""
    root = tmp_path / "PortableSecurityAudit"
    (root / "config").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "config" / "default.toml", root / "config" / "default.toml")
    for d in ("reports", "logs", "checksums", "docs"):
        (root / d).mkdir()
    return root


@pytest.fixture
def config() -> AppConfig:
    cfg = AppConfig()
    cfg.execution.check_timeout_seconds = 5
    return cfg


@pytest.fixture
def authorization():
    return create_authorization(operator="Test Operator", organization="Example Org",
                                engagement_reference="CHG-0001", scope_statement="Unit tests",
                                host="test-host", confirmed=True, method="cli-argument")

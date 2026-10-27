import sys

import pytest

from psatoolkit.core import osdetect
from psatoolkit.core.osdetect import (BEST_EFFORT, SUPPORTED, UNSUPPORTED, classify_linux, classify_windows,
                                      detect_os, normalize_arch, parse_os_release, windows_machine,
                                      windows_version_info)

UBUNTU_2404 = '''PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
# comment line
'''


@pytest.mark.parametrize("version,edition,name,server,support", [
    ("10.0.19045", "Professional", "Windows 10", False, SUPPORTED),
    ("10.0.22631", "Enterprise", "Windows 11", False, SUPPORTED),
    ("10.0.26100", "Professional", "Windows 11", False, SUPPORTED),
    ("10.0.17763", "ServerStandard", "Windows Server 2019", True, SUPPORTED),
    ("10.0.20348", "ServerDatacenter", "Windows Server 2022", True, SUPPORTED),
    ("10.0.26100", "ServerStandard", "Windows Server 2025", True, SUPPORTED),
    ("10.0.25398", "ServerStandard", "Windows Server (build 25398)", True, BEST_EFFORT),
    ("6.1.7601", "Professional", "Windows 7", False, UNSUPPORTED),
])
def test_classify_windows(version, edition, name, server, support):
    info = classify_windows(version.split(".")[0] if not version.startswith("6.1") else "7", version, edition, "AMD64")
    assert info.family == "windows"
    assert info.name.startswith(name)
    assert info.is_server is server
    assert info.support_level == support
    assert info.architecture == "x86_64"


def test_classify_windows_handles_garbage_version():
    info = classify_windows("", "garbage", "", "ARM64")
    assert info.support_level == UNSUPPORTED
    assert info.architecture == "arm64"


def test_parse_os_release_strips_quotes_and_comments():
    data = parse_os_release(UBUNTU_2404)
    assert data["PRETTY_NAME"] == "Ubuntu 24.04.1 LTS"
    assert data["ID"] == "ubuntu"
    assert "# comment line" not in data


@pytest.mark.parametrize("text,support,distro", [
    (UBUNTU_2404, SUPPORTED, "ubuntu"),
    ('ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"', SUPPORTED, "ubuntu"),
    ('ID=ubuntu\nVERSION_ID="20.04"', BEST_EFFORT, "ubuntu"),
    ('ID=debian\nVERSION_ID="12"', BEST_EFFORT, "debian"),
    ('ID=rocky\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"', BEST_EFFORT, "rocky"),
    ('ID=alpine\nVERSION_ID=3.20.0', BEST_EFFORT, "alpine"),
    ("", BEST_EFFORT, "linux"),
])
def test_classify_linux(text, support, distro):
    info = classify_linux(parse_os_release(text), "6.8.0-45-generic", "x86_64", has_desktop=False)
    assert info.family == "linux"
    assert info.support_level == support
    assert info.distro_id == distro
    assert info.is_server is True
    if support != SUPPORTED:
        assert info.notes


def test_desktop_linux_is_not_server():
    info = classify_linux(parse_os_release(UBUNTU_2404), "6.8.0", "aarch64", has_desktop=True)
    assert info.is_server is False
    assert info.architecture == "arm64"


@pytest.mark.parametrize("raw,expected", [("AMD64", "x86_64"), ("x86_64", "x86_64"), ("aarch64", "arm64"),
                                          ("i686", "x86"), ("", "unknown"), ("riscv64", "riscv64")])
def test_normalize_arch(raw, expected):
    assert normalize_arch(raw) == expected


def test_detect_os_linux_reads_os_release(tmp_path, monkeypatch):
    path = tmp_path / "os-release"
    path.write_text(UBUNTU_2404)
    monkeypatch.setattr(osdetect.sys, "platform", "linux")
    info = osdetect.detect_os(str(path))
    assert info.family == "linux" and info.version == "24.04"


def test_detect_os_linux_missing_os_release(tmp_path, monkeypatch):
    monkeypatch.setattr(osdetect.sys, "platform", "linux")
    info = osdetect.detect_os(str(tmp_path / "nope"))
    assert info.family == "linux" and info.support_level == BEST_EFFORT


def test_detect_os_windows(monkeypatch):
    monkeypatch.setattr(osdetect.sys, "platform", "win32")
    monkeypatch.setattr(osdetect.sys, "getwindowsversion", lambda: _WinVer(10, 0, 20348, product_type=3),
                        raising=False)
    monkeypatch.setattr(osdetect.platform, "win32_edition", lambda: "ServerDatacenter", raising=False)
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    info = osdetect.detect_os()
    assert info.name.startswith("Windows Server 2022") and info.architecture == "x86_64"
    # a server whose edition string lacks "Server" is still classified as a server (product_type)
    monkeypatch.setattr(osdetect.platform, "win32_edition", lambda: "", raising=False)
    assert osdetect.detect_os().is_server


class _WinVer(tuple):
    """Shape of ``sys.getwindowsversion()``: a tuple with named attributes."""

    def __new__(cls, major, minor, build, product_type=1, platform_version=None):
        obj = super().__new__(cls, (major, minor, build, 2, ""))
        obj.product_type = product_type
        obj.platform_version = platform_version
        return obj


def test_windows_version_info_without_processes():
    assert windows_version_info(_WinVer(10, 0, 22631)) == ("10", "10.0.22631", False)
    assert windows_version_info(_WinVer(10, 0, 20348, product_type=3)) == ("10", "10.0.20348", True)
    assert windows_version_info(_WinVer(10, 0, 26100, product_type=2))[2] is True     # domain controller
    # platform_version (real kernel version) wins over a compatibility-shimmed tuple
    assert windows_version_info(_WinVer(6, 2, 9200, platform_version=(10, 0, 26100)))[1] == "10.0.26100"
    assert windows_version_info(_WinVer(6, 1, 7601))[0] == "7"


def test_windows_machine_prefers_wow64_variable():
    assert windows_machine({"PROCESSOR_ARCHITECTURE": "x86", "PROCESSOR_ARCHITEW6432": "AMD64"}) == "AMD64"
    assert windows_machine({"PROCESSOR_ARCHITECTURE": "ARM64"}) == "ARM64"
    assert windows_machine({}) == ""


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows host detection")
def test_detect_os_on_windows_starts_no_processes(monkeypatch):
    import subprocess

    def no_popen(*a, **k):
        raise AssertionError(f"OS detection started a process: {a}")
    monkeypatch.setattr(subprocess, "Popen", no_popen)
    info = detect_os()
    assert info.family == "windows" and int(info.build) >= 10240 and info.architecture != "unknown"

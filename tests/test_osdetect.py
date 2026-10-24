import pytest

from psatoolkit.core import osdetect
from psatoolkit.core.osdetect import (BEST_EFFORT, SUPPORTED, UNSUPPORTED, classify_linux, classify_windows,
                                      normalize_arch, parse_os_release)

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
    monkeypatch.setattr(osdetect.platform, "win32_ver", lambda: ("10", "10.0.20348", "", "Multiprocessor Free"))
    monkeypatch.setattr(osdetect.platform, "win32_edition", lambda: "ServerDatacenter", raising=False)
    info = osdetect.detect_os()
    assert info.name.startswith("Windows Server 2022")

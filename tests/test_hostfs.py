"""HostFS: read-only, regular files only, symlinks resolved safely (security review, Phase 9)."""

import os
import sys
import threading

import pytest

from psatoolkit.core.hostfs import HostFS

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX file types")


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "conf").write_text("a=1\n")
    return tmp_path


def test_reads_regular_files(tree):
    fs = HostFS(tree)
    assert fs.try_read("/etc/conf") == ("a=1\n", None)
    assert fs.try_read("/etc/missing") == (None, "missing")


def test_directories_are_not_read(tree):
    text, err = HostFS(tree).try_read("/etc")
    assert text is None and err.startswith("error")


@posix_only
def test_fifo_is_refused_without_blocking(tree):
    os.mkfifo(tree / "etc" / "pipe")
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", HostFS(tree).try_read("/etc/pipe")), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "reading a FIFO must not block"
    assert out["r"][0] is None and "not a regular file" in out["r"][1]


@posix_only
def test_device_nodes_are_never_opened():
    # /dev/null is harmless, but the same path is taken for /dev/watchdog, which arms a reboot timer.
    text, err = HostFS("/").try_read("/dev/null")
    assert text is None and "not a regular file" in err


@posix_only
def test_symlinks_inside_root_are_followed_and_resolved(tree):
    os.symlink("conf", tree / "etc" / "link")
    fs = HostFS(tree)
    assert fs.try_read("/etc/link") == ("a=1\n", None)
    assert fs.resolve("/etc/link") == "/etc/conf"


@posix_only
def test_symlinks_escaping_a_test_root_are_not_followed(tree, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret"
    outside.write_text("secret")
    os.symlink(outside, tree / "etc" / "escape")
    fs = HostFS(tree)
    assert fs.try_read("/etc/escape") == (None, "missing")
    assert fs.resolve("/etc/escape") is None

"""Phase 8: frozen-build root discovery, self-test, USB preparation and build files."""

import importlib.util
import json
import sys

import pytest

from conftest import REPO_ROOT
from psatoolkit import cli
from psatoolkit.core import paths
from psatoolkit.core.integrity import verify_manifest


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prepare_usb = load_script("prepare_usb")


# -- root discovery for frozen builds -------------------------------------------------------------

def make_drive(tmp_path):
    root = tmp_path / "PSA"
    (root / "config").mkdir(parents=True)
    (root / "config" / "default.toml").write_text("")
    return root


@pytest.mark.parametrize("exe_rel", ["PortableSecurityAudit.exe",
                                     "linux/PortableSecurityAudit/PortableSecurityAudit",
                                     "linux/PortableSecurityAudit"])
def test_frozen_root_discovery(tmp_path, monkeypatch, exe_rel):
    root = make_drive(tmp_path)
    exe = root / exe_rel
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setenv("PSA_HOME", str(tmp_path / "attacker-controlled"))   # ignored for frozen builds
    assert paths.discover_root() == root.resolve()


def test_frozen_without_marker_uses_exe_dir(tmp_path, monkeypatch):
    exe = tmp_path / "loose" / "PortableSecurityAudit.exe"
    exe.parent.mkdir()
    exe.write_text("")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    assert paths.discover_root() == exe.parent.resolve()


def test_source_run_honours_psa_home(tmp_path, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setenv("PSA_HOME", str(tmp_path))
    assert paths.discover_root() == tmp_path.resolve()


# -- self-test ---------------------------------------------------------------------------------------

def test_selftest_reports_components(portable_root, capsys):
    assert cli.main(["--root", str(portable_root), "selftest"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    for part in ("sha256", "PDF writer", "configuration", "GUI (Tkinter)", "Self-test passed"):
        assert part in out
    gui_ok = "[OK] GUI" in out
    expected = cli.EXIT_OK if gui_ok else cli.EXIT_ERROR
    assert cli.main(["--root", str(portable_root), "selftest", "--require-gui"]) == expected


# -- USB preparation ------------------------------------------------------------------------------------

def fake_builds(tmp_path):
    win = tmp_path / "dist" / "windows" / "PortableSecurityAudit"
    (win / "_internal").mkdir(parents=True)
    (win / "PortableSecurityAudit.exe").write_bytes(b"MZ fake exe")
    (win / "_internal" / "python312.dll").write_bytes(b"fake dll")
    lin = tmp_path / "dist" / "linux" / "PortableSecurityAudit"
    (lin / "_internal").mkdir(parents=True)
    (lin / "PortableSecurityAudit").write_bytes(b"\x7fELF fake")
    return win, lin


def test_prepare_full_drive(tmp_path):
    win, lin = fake_builds(tmp_path)
    target = tmp_path / "usb" / "PortableSecurityAudit"
    result = prepare_usb.prepare(target, win, lin, True, None,
                                 [REPO_ROOT / "baselines" / "examples" / "example-ubuntu-server.json"], False)
    for rel in ("PortableSecurityAudit.exe", "_internal/python312.dll", "linux/PortableSecurityAudit/PortableSecurityAudit",
                "app/psatoolkit/cli.py", "PortableSecurityAudit.sh", "PortableSecurityAudit-source.bat",
                "config/default.toml", "docs/USER_GUIDE.md", "baselines/examples/example-windows-workstation.json",
                "baselines/Example_Ubuntu_Server_Baseline.json", "README.md", "LICENSES.md", "RELEASE-INFO.txt",
                "checksums/manifest.json"):
        assert (target / rel).exists(), rel
    for d in ("reports", "logs", "vulndata", "tools/windows", "tools/linux"):
        assert (target / d).is_dir()
    assert not list(target.rglob("__pycache__"))
    assert verify_manifest(target).ok and len(result["manifest_sha256"]) == 64
    manifest = json.loads((target / "checksums" / "manifest.json").read_text())
    assert "PortableSecurityAudit.exe" in manifest["files"] and "linux/PortableSecurityAudit/PortableSecurityAudit" in manifest["files"]


def test_prepare_refuses_foreign_and_existing_dirs(tmp_path):
    win, _ = fake_builds(tmp_path)
    foreign = tmp_path / "Documents"
    foreign.mkdir()
    (foreign / "thesis.docx").write_text("precious")
    with pytest.raises(prepare_usb.PrepareError, match="not a Portable Security Audit drive"):
        prepare_usb.prepare(foreign, win, None, True, None, [], False)
    assert (foreign / "thesis.docx").read_text() == "precious"
    target = tmp_path / "usb"
    prepare_usb.prepare(target, win, None, True, None, [], False)
    with pytest.raises(prepare_usb.PrepareError, match="--update"):
        prepare_usb.prepare(target, win, None, True, None, [], False)


def test_update_keeps_reports_and_local_settings(tmp_path):
    win, lin = fake_builds(tmp_path)
    target = tmp_path / "usb"
    prepare_usb.prepare(target, win, None, True, None, [], False)
    (target / "reports" / "PSA-1").mkdir()
    (target / "reports" / "PSA-1" / "report.json").write_text("{}")
    (target / "config" / "local.toml").write_text("[general]\n")
    (target / "baselines" / "Mine.json").write_text("{}")
    (win / "PortableSecurityAudit.exe").write_bytes(b"MZ new version")
    prepare_usb.prepare(target, win, lin, True, None, [], True)
    assert (target / "reports" / "PSA-1" / "report.json").exists()
    assert (target / "config" / "local.toml").exists() and (target / "baselines" / "Mine.json").exists()
    assert (target / "PortableSecurityAudit.exe").read_bytes() == b"MZ new version"
    assert (target / "linux" / "PortableSecurityAudit" / "PortableSecurityAudit").exists()


def test_prepare_validates_inputs_before_writing(tmp_path):
    win, _ = fake_builds(tmp_path)
    bad = tmp_path / "bad-baseline.json"
    bad.write_text(json.dumps({"format": "psa-baseline-1", "name": "x", "applies_to": {"os_family": "linux"},
                               "rules": [{"id": "A", "title": "t", "check": {"type": "shell"}, "expected": {"op": "exists"}}]}))
    target = tmp_path / "usb"
    with pytest.raises(prepare_usb.PrepareError, match="baseline"):
        prepare_usb.prepare(target, win, None, True, None, [bad], False)
    assert not target.exists()
    with pytest.raises(prepare_usb.PrepareError, match="vulnerability data"):
        prepare_usb.prepare(target, win, None, True, tmp_path / "missing-vulndata", [], False)
    with pytest.raises(prepare_usb.PrepareError, match="PortableSecurityAudit.exe"):
        prepare_usb.prepare(target, tmp_path, None, True, None, [], False)


def test_cli_main_exit_codes(tmp_path, capsys):
    win, _ = fake_builds(tmp_path)
    assert prepare_usb.main([str(tmp_path / "usb"), "--windows-build", str(win)]) == 0
    assert "Manifest SHA-256:" in capsys.readouterr().out
    assert prepare_usb.main([str(tmp_path / "usb"), "--windows-build", str(win)]) == 1


# -- build files ---------------------------------------------------------------------------------------------

def test_build_files_are_consistent():
    spec = (REPO_ROOT / "packaging" / "psa.spec").read_text()
    assert "uac_admin=False" in spec and "upx=False" in spec and "psatoolkit.gui.app" in spec
    reqs = (REPO_ROOT / "requirements-build.txt").read_text()
    assert any(line.startswith("pyinstaller==") for line in reqs.splitlines())   # pinned
    workflow = (REPO_ROOT / ".github" / "workflows" / "build.yml").read_text()
    assert "permissions:" in workflow and "contents: read" in workflow
    assert "selftest --require-gui" in workflow

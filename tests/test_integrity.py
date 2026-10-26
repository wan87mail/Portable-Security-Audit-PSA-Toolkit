import json

from psatoolkit.core.integrity import verify_manifest, write_manifest


def _populate(root):
    (root / "app").mkdir()
    (root / "app" / "main.py").write_text("print('hi')\n")
    (root / "tools").mkdir()
    (root / "tools" / "nmap").write_bytes(b"\x7fELF fake")
    (root / "reports" / "old").mkdir(parents=True)
    (root / "reports" / "old" / "report.json").write_text("{}")
    (root / "config" / "local.toml").write_text("[general]\n")


def test_manifest_round_trip(portable_root):
    _populate(portable_root)
    path, digest = write_manifest(portable_root, "0.2.0")
    manifest = json.loads(path.read_text())
    assert "app/main.py" in manifest["files"]
    assert "config/default.toml" in manifest["files"]
    assert not any(k.startswith("reports/") for k in manifest["files"])
    assert "config/local.toml" not in manifest["files"]
    report = verify_manifest(portable_root)
    assert report.ok, report.summary()
    assert report.manifest_digest == digest
    assert "PASSED" in report.summary()


def test_detects_modified_missing_and_unexpected(portable_root):
    _populate(portable_root)
    write_manifest(portable_root, "0.2.0")
    (portable_root / "app" / "main.py").write_text("print('tampered')\n")
    (portable_root / "tools" / "nmap").unlink()
    (portable_root / "app" / "backdoor.py").write_text("")
    report = verify_manifest(portable_root)
    assert not report.ok
    assert report.modified == ["app/main.py"]
    assert report.missing == ["tools/nmap"]
    assert report.unexpected == ["app/backdoor.py"]
    assert "FAILED" in report.summary()


def test_missing_and_malformed_manifest(portable_root):
    report = verify_manifest(portable_root)
    assert not report.ok and not report.manifest_found
    (portable_root / "checksums" / "manifest.json").write_text("{not json")
    report = verify_manifest(portable_root)
    assert not report.ok and "malformed" in report.error


def test_manifest_path_traversal_entry_flagged(portable_root):
    (portable_root / "checksums" / "manifest.json").write_text(json.dumps(
        {"tool_version": "x", "algorithm": "sha256", "files": {"../outside.txt": "0" * 64}}))
    report = verify_manifest(portable_root)
    assert not report.ok and report.modified

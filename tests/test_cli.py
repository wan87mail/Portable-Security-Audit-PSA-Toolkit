import argparse
import json
import subprocess

import pytest

from psatoolkit import cli

AUTH = ["--operator", "Test Operator", "--reference", "CHG-1", "--confirm", "I AM AUTHORIZED"]


@pytest.fixture
def run(portable_root, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)

    def _run(*args):
        return cli.main(["--root", str(portable_root), *args])
    return _run


def test_demo_audit_end_to_end(run, portable_root, capsys, monkeypatch):
    def no_popen(*a, **k):
        raise AssertionError("demo mode must not start processes")
    monkeypatch.setattr(subprocess, "Popen", no_popen)
    assert run("audit", "--demo", *AUTH) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "AUTHORIZED USE ONLY" in out
    assert "critical=1, high=3" in out
    reports = list((portable_root / "reports").glob("PSA-*/report.json"))
    assert len(reports) == 1
    assert run("verify-report", str(reports[0])) == cli.EXIT_OK
    logs = list((portable_root / "logs").glob("audit-*.jsonl"))
    assert run("verify-log", str(logs[0])) == cli.EXIT_OK
    assert run("reports") == cli.EXIT_OK
    assert "demo" in capsys.readouterr().out


def test_live_local_audit(run, portable_root):
    assert run("audit", *AUTH) == cli.EXIT_OK
    doc = json.loads(next((portable_root / "reports").glob("PSA-*/report.json")).read_text())
    assert doc["assessment"]["mode"] == "live"
    assert doc["assessment"]["authorization"]["operator"] == "Test Operator"


@pytest.mark.parametrize("args", [
    ["audit", "--demo"],                                                    # no confirmation
    ["audit", "--demo", "--operator", "x", "--reference", "y", "--confirm", "yes"],
    ["audit", "--demo", "--reference", "y", "--confirm", "I AM AUTHORIZED"],  # no operator
    ["audit", *AUTH, "--target", "10.0.0.5"],                                # target without reference
    ["audit", *AUTH, "--target", "10.0.0.0/8", "--target-ref", "R"],         # oversized scope
])
def test_authorization_refusals(run, portable_root, args):
    assert run(*args) == cli.EXIT_UNAUTHORIZED
    assert not list((portable_root / "reports").glob("PSA-*"))


def test_unknown_module(run):
    assert run("audit", "--modules", "nope", *AUTH) == cli.EXIT_USAGE


def test_unwritable_output_dir(run, tmp_path):
    assert run("audit", "--demo", "--output", str(tmp_path / "missing"), *AUTH) == cli.EXIT_ERROR


def test_preview_scan_sends_nothing(run, capsys, monkeypatch):
    import socket

    def no_socket(*a, **k):
        raise AssertionError("preview must not open sockets")
    monkeypatch.setattr(socket, "socket", no_socket)
    monkeypatch.setattr(socket, "create_connection", no_socket)
    assert run("preview-scan", "--target", "10.0.0.0/29", "--ports", "22,443") == cli.EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["total_hosts"] == 6 and data["total_connection_attempts"] == 12
    assert run("preview-scan", "--target", "10.0.0.0/16") == cli.EXIT_USAGE


def test_integrity_commands(run, portable_root):
    assert run("verify") == cli.EXIT_INTEGRITY            # no manifest yet
    assert run("build-manifest") == cli.EXIT_OK
    assert run("verify") == cli.EXIT_OK
    (portable_root / "config" / "default.toml").write_text("# tampered\n")
    assert run("verify") == cli.EXIT_INTEGRITY


def test_info_and_modules(run, capsys):
    assert run("info") == cli.EXIT_OK
    assert run("modules", "-v") == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "SYS-ASSET-001" in out and "demo" in out


def test_bad_config_reports_error(run, portable_root):
    (portable_root / "config" / "local.toml").write_text("not = [valid")
    assert run("info") == cli.EXIT_ERROR


def test_targets_and_preview_state_that_no_network_module_is_included(run, portable_root, capsys):
    assert run("preview-scan", "--target", "192.0.2.10", "--ports", "22") == cli.EXIT_OK
    assert "not contacted" in capsys.readouterr().out
    assert run("audit", "--demo", *AUTH, "--target", "192.0.2.10", "--target-ref", "CHG-9") == cli.EXIT_OK
    assert "--target is ignored in demo mode" in capsys.readouterr().err
    tk = cli.Toolkit(root=portable_root)
    args = argparse.Namespace(target=["192.0.2.10"], target_ref=["CHG-9"], confirm="I AM AUTHORIZED")
    cli._add_targets(tk, args)
    captured = capsys.readouterr()
    assert "Authorized target added: 192.0.2.10" in captured.out and cli.NO_NETWORK_NOTE in captured.err

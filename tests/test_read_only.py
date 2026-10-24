"""Guards that the shipped modules stay read-only.

These tests spy on every way the toolkit could change a system: starting
processes outside the safe runner, writing files outside the output folders,
and opening network connections from local modules.
"""

import builtins
import socket
import subprocess
from pathlib import Path

from psatoolkit.core.safe_exec import ReadOnlyPolicy
from psatoolkit.core.session import Toolkit
from psatoolkit.modules import load_modules


def test_only_safe_runner_starts_processes():
    """No module may import subprocess/os.system directly; they must use ctx.runner."""
    modules_dir = Path(__file__).resolve().parents[1] / "src" / "psatoolkit" / "modules"
    for path in modules_dir.glob("*.py"):
        text = path.read_text()
        for forbidden in ("import subprocess", "os.system", "os.popen", "shell=True", "Popen("):
            assert forbidden not in text, f"{path.name} uses {forbidden}"


def test_policy_has_no_generic_interpreters():
    names = set(ReadOnlyPolicy.default().rules)
    assert not names & {"bash", "sh", "cmd", "python", "python3", "perl", "curl", "wget", "rm", "del"}


def test_live_local_assessment_writes_only_to_output(portable_root, authorization, monkeypatch):
    out_dir = portable_root / "reports"
    allowed = [out_dir.resolve(), (portable_root / "logs").resolve()]
    real_open = builtins.open
    writes: list[str] = []

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(m in mode for m in "wax+"):
            resolved = Path(file).resolve()
            if not any(resolved.is_relative_to(a) for a in allowed) and "psa-" not in str(resolved):
                writes.append(str(resolved))
        return real_open(file, mode, *args, **kwargs)

    def no_network(*a, **k):
        raise AssertionError("local modules must not open network connections")

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(socket, "create_connection", no_network)
    started = []
    real_popen = subprocess.Popen
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: started.append(a) or real_popen(*a, **k))

    tk = Toolkit(root=portable_root, elevated=False, hostname="ro-test")
    local = [m.module_id for m in tk.available_modules() if m.category == "local"]
    outcome = tk.run_assessment(authorization, local, output_override=str(out_dir))
    assert outcome.result.status == "completed"
    assert writes == [], f"unexpected writes: {writes}"
    for argv in started:
        exe = Path(argv[0][0]).name
        ReadOnlyPolicy.default().check(exe, argv[0][1:])  # anything started passed the policy


def test_every_registered_check_declares_metadata():
    for module in load_modules():
        assert module.category in {"local", "network", "baseline", "demo"}
        for check in module.checks:
            assert check.check_id and check.title and check.supported_os
            if check.requires_admin:
                assert check.admin_reason, f"{check.check_id} must explain why admin is needed"

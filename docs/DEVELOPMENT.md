# Developer guide

## Environment (Windows 10/11)

```powershell
winget install Python.Python.3.12          # or the python.org installer
git clone <repo-url> PortableSecurityAudit
cd PortableSecurityAudit
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e .
python -m pytest
PortableSecurityAudit audit --demo
```

## Environment (Linux)

```bash
sudo apt install python3-venv python3-tk    # tk only needed for the GUI
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e .
python -m pytest
xvfb-run -a python -m pytest tests/test_gui_smoke.py
```

The runtime has no third-party dependencies and supports Python 3.10+ (Ubuntu
22.04 ships 3.10). Test with the oldest version you deploy to, for example
`uv run --python 3.10 --with pytest python -m pytest`.

## Adding a check

```python
# src/psatoolkit/modules/linux_audit.py  (Phase 3)
from psatoolkit.core.engine import Check, Module, SkipCheck
from psatoolkit.core.models import Severity, FindingStatus, Confidence

class SshRootLoginCheck(Check):
    check_id = "LNX-SSH-001"
    title = "SSH root login"
    supported_os = frozenset({"linux"})
    requires_admin = True
    admin_reason = "'sshd -T' must read host keys to print the effective configuration."
    required_tools = ("sshd",)

    def run(self, ctx):
        res = ctx.runner.run(["sshd", "-T"])          # argument list, policy-checked
        if not res.ok:
            raise SkipCheck(f"sshd -T failed: {res.error or res.stderr.strip()}")
        settings = dict(line.split(" ", 1) for line in res.stdout.splitlines() if " " in line)
        if settings.get("permitrootlogin") != "yes":
            return []
        return [ctx.finding(self, title="SSH permits root login", severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED, component="sshd", ...,
                            evidence=[ctx.evidence("Effective setting", "sshd -T",
                                                   {"permitrootlogin": "yes"})])]
```

Rules for checks:

1. Run external programs only through `ctx.runner.run([...])`. Never import
   `subprocess` in `modules/` (a test enforces this).
2. If a new executable is required, add a read-only rule for it in
   `ReadOnlyPolicy.default()`, plus allow/deny tests in `tests/test_safe_exec.py`.
3. Never read secrets (shadow hashes, private keys, browser data). Collect
   metadata such as permissions and owners instead.
4. Use `FindingStatus.POTENTIAL` and `manual_validation_required=True` when
   the evidence is indirect (for example, version strings).
5. Raise `SkipCheck(reason, category)` when the check cannot conclude.
6. Write a `severity_rationale` that a junior administrator can follow.
7. Register the module in `modules/__init__.py`.

## Release integrity

Run `python scripts/build_manifest.py <drive-root>` as the last step, and
publish the printed manifest SHA-256 through a separate channel.

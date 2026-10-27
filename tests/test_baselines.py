"""Phase 7: Module F security baselines."""

import copy
import json

import pytest

from conftest import LINUX_OS, REPO_ROOT
from fakes import WINDOWS_OS, FakeFS, FakeRunner, make_ctx
from psatoolkit import cli
from psatoolkit.core.baseline import BaselineError, evaluate, load_baseline, load_directory, parse_baseline
from psatoolkit.core.engine import SkipCheck
from psatoolkit.core.models import FindingStatus, Severity
from psatoolkit.modules.baseline_audit import BaselineCheck

EXAMPLES = REPO_ROOT / "baselines" / "examples"


def base(rules, os_family="linux", **extra):
    return {"format": "psa-baseline-1", "name": "Test Baseline", "version": "2", "source": "unit tests",
            "applies_to": {"os_family": os_family, **extra}, "rules": rules}


def rule(rid="R-1", check=None, expected=None, **extra):
    return {"id": rid, "title": f"Rule {rid}", "severity": extra.pop("severity", "medium"),
            "check": check or {"type": "sysctl", "name": "kernel.randomize_va_space"},
            "expected": expected or {"op": "eq", "value": 2}, **extra}


# -- validation ----------------------------------------------------------------------------------------

def test_example_baselines_are_valid():
    ubuntu = load_baseline(EXAMPLES / "example-ubuntu-server.json")
    windows = load_baseline(EXAMPLES / "example-windows-workstation.json")
    assert len(ubuntu.rules) == 21 and ubuntu.applies_to("linux", "ubuntu") and not ubuntu.applies_to("linux", "rhel")
    assert len(windows.rules) == 20 and windows.applies_to("windows") and len(ubuntu.sha256) == 64


@pytest.mark.parametrize("check,message", [
    ({"type": "shell", "cmd": "id"}, "unknown check type"),
    ({"type": "sysctl", "name": "kernel.x; rm -rf /"}, "invalid value"),
    ({"type": "sysctl", "name": "kernel.randomize_va_space", "extra": 1}, "unknown parameter"),
    ({"type": "file_kv", "path": "/etc/../etc/shadow", "key": "x"}, "path traversal"),
    ({"type": "file_kv", "path": "/etc/shadow", "key": "root"}, "not permitted"),
    ({"type": "file_contains", "path": "/etc/ssh/ssh_host_ed25519_key", "text": "BEGIN"}, "not permitted"),
    ({"type": "file_kv", "path": "/home/alice/.bashrc", "key": "x"}, "not permitted"),
    ({"type": "file_kv", "path": "relative/path", "key": "x"}, "invalid value"),
    ({"type": "file_kv", "path": "/etc/login.defs"}, "missing parameter"),
    ({"type": "service", "unit": "-H evil", "property": "enabled"}, "invalid value"),
    ({"type": "package", "name": "$(id)"}, "invalid value"),
    ({"type": "sshd", "key": "PermitRootLogin yes"}, "invalid value"),
    ({"type": "registry", "path": "HKLM:\\SOFTWARE", "name": "x"}, "only available on windows"),
])
def test_malicious_or_invalid_linux_rules_rejected(check, message):
    with pytest.raises(BaselineError, match=message):
        parse_baseline(base([rule(check=check)]))


@pytest.mark.parametrize("path,name", [
    ("HKLM:\\SOFTWARE\\x'; Remove-Item C:\\ -Recurse; '", "v"),
    ("HKLM:\\SOFTWARE\\$(Get-Process)", "v"),
    ("HKLM:\\SOFTWARE\\a`b", "v"),
    ("HKLM:\\SOFTWARE\\ok", "v'|iex"),
    ("C:\\Windows\\System32", "v"),
    ("HKEY_LOCAL_MACHINE\\SOFTWARE", "v"),
])
def test_registry_injection_rejected(path, name):
    with pytest.raises(BaselineError):
        parse_baseline(base([rule(check={"type": "registry", "path": path, "name": name})], "windows"))


def test_shadow_permissions_may_be_checked_but_not_read():
    b = parse_baseline(base([rule(check={"type": "file_mode", "path": "/etc/shadow", "owner_uid": 0},
                                  expected={"op": "mode_max", "value": "0640"})]))
    assert b.rules[0].expected == 0o640


@pytest.mark.parametrize("data,message", [
    ({"format": "other"}, "not a baseline"),
    (base([]), "non-empty list"),
    (base([rule(), rule()]), "duplicate id"),
    (base([rule(rid="bad id!")]), "'id' must match"),
    (base([rule(severity="urgent")]), "severity must be"),
    (base([rule(expected={"op": "regex", "value": ".*"})]), "'op' from"),
    (base([rule(expected={"op": "ge", "value": "abc"})]), "numeric"),
    (base([rule(expected={"op": "in", "value": []})]), "non-empty list"),
    (base([rule(check={"type": "file_mode", "path": "/etc/passwd"}, expected={"op": "eq", "value": 1})]), "mode_max"),
    (base([rule()], os_family="solaris"), "os_family"),
    (base([rule(title="x" * 201)]), "longer than"),
])
def test_structural_validation(data, message):
    with pytest.raises(BaselineError, match=message):
        parse_baseline(data)


def test_load_directory_reports_bad_files(tmp_path):
    (tmp_path / "good.json").write_text(json.dumps(base([rule()])))
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "evil.json").write_text(json.dumps(base([rule(check={"type": "shell"})])))
    baselines, errors = load_directory(tmp_path)
    assert [b.name for b in baselines] == ["Test Baseline"]
    assert len(errors) == 2 and any("invalid JSON" in e for e in errors)


@pytest.mark.parametrize("op,expected,actual,result", [
    ("eq", 2, "2", True), ("eq", "no", "No", True), ("ne", 0, None, True), ("eq", 1, None, False),
    ("in", ["no", "prohibit-password"], "prohibit-password", True), ("not_in", ["Automatic"], None, True),
    ("ge", 14, "8", False), ("le", 4, "4", True), ("gt", 1, 2, True), ("lt", 1, 1, False),
    ("exists", None, "1.0", True), ("absent", None, None, True), ("absent", None, "1.0", False),
    ("contains", "sha512", "SHA512 x", True), ("not_contains", "md5", "sha512", True),
])
def test_evaluate(op, expected, actual, result):
    r = parse_baseline(base([rule(expected={"op": op, "value": expected} if expected is not None else {"op": op})])).rules[0]
    assert evaluate(r, actual) is result


# -- Linux collectors --------------------------------------------------------------------------------------------

LINUX_RULES = [
    rule("SYS", {"type": "sysctl", "name": "kernel.randomize_va_space"}, {"op": "eq", "value": 2}, severity="high"),
    rule("SSH", {"type": "sshd", "key": "permitrootlogin", "default": "prohibit-password"},
         {"op": "in", "value": ["no", "prohibit-password"]}),
    rule("KV", {"type": "file_kv", "path": "/etc/login.defs", "key": "UMASK", "default": "022"},
         {"op": "in", "value": ["027", "077"]}, severity="low"),
    rule("TXT", {"type": "file_contains", "path": "/etc/apt/apt.conf.d/20auto-upgrades", "text": "Unattended-Upgrade \"1\""},
         {"op": "eq", "value": True}),
    rule("MODE", {"type": "file_mode", "path": "/etc/passwd", "owner_uid": 0}, {"op": "mode_max", "value": "0644"},
         severity="high"),
    rule("OWNER", {"type": "file_mode", "path": "/etc/crontab", "owner_uid": 0}, {"op": "mode_max", "value": "0644"}),
    rule("PKG", {"type": "package", "name": "telnetd"}, {"op": "absent"}, severity="high"),
    rule("SVC", {"type": "service", "unit": "ufw", "property": "enabled"}, {"op": "eq", "value": "enabled"}),
    rule("DENIED", {"type": "file_kv", "path": "/etc/secret.conf", "key": "x"}, {"op": "exists"}),
]


def linux_setup(tmp_path, rules=LINUX_RULES, elevated=False):
    (tmp_path / "b.json").write_text(json.dumps(base(rules, distro=["ubuntu"])))
    fs = FakeFS().add("/proc/sys/kernel/randomize_va_space", "2\n") \
        .add("/etc/ssh/sshd_config", "PermitRootLogin yes\n") \
        .add("/etc/login.defs", "UMASK 022\n").add("/etc/passwd", "", mode=0o664) \
        .add("/etc/crontab", "", mode=0o644, uid=1000).add("/etc/secret.conf", None)
    fs.denied.add("/etc/secret.conf")
    runner = FakeRunner().on("dpkg-query", stdout="telnetd\t0.17-44\tii \tnetkit-telnet\t0.17-44\n") \
        .on("systemctl", "is-enabled", "ufw", stdout="disabled\n", returncode=1)
    ctx = make_ctx(LINUX_OS, runner, fs, elevated=elevated)
    ctx.config.baselines.directory = str(tmp_path)
    return ctx, runner


def test_linux_baseline_end_to_end(tmp_path):
    ctx, runner = linux_setup(tmp_path)
    findings = BaselineCheck().run(ctx)
    summary, deviations = findings[0], findings[1:]
    # Only SYS passes; TXT fails because the file is absent; DENIED is inconclusive (not a pass).
    assert summary.severity == Severity.INFO and "1 of 8 evaluated rules met" in summary.title
    titles = {f.title.removeprefix("Baseline deviation: Rule "): f for f in deviations}
    assert set(titles) == {"SSH", "KV", "TXT", "MODE", "OWNER", "PKG", "SVC"}
    assert "observed: not set / not present" in titles["TXT"].description
    assert titles["MODE"].severity == Severity.HIGH and "mode 0664" in titles["MODE"].description
    assert "owner uid 1000" in titles["OWNER"].description
    assert titles["PKG"].status == FindingStatus.CONFIRMED and "observed: 0.17-44" in titles["PKG"].description
    assert "observed: yes" in titles["SSH"].description
    assert any("DENIED" in l.description and "could not be read" in l.description for l in ctx.partial)
    assert ctx.data_sources[0]["passed"] == 1 and ctx.data_sources[0]["inconclusive"] == 1
    assert all(f.references and f.references[0].kind.value == "BASELINE" for f in deviations)


def test_baseline_evidence_contains_only_compared_value(tmp_path):
    ctx, _ = linux_setup(tmp_path)
    ctx.fs.add("/etc/login.defs", "UMASK 022\nSECRET_TOKEN=abc123\n")
    blob = json.dumps([[e.data for e in f.evidence] for f in BaselineCheck().run(ctx)], default=str)
    assert "abc123" not in blob


def test_no_applicable_baseline_is_skip(tmp_path):
    (tmp_path / "w.json").write_text(json.dumps(base([rule(check={"type": "registry", "path": "HKLM:\\SOFTWARE\\X",
                                                                  "name": "v"})], "windows")))
    ctx = make_ctx(LINUX_OS, FakeRunner(), FakeFS())
    ctx.config.baselines.directory = str(tmp_path)
    with pytest.raises(SkipCheck, match="No imported baseline applies"):
        BaselineCheck().run(ctx)


def test_enabled_list_filters_baselines(tmp_path):
    ctx, _ = linux_setup(tmp_path)
    ctx.config.baselines.enabled = ["Some Other Baseline"]
    with pytest.raises(SkipCheck):
        BaselineCheck().run(ctx)


# -- Windows collectors ---------------------------------------------------------------------------------------------

def test_windows_example_baseline_batches_queries_through_policy(tmp_path):
    (tmp_path / "w.json").write_text((EXAMPLES / "example-windows-workstation.json").read_text())
    reg = {"r0.EnableLUA": 1, "r1.ConsentPromptBehaviorAdmin": None, "r2.LmCompatibilityLevel": 5,
           "r3.UseLogonCredential": None, "r4.RunAsPPL": 1, "r5.RequireSecuritySignature": 1,
           "r6.RequireSecuritySignature": 0, "r7.fDenyTSConnections": 0, "r8.EnableMulticast": 0,
           "r9.EnableFirewall": None, "r10.DisableAntiSpyware": None}
    net = "Minimum password length:                              14\nLength of password history maintained:" \
          "                24\nLockout threshold:                                    Never\n"
    runner = FakeRunner().on("powershell", contains="Get-ItemProperty", json_=reg) \
        .on("powershell", contains="Get-Service", json_=[{"Name": "RemoteRegistry", "StartType": "Automatic"}]) \
        .on("net", "accounts", stdout=net)
    ctx = make_ctx(WINDOWS_OS, runner, elevated=False)
    ctx.config.baselines.directory = str(tmp_path)
    findings = BaselineCheck().run(ctx)
    ps_calls = [c for c in runner.calls if c[0] == "powershell"]
    assert len(ps_calls) == 2                                     # one registry batch + one service batch
    failed = sorted(f.title.removeprefix("Baseline deviation: ") for f in findings[1:])
    assert "Administrators are prompted for consent on the secure desktop" in failed    # default 5 not in [1,2]
    assert "Remote Desktop is disabled on workstations" in failed
    assert "SMB client requires signing" in failed and "Account lockout is configured" in failed
    assert "Remote Registry does not start automatically" in failed
    assert "Group Policy does not disable Microsoft Defender" not in failed               # absent -> ne passes
    assert any("AUD-01" in l.description and "privileges" in l.description for l in ctx.partial)


# -- CLI ---------------------------------------------------------------------------------------------------------------

def test_cli_import_and_list(portable_root, tmp_path, capsys):
    run = lambda *a: cli.main(["--root", str(portable_root), *a])  # noqa: E731
    assert run("import-baseline", str(EXAMPLES / "example-ubuntu-server.json")) == cli.EXIT_OK
    assert (portable_root / "baselines" / "Example_Ubuntu_Server_Baseline.json").exists()
    assert run("import-baseline", str(EXAMPLES / "example-ubuntu-server.json")) == cli.EXIT_USAGE
    assert run("import-baseline", str(EXAMPLES / "example-ubuntu-server.json"), "--replace") == cli.EXIT_OK
    evil = tmp_path / "evil.json"
    data = copy.deepcopy(base([rule(check={"type": "file_kv", "path": "/etc/shadow", "key": "root"})]))
    evil.write_text(json.dumps(data))
    assert run("import-baseline", str(evil)) == cli.EXIT_USAGE
    assert not (portable_root / "baselines" / "Test_Baseline.json").exists()
    capsys.readouterr()
    assert run("baselines") == cli.EXIT_OK
    assert "Example Ubuntu Server Baseline v1.0" in capsys.readouterr().out

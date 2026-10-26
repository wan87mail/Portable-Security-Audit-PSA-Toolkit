import sys
import threading
import time

import pytest

from psatoolkit.core.safe_exec import CommandRunner, PolicyViolation, ReadOnlyPolicy
from psatoolkit.core.stop import StopToken

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="uses POSIX utilities")


@pytest.fixture
def policy():
    return ReadOnlyPolicy.default()


@pytest.mark.parametrize("argv", [
    ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "/v", "RunAsPPL"],
    ["netsh", "advfirewall", "show", "allprofiles"],
    ["sc", "qc", "LanmanServer"],
    ["net", "accounts"],
    ["net", "localgroup", "Administrators"],
    ["auditpol", "/get", "/category:*"],
    ["manage-bde", "-status"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
     "Get-MpComputerStatus | Select-Object AMServiceEnabled | ConvertTo-Json"],
    ["systemctl", "is-enabled", "ssh"],
    ["systemctl", "--no-pager", "list-units", "--type=service"],
    ["ss", "-tulpn"],
    ["ip", "-br", "addr"],
    ["ufw", "status", "verbose"],
    ["iptables", "-L", "-n", "-v"],
    ["iptables", "-t", "nat", "-S"],
    ["nft", "list", "ruleset"],
    ["sshd", "-T"],
    ["find", "/etc", "-xdev", "-perm", "-0002", "-type", "f"],
    ["apt", "list", "--upgradable"],
    ["openssl", "x509", "-noout", "-dates"],
    ["nmap", "-sT", "-Pn", "-p", "22,443", "--script", "safe", "10.0.0.5"],
])
def test_read_only_commands_allowed(policy, argv):
    policy.check(argv[0], argv[1:])


@pytest.mark.parametrize("argv", [
    ["reg", "add", r"HKLM\SOFTWARE\x", "/v", "y", "/d", "1"],
    ["reg", "delete", r"HKLM\SOFTWARE\x"],
    ["reg", "import", "evil.reg"],
    ["netsh", "advfirewall", "set", "allprofiles", "state", "off"],
    ["netsh", "advfirewall", "firewall", "add", "rule", "name=x"],
    ["netsh", "interface", "show", "interface", "&&", "netsh", "reset"],
    ["sc", "config", "WinDefend", "start=", "disabled"],
    ["sc", "stop", "WinDefend"],
    ["net", "user", "bob", "Passw0rd!"],
    ["net", "user", "bob", "/add"],
    ["net", "accounts", "/minpwlen:0"],
    ["net", "localgroup", "Administrators", "bob", "/add"],
    ["net", "stop", "wuauserv"],
    ["auditpol", "/set", "/category:*"],
    ["manage-bde", "-off", "C:"],
    ["secedit", "/configure", "/db", "x.sdb"],
    ["ipconfig", "/release"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Stop-Service WinDefend"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Process | Stop-Process"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "iex (gc x.ps1)"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Invoke-WebRequest http://x"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Date | Out-File C:\\x.txt"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "$k=Get-Item HKLM:\\x; $k.SetValue('a',1)"],
    ["powershell", "-EncodedCommand", "ZQBjAGgAbwA="],
    ["powershell", "-Command", "Get-Date"],
    ["systemctl", "restart", "ssh"],
    ["systemctl", "disable", "apparmor"],
    ["systemctl", "--now", "mask", "ufw"],
    ["ufw", "disable"],
    ["nft", "flush", "ruleset"],
    ["iptables", "-F"],
    ["iptables", "-P", "INPUT", "ACCEPT"],
    ["iptables", "-L", "-A", "INPUT"],
    ["ip", "link", "set", "eth0", "down"],
    ["ip", "addr", "add", "10.0.0.1/24", "dev", "eth0"],
    ["find", "/tmp", "-name", "x", "-delete"],
    ["find", "/", "-exec", "rm", "{}", ";"],
    ["apt", "install", "nmap"],
    ["apt", "remove", "ufw"],
    ["dnf", "upgrade"],
    ["rpm", "-e", "openssh"],
    ["sshd", "-D"],
    ["cryptsetup", "luksFormat", "/dev/sda"],
    ["nmap", "--script", "smb-vuln-ms17-010,exploit", "10.0.0.5"],
    ["nmap", "--script", "brute", "10.0.0.5"],
    ["nmap", "-iL", "targets.txt"],
    ["openssl", "req", "-new"],
    ["rm", "-rf", "/"],
    ["bash", "-c", "id"],
    ["cmd", "/c", "whoami"],
    ["curl", "http://example.com"],
])
def test_mutating_or_unknown_commands_denied(policy, argv):
    with pytest.raises(PolicyViolation):
        policy.check(argv[0], argv[1:])


def test_exe_suffix_is_normalised(policy):
    policy.check("REG.EXE", ["query", "HKLM"])
    with pytest.raises(PolicyViolation):
        policy.check("reg.exe", ["add", "HKLM"])


def test_runner_rejects_shell_strings():
    runner = CommandRunner()
    for bad in ("reg query HKLM", b"ls", [], ["ls", 3]):
        with pytest.raises(TypeError):
            runner.run(bad)  # type: ignore[arg-type]


def test_runner_denies_paths_and_policy_violations():
    runner = CommandRunner()
    assert runner.run(["/bin/rm", "-rf", "/nonexistent"]).error == "policy_denied"
    assert runner.run(["reg", "add", "HKLM\\x"]).error == "policy_denied"
    assert runner.run(["uname", "\x00"]).error == "policy_denied"


def test_runner_audits_denials():
    events = []
    runner = CommandRunner(audit=lambda e, d: events.append((e, d)))
    runner.run(["systemctl", "stop", "ssh"])
    assert events and events[0][0] == "command_denied"


def test_missing_tool_is_reported_not_raised():
    policy = ReadOnlyPolicy(rules={"psa-definitely-missing-tool": lambda a: None})
    runner = CommandRunner(policy=policy)
    result = runner.run(["psa-definitely-missing-tool", "--version"])
    assert result.error == "not_found" and not result.ok
    assert runner.is_available("psa-definitely-missing-tool") is False


def test_demo_mode_never_executes(monkeypatch):
    import subprocess

    def boom(*a, **k):
        raise AssertionError("subprocess must not be started in demo mode")

    monkeypatch.setattr(subprocess, "Popen", boom)
    result = CommandRunner(demo=True).run(["uname", "-a"])
    assert result.error == "demo_mode"


@posix_only
def test_successful_command_and_secure_environment():
    result = CommandRunner().run(["uname", "-s"])
    assert result.ok, result
    assert result.stdout.strip()


@posix_only
def test_timeout_is_enforced():
    policy = ReadOnlyPolicy(rules={"sleep": lambda a: None})
    runner = CommandRunner(policy=policy)
    started = time.monotonic()
    result = runner.run(["sleep", "10"], timeout=0.5)
    elapsed = time.monotonic() - started
    assert result.timed_out and not result.ok
    assert elapsed < 5


@posix_only
def test_stop_token_kills_running_command():
    stop = StopToken()
    runner = CommandRunner(stop_token=stop, policy=ReadOnlyPolicy(rules={"sleep": lambda a: None}))
    threading.Timer(0.3, stop.stop).start()
    started = time.monotonic()
    result = runner.run(["sleep", "10"], timeout=30)
    assert result.cancelled
    assert time.monotonic() - started < 5
    assert runner.run(["sleep", "1"]).cancelled  # nothing new starts after stop


@posix_only
def test_output_is_truncated_and_redacted():
    policy = ReadOnlyPolicy(rules={"printf": lambda a: None})
    runner = CommandRunner(policy=policy, max_output_bytes=10_000)
    result = runner.run(["printf", "password=hunter2 " + "x" * 20000])
    assert result.truncated
    assert "hunter2" not in result.stdout and "[REDACTED]" in result.stdout

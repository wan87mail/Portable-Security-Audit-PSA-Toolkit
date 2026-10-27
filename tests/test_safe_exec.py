import sys
import threading
import time

import pytest

from psatoolkit.core.safe_exec import CommandRunner, PolicyViolation, ReadOnlyPolicy
from psatoolkit.core.stop import StopToken
from conftest import LONG_COMMAND, LONG_COMMAND_POLICY_RULES

posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="uses POSIX utilities")


@pytest.fixture
def policy():
    return ReadOnlyPolicy.default()


# Every command line the shipped checks run (keep in sync with the modules).
@pytest.mark.parametrize("argv", [
    ["net", "accounts"],
    ["auditpol", "/get", "/category:*", "/r"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
     "Get-MpComputerStatus | Select-Object AMServiceEnabled | ConvertTo-Json"],
    ["systemctl", "is-enabled", "ssh"],
    ["systemctl", "is-active", "ufw"],
    ["systemctl", "list-units", "--type=service,socket", "--state=running,listening", "--no-pager"],
    ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"],
    ["dpkg-query", "-W", "-f", "${binary:Package}\t${Version}\n"],
    ["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"],
    ["ip", "-j", "addr"],
    ["ip", "-br", "addr", "show", "dev", "eth0"],
    ["ufw", "status", "verbose"],
    ["nft", "list", "ruleset"],
    ["iptables", "-S"],
    ["iptables", "-t", "nat", "-L", "-n", "-v"],
    ["apt", "list", "--upgradable"],
    ["dnf", "-q", "--cacheonly", "check-update"],
    ["dnf", "-q", "--cacheonly", "updateinfo", "list", "--security"],
    ["sshd", "-T"],
    ["openssl", "x509", "-in", "/etc/ssl/certs/a.pem", "-noout", "-subject", "-enddate"],
    ["openssl", "version"],
])
def test_read_only_commands_allowed(policy, argv):
    policy.check(argv[0], argv[1:])


@pytest.mark.parametrize("argv", [
    # state-changing forms of allowed programs
    ["net", "user", "bob", "Passw0rd!"],
    ["net", "user", "bob", "/add"],
    ["net", "share", "x=C:\\"],                        # positional-only share creation
    ["net", "accounts", "/minpwlen:0"],
    ["net", "localgroup", "Administrators", "bob", "/add"],
    ["auditpol", "/set", "/category:*"],
    ["auditpol", "/get", "/category:*", "/set"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Stop-Service WinDefend"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Process | Stop-Process"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "iex (gc x.ps1)"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Invoke-WebRequest http://x"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Date | Out-File C:\\x.txt"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "$k=Get-Item HKLM:\\x; $k.SetValue('a',1)"],
    ["powershell", "-NoProfile", "-NonInteractive", "-Command", "[ScriptBlock]::Create('x')"],
    ["powershell", "-EncodedCommand", "ZQBjAGgAbwA="],
    ["powershell", "-Command", "Get-Date"],
    ["systemctl", "restart", "ssh"],
    ["systemctl", "disable", "apparmor"],
    ["systemctl", "--now", "mask", "ufw"],
    ["systemctl", "kill", "sshd"],
    ["ufw", "disable"],
    ["nft", "flush", "ruleset"],
    ["nft", "-f", "list"],                              # would apply a file named 'list'
    ["iptables", "-F"],
    ["iptables", "-P", "INPUT", "ACCEPT"],
    ["iptables", "-L", "-A", "INPUT"],
    ["ip", "link", "set", "eth0", "down"],
    ["ip", "addr", "add", "10.0.0.1/24", "dev", "eth0"],
    ["ip", "netns", "exec", "x", "sh"],                 # runs a command
    ["ip", "-batch", "cmds.txt"],
    ["ip", "-force", "-b", "x"],
    ["ip", "xfrm", "state", "deleteall"],
    ["ip", "route", "flush", "all"],
    ["apt", "install", "nmap"],
    ["apt", "remove", "ufw"],
    ["apt", "list", "-o", "APT::Update::Pre-Invoke::=touch /tmp/x"],
    ["dnf", "upgrade"],
    ["dnf", "check-update"],                            # refreshes metadata over the network
    ["dnf", "--cacheonly", "--setopt=x=1", "list"],
    ["rpm", "-e", "openssh"],
    ["rpm", "-qa", "--pipe", "sh"],
    ["rpm", "-q", "--eval", "%(id)"],
    ["rpm", "-q", "--qf", "%(id)", "bash"],
    ["dpkg-query", "--load-avail", "x"],
    ["sshd", "-D"],
    ["openssl", "req", "-new"],
    ["openssl", "x509", "-in", "a.pem", "-out", "/etc/ssl/certs/b.pem"],
    ["openssl", "x509", "-in", "a.pem"],                # must be -noout
    ["openssl", "s_client", "-connect", "example.com:443"],
    # programs that are not on the least-privilege list at all
    ["reg", "add", r"HKLM\SOFTWARE\x", "/v", "y", "/d", "1"],
    ["reg", "query", "HKLM"],
    ["netsh", "wlan", "show", "profile", "name=x", "key=clear"],
    ["sc", "config", "WinDefend", "start=", "disabled"],
    ["manage-bde", "-off", "C:"],
    ["secedit", "/configure", "/db", "x.sdb"],
    ["ipconfig", "/release"],
    ["pwsh", "-NoProfile", "-NonInteractive", "-Command", "Get-Date"],
    ["hostname", "attacker"],                           # sets the hostname on Linux
    ["ss", "-K", "dst", "10.0.0.1"],                    # kills sockets
    ["find", "/tmp", "-name", "x", "-delete"],
    ["cryptsetup", "luksDump", "--dump-master-key", "/dev/sda2"],
    ["nmap", "-oN", "/etc/passwd", "10.0.0.5"],
    ["uname", "-a"],
    ["rm", "-rf", "/"],
    ["bash", "-c", "id"],
    ["cmd", "/c", "whoami"],
    ["curl", "http://example.com"],
])
def test_mutating_or_unknown_commands_denied(policy, argv):
    with pytest.raises(PolicyViolation):
        policy.check(argv[0], argv[1:])


def test_exe_suffix_is_normalised(policy):
    policy.check("NET.EXE", ["accounts"])
    with pytest.raises(PolicyViolation):
        policy.check("net.exe", ["user", "x", "/add"])


def test_policy_only_lists_programs_the_checks_use(policy):
    """Least privilege: a new program needs a rule, tests and a reason (see ReadOnlyPolicy)."""
    assert sorted(policy.rules) == sorted([
        "powershell", "net", "auditpol", "systemctl", "lsblk", "dpkg-query", "rpm", "ip", "ufw", "nft",
        "iptables", "apt", "dnf", "sshd", "openssl"])


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
    result = CommandRunner(policy=ReadOnlyPolicy(rules={"uname": lambda a: None})).run(["uname", "-s"])
    assert result.ok, result
    assert result.stdout.strip()


def test_timeout_is_enforced():
    runner = CommandRunner(policy=ReadOnlyPolicy(rules=dict(LONG_COMMAND_POLICY_RULES)))
    started = time.monotonic()
    result = runner.run(LONG_COMMAND, timeout=0.5)
    elapsed = time.monotonic() - started
    assert result.timed_out and not result.ok
    assert elapsed < 5


def test_stop_token_kills_running_command():
    stop = StopToken()
    runner = CommandRunner(stop_token=stop, policy=ReadOnlyPolicy(rules=dict(LONG_COMMAND_POLICY_RULES)))
    threading.Timer(0.3, stop.stop).start()
    started = time.monotonic()
    result = runner.run(LONG_COMMAND, timeout=60)
    assert result.cancelled
    assert time.monotonic() - started < 5
    assert runner.run(LONG_COMMAND).cancelled  # nothing new starts after stop


@posix_only
def test_output_is_truncated_and_redacted():
    policy = ReadOnlyPolicy(rules={"printf": lambda a: None})
    runner = CommandRunner(policy=policy, max_output_bytes=10_000)
    result = runner.run(["printf", "password=hunter2 " + "x" * 20000])
    assert result.truncated
    assert "hunter2" not in result.stdout and "[REDACTED]" in result.stdout


def test_windows_child_env_is_minimal_and_pins_search_paths():
    from pathlib import Path

    from psatoolkit.core.safe_exec import windows_child_env
    host = {"PATH": r"C:\Users\x\evil;C:\Windows\System32", "PSMODULEPATH": r"C:\Users\x\Modules",
            "SYSTEMROOT": r"C:\Windows", "TEMP": r"C:\Temp", "PYTHONPATH": r"C:\x", "COR_PROFILER": "{bad}",
            "PROGRAMFILES": r"C:\Program Files", "Secret_Token": "hunter2"}
    env = windows_child_env(host, Path(r"C:\Windows"))
    assert "evil" not in env["PATH"] and env["PATH"].split(";")[0].endswith("System32")
    assert "Users" not in env["PSModulePath"] and env["PSModulePath"].endswith(r"v1.0\Modules")
    assert env["TEMP"] == r"C:\Temp"
    for dropped in ("PYTHONPATH", "COR_PROFILER", "Secret_Token", "PSMODULEPATH"):
        assert dropped not in env


@pytest.mark.parametrize("name", ["..", "net accounts", "a;b", "$(id)", "-x", "x" * 70])
def test_resolver_rejects_odd_executable_names(name):
    with pytest.raises(PolicyViolation):
        CommandRunner().resolve(name)


def test_resolver_ignores_current_directory(tmp_path, monkeypatch):
    name = "psa-cwd-planted"
    planted = tmp_path / (name + (".exe" if sys.platform.startswith("win") else ""))
    planted.write_bytes(b"")
    planted.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    assert CommandRunner().resolve(name) is None


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows resolution")
def test_windows_resolver_returns_system32_exe_only():
    path = CommandRunner().resolve("net")
    assert path and path.lower().endswith(r"system32\net.exe")


@posix_only
def test_output_cap_applies_while_reading():
    """Output beyond the cap is discarded as it streams; memory stays bounded."""
    policy = ReadOnlyPolicy(rules={"head": lambda a: None})
    runner = CommandRunner(policy=policy, max_output_bytes=1000)
    result = runner.run(["head", "-c", "50000000", "/dev/zero"], timeout=30)
    assert result.ok and result.truncated
    assert len(result.stdout) <= 1000

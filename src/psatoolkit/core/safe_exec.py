"""Safe, read-only execution of external commands.

Every external program the toolkit runs goes through :class:`CommandRunner`:

* argument arrays only — ``shell=False`` always, nothing is concatenated;
* executables must be on an allow-list and resolve to a trusted location
  (system directories, or the USB ``tools/`` folder for optional tools);
* a per-executable :class:`ReadOnlyPolicy` rejects state-changing
  sub-commands (``reg add``, ``netsh ... set``, ``systemctl restart``...);
* stdin is closed, output is size-capped, and a timeout plus the emergency
  stop token terminate the whole process group.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from psatoolkit.core.redaction import redact_text
from psatoolkit.core.stop import StopToken

IS_WINDOWS = sys.platform.startswith("win")
POSIX_SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Optional third-party tools that may be shipped on the USB drive.
BUNDLED_TOOLS = frozenset({"nmap", "openssl"})


class PolicyViolation(Exception):
    pass


# --------------------------------------------------------------------------
# Read-only policy
# --------------------------------------------------------------------------

def _positional(args: Sequence[str]) -> list[str]:
    return [a for a in args if not a.startswith("-")]


def _first_positional(args: Sequence[str]) -> str:
    pos = _positional(args)
    return pos[0].lower() if pos else ""


def _require_first(allowed: set[str]) -> Callable[[Sequence[str]], str | None]:
    def rule(args: Sequence[str]) -> str | None:
        first = _first_positional(args)
        if first not in allowed:
            return f"sub-command '{first or '<none>'}' is not on the read-only list {sorted(allowed)}"
        return None
    return rule


def _forbid_tokens(forbidden: set[str], also: Callable[[Sequence[str]], str | None] | None = None):
    def rule(args: Sequence[str]) -> str | None:
        lowered = {a.lower() for a in args}
        bad = lowered & forbidden
        if bad:
            return f"argument(s) {sorted(bad)} may modify the system"
        return also(args) if also else None
    return rule


def _windows_first_arg(allowed: set[str]) -> Callable[[Sequence[str]], str | None]:
    """Windows tools use '/' or '-' switches as sub-commands (auditpol /get)."""
    def rule(args: Sequence[str]) -> str | None:
        first = args[0].lower() if args else ""
        if first not in allowed:
            return f"'{first or '<none>'}' is not an allowed read-only switch {sorted(allowed)}"
        return None
    return rule


def _netsh(args: Sequence[str]) -> str | None:
    lowered = [a.lower() for a in args]
    if "show" not in lowered:
        return "netsh is only permitted with a 'show' sub-command"
    bad = set(lowered) & {"set", "add", "delete", "reset", "import", "install", "uninstall", "flush", "dump", "exec"}
    return f"netsh argument(s) {sorted(bad)} may modify the system" if bad else None


def _net(args: Sequence[str]) -> str | None:
    if _first_positional(args) not in {"user", "localgroup", "accounts", "share", "config"}:
        return "net is only permitted for user/localgroup/accounts/share/config queries"
    if len(_positional(args)) > 2:
        return "extra positional arguments to 'net' could set a password or membership"
    for a in args:
        low = a.lower()
        if low.startswith("/") and low not in ("/domain",):
            return f"switch '{a}' may modify accounts or policy"
    return None


_PS_MUTATING = re.compile(
    r"(?i)\b(Set|New|Remove|Add|Enable|Disable|Start|Stop|Restart|Install|Uninstall|Clear|"
    r"Rename|Move|Copy|Register|Unregister|Update|Grant|Revoke|Suspend|Resume|Reset|Mount|"
    r"Dismount|Import|Export|Invoke|Push|Publish|Send|Initialize|Format-Volume|Lock|Unlock|"
    r"Protect|Unprotect|Backup|Restore|Save|Out-File|Tee-Object)-?\w*\b")
_PS_ALLOWED_VERB = re.compile(r"(?i)^(Out-String|Out-Null|Write-Output)$")


def _powershell(args: Sequence[str]) -> str | None:
    lowered = [a.lower() for a in args]
    if any(a in ("-encodedcommand", "-enc", "-e", "-file", "-f") for a in lowered):
        return "PowerShell may only run inline, reviewable -Command scripts"
    if "-command" not in lowered:
        return "PowerShell requires -NoProfile -NonInteractive -Command <script>"
    if "-noprofile" not in lowered or "-noninteractive" not in lowered:
        return "PowerShell must run with -NoProfile -NonInteractive"
    script = " ".join(args[lowered.index("-command") + 1:])
    for match in _PS_MUTATING.finditer(script):
        token = match.group(0)
        # Only Verb-Noun cmdlets are a concern; plain words like "Start" in strings are not.
        if "-" in token and not _PS_ALLOWED_VERB.match(token):
            return f"PowerShell cmdlet '{token}' is not permitted in read-only mode"
    if re.search(r"(?i)(\biex\b|\[\s*system\.diagnostics\.process\s*\]|\.(set|delete|create|put|invoke|start|kill|terminate)\w*\s*\()", script):
        return "PowerShell script contains a dynamic-execution or mutating method call"
    return None


def _ip(args: Sequence[str]) -> str | None:
    bad = {a.lower() for a in args} & {"add", "del", "delete", "set", "flush", "change", "replace", "append", "prepend", "save", "restore"}
    return f"ip argument(s) {sorted(bad)} may modify networking" if bad else None


def _iptables(args: Sequence[str]) -> str | None:
    allowed = {"-l", "--list", "-s", "--list-rules", "-n", "--numeric", "-v", "--verbose",
               "-t", "--table", "-x", "--exact", "--line-numbers", "-w", "--wait"}
    for a in args:
        if a.startswith("-") and a.lower() not in allowed:
            return f"iptables option '{a}' is not read-only"
        if not a.startswith("-") and not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", a):
            return f"iptables argument '{a}' is not a table or chain name"
    if not ({"-l", "--list", "-s", "--list-rules"} & {a.lower() for a in args}):
        return "iptables is only permitted with -L or -S"
    return None


def _find(args: Sequence[str]) -> str | None:
    bad = {a.lower() for a in args} & {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint",
                                       "-fprint0", "-fprintf", "-fls"}
    return f"find action(s) {sorted(bad)} are not permitted" if bad else None


def _nmap(args: Sequence[str]) -> str | None:
    joined = " ".join(args).lower()
    for word in ("exploit", "brute", "dos", "intrusive", "malware", "fuzzer", "--script-args-file"):
        if word in joined:
            return f"nmap '{word}' scripts/options are not permitted (non-destructive mode only)"
    if "--resume" in joined or "-il" in {a.lower() for a in args}:
        return "nmap targets must be passed explicitly, not from files"
    return None


def _openssl(args: Sequence[str]) -> str | None:
    return _require_first({"x509", "s_client", "version", "ciphers", "verify", "crl"})(args)


@dataclass
class ReadOnlyPolicy:
    """Maps allowed executables to a rule returning a denial reason or None."""

    rules: dict[str, Callable[[Sequence[str]], str | None]] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "ReadOnlyPolicy":
        ok: Callable[[Sequence[str]], str | None] = lambda args: None  # noqa: E731
        return cls(rules={
            # --- Windows -------------------------------------------------
            "netsh": _netsh,
            "reg": _require_first({"query"}),
            "sc": _require_first({"query", "queryex", "qc", "qdescription", "qfailure",
                                  "qsidtype", "qprivs", "qtriggerinfo", "sdshow", "enumdepend"}),
            "net": _net,
            "powershell": _powershell,
            "pwsh": _powershell,
            "auditpol": _windows_first_arg({"/get"}),
            "manage-bde": _windows_first_arg({"-status"}),
            "secedit": _windows_first_arg({"/export"}),
            "ipconfig": _forbid_tokens({"/release", "/release6", "/renew", "/renew6", "/flushdns",
                                        "/registerdns", "/setclassid", "/setclassid6"}),
            "systeminfo": ok, "whoami": ok, "netstat": ok, "hostname": ok,
            # --- Linux ---------------------------------------------------
            "systemctl": _require_first({"status", "is-active", "is-enabled", "is-failed",
                                         "list-units", "list-unit-files", "list-sockets",
                                         "list-timers", "show", "cat", "get-default"}),
            "ss": ok, "uname": ok, "id": ok, "lsblk": ok, "findmnt": ok, "stat": ok,
            "getenforce": ok, "sestatus": ok, "aa-status": ok, "apparmor_status": ok,
            "getcap": ok, "uptime": ok, "dpkg-query": ok,
            "ip": _ip,
            "ufw": _require_first({"status"}),
            "nft": _require_first({"list"}),
            "iptables": _iptables, "ip6tables": _iptables,
            "firewall-cmd": _forbid_tokens(set(), lambda a: None if all(
                x.startswith("--list") or x.startswith("--get") or x in ("--state", "--zone")
                or x.startswith("--zone=") for x in a) else "firewall-cmd is limited to --list/--get/--state"),
            "apt": _require_first({"list"}),
            "rpm": lambda a: None if a and a[0].startswith("-q") else "rpm is limited to queries (-q...)",
            "dnf": _require_first({"check-update", "updateinfo", "list", "info"}),
            "sshd": lambda a: None if list(a) == ["-T"] else "sshd is limited to 'sshd -T'",
            "cryptsetup": _require_first({"status", "isluks", "luksdump"}),
            "find": _find,
            "timedatectl": _require_first({"status", "show"}),
            # --- Optional tools (Phase 4/5) -----------------------------
            "nmap": _nmap,
            "openssl": _openssl,
        })

    def check(self, executable_name: str, args: Sequence[str]) -> None:
        name = executable_name.lower()
        if name.endswith(".exe"):
            name = name[:-4]
        rule = self.rules.get(name)
        if rule is None:
            raise PolicyViolation(f"'{executable_name}' is not on the read-only executable allow-list")
        reason = rule(list(args))
        if reason:
            raise PolicyViolation(f"{executable_name}: {reason}")


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

@dataclass
class CommandResult:
    argv: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False
    error: str | None = None          # "not_found", "policy_denied", "os_error", "demo_mode"
    error_detail: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and not self.cancelled and self.returncode == 0

    @property
    def display(self) -> str:
        return " ".join(self.argv)


def _windows_system_dirs() -> list[Path]:
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return [root / "System32", root / "System32" / "WindowsPowerShell" / "v1.0", root]


class CommandRunner:
    def __init__(self, stop_token: StopToken | None = None, policy: ReadOnlyPolicy | None = None,
                 default_timeout: float = 30.0, max_output_bytes: int = 2_000_000,
                 tool_dirs: Sequence[Path] = (), audit: Callable[[str, dict], None] | None = None,
                 demo: bool = False) -> None:
        self.stop_token = stop_token or StopToken()
        self.policy = policy or ReadOnlyPolicy.default()
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes
        self.tool_dirs = [Path(p) for p in tool_dirs]
        self.audit = audit
        self.demo = demo

    # -- resolution ------------------------------------------------------
    def resolve(self, name: str) -> str | None:
        """Resolve an executable name to a trusted absolute path, or None."""
        if os.sep in name or (os.altsep and os.altsep in name):
            raise PolicyViolation("Executables must be given by name, not by path")
        base = name.lower().removesuffix(".exe")
        search: list[Path] = []
        if base in BUNDLED_TOOLS:
            search.extend(self.tool_dirs)
        if IS_WINDOWS:
            search.extend(_windows_system_dirs())
            if base in BUNDLED_TOOLS:
                pf = os.environ.get("ProgramFiles(x86)") or os.environ.get("ProgramFiles")
                if pf:
                    search.append(Path(pf) / "Nmap")
            path_str = os.pathsep.join(str(p) for p in search)
            return shutil.which(name, path=path_str)
        path_str = os.pathsep.join([*(str(p) for p in search), POSIX_SECURE_PATH])
        return shutil.which(name, path=path_str)

    def is_available(self, name: str) -> bool:
        try:
            return self.resolve(name) is not None
        except PolicyViolation:
            return False

    # -- execution -------------------------------------------------------
    def run(self, argv: Sequence[str], timeout: float | None = None) -> CommandResult:
        if isinstance(argv, (str, bytes)) or not argv or not all(isinstance(a, str) for a in argv):
            raise TypeError("argv must be a non-empty list of strings (never a shell string)")
        argv = list(argv)
        result = CommandResult(argv=argv)
        if any("\x00" in a for a in argv):
            result.error, result.error_detail = "policy_denied", "NUL byte in argument"
            return result
        if self.demo:
            result.error, result.error_detail = "demo_mode", "Commands are never executed in demo mode"
            return result
        try:
            self.policy.check(argv[0], argv[1:])
            exe = self.resolve(argv[0])
        except PolicyViolation as exc:
            result.error, result.error_detail = "policy_denied", str(exc)
            self._audit("command_denied", {"argv": argv, "reason": str(exc)})
            return result
        if exe is None:
            result.error, result.error_detail = "not_found", f"'{argv[0]}' was not found in trusted locations"
            return result
        if self.stop_token.stopped:
            result.cancelled = True
            return result

        timeout = self.default_timeout if timeout is None else timeout
        self._audit("command_start", {"argv": argv, "resolved": exe, "timeout": timeout})
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                [exe, *argv[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False, env=self._env(), **self._popen_platform_kwargs())
        except OSError as exc:
            result.error, result.error_detail = "os_error", str(exc)
            return result

        out_b, err_b = b"", b""
        while True:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                result.timed_out = True
                break
            if self.stop_token.stopped:
                result.cancelled = True
                break
            try:
                out_b, err_b = proc.communicate(timeout=min(0.25, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        if result.timed_out or result.cancelled:
            self._kill(proc)
            try:
                out_b, err_b = proc.communicate(timeout=5)
            except (subprocess.TimeoutExpired, ValueError):
                out_b, err_b = b"", b""

        result.duration = time.monotonic() - started
        result.returncode = proc.returncode
        result.stdout, t1 = self._decode(out_b)
        result.stderr, t2 = self._decode(err_b)
        result.truncated = t1 or t2
        self._audit("command_end", {"argv": argv, "returncode": result.returncode,
                                    "timed_out": result.timed_out, "cancelled": result.cancelled,
                                    "duration": round(result.duration, 3)})
        return result

    # -- helpers ---------------------------------------------------------
    def _decode(self, data: bytes) -> tuple[str, bool]:
        truncated = len(data) > self.max_output_bytes
        text = data[: self.max_output_bytes].decode("utf-8", errors="replace")
        return redact_text(text), truncated

    @staticmethod
    def _env() -> dict[str, str]:
        if IS_WINDOWS:
            return dict(os.environ)
        env = {"PATH": POSIX_SECURE_PATH, "LC_ALL": "C", "LANG": "C"}
        for key in ("HOME", "USER", "LOGNAME", "TERM"):
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    @staticmethod
    def _popen_platform_kwargs() -> dict:
        if IS_WINDOWS:
            return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
        return {"start_new_session": True}

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            if IS_WINDOWS:
                proc.kill()
            else:
                os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    def _audit(self, event: str, details: dict) -> None:
        if self.audit:
            try:
                self.audit(event, details)
            except Exception:
                pass

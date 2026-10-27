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
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Callable, Sequence

from psatoolkit.core.redaction import redact_text
from psatoolkit.core.stop import StopToken

IS_WINDOWS = sys.platform.startswith("win")
POSIX_SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Optional third-party tools that may be shipped on the USB drive.
BUNDLED_TOOLS = frozenset({"openssl"})


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


def _net(args: Sequence[str]) -> str | None:
    # Only the account-policy query is needed; 'net user/share/localgroup' can create
    # accounts, shares or memberships with positional arguments alone.
    return None if [a.lower() for a in args] == ["accounts"] else "net is limited to 'net accounts'"


def _auditpol(args: Sequence[str]) -> str | None:
    if not args or args[0].lower() != "/get":
        return "auditpol is limited to /get"
    for a in args[1:]:
        if not re.fullmatch(r"(?i)/(category|subcategory):[^/]{1,200}|/r", a):
            return f"auditpol argument '{a}' is not permitted"
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
    if re.search(r"(?i)(\biex\b|\[\s*system\.diagnostics\.process\s*\]|\[\s*scriptblock\s*\]|"
                 r"\.(set|delete|create|put|invoke|start|kill|terminate)\w*\s*\()", script):
        return "PowerShell script contains a dynamic-execution or mutating method call"
    return None


_IP_OBJECTS = {"addr", "address", "a", "link", "l", "route", "r", "ro", "neigh", "n", "rule", "ru"}
_IP_VERBS = {"show", "list", "ls", "lst", "get"}
_IP_OPTIONS = {"-j", "-json", "-br", "-brief", "-4", "-6", "-o", "-oneline", "-d", "-details",
               "-s", "-stats", "-p", "-pretty"}


def _ip(args: Sequence[str]) -> str | None:
    """Allow-list: ``ip [options] OBJECT [show|list|get [selectors]]``.

    A deny-list is not enough here: ``ip netns exec``, ``ip -batch`` and dozens of
    verbs (``deleteall``, ``flush``...) run commands or change networking.
    """
    positional = []
    for a in args:
        if a.startswith("-"):
            if a.lower() not in _IP_OPTIONS:
                return f"ip option '{a}' is not permitted"
        else:
            positional.append(a.lower())
    if not positional or positional[0] not in _IP_OBJECTS:
        return f"ip object must be one of {sorted(_IP_OBJECTS)}"
    if len(positional) > 1 and positional[1] not in _IP_VERBS:
        return f"ip is limited to {sorted(_IP_VERBS)}"
    for a in positional[2:]:
        if not re.fullmatch(r"[a-z0-9_.:/@%-]{1,64}", a) or a in {"exec", "add", "del", "delete", "set", "flush"}:
            return f"ip selector '{a}' is not permitted"
    return None


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


def _nft(args: Sequence[str]) -> str | None:
    # 'nft -f FILE list' would apply FILE; interactive mode reads commands from stdin.
    bad = {a.lower() for a in args} & {"-f", "--file", "-i", "--interactive"}
    if bad:
        return f"nft option(s) {sorted(bad)} are not permitted"
    return _require_first({"list"})(args)


def _apt(args: Sequence[str]) -> str | None:
    for a in args:
        low = a.lower()
        if low in ("-o", "-c") or low.startswith(("--option", "--config-file", "-o=", "-c=")):
            return "apt configuration overrides (-o/-c) are not permitted"
    return _require_first({"list"})(args)


_RPM_FORBIDDEN = {"--pipe", "--eval", "-e", "--erase", "--define", "-d", "--macros", "--rcfile", "--load",
                  "-i", "--install", "-u", "--upgrade", "-f", "--freshen", "--import", "--initdb",
                  "--rebuilddb", "--setperms", "--setugids", "--setcaps", "--restore", "--dbpath", "--root"}


def _rpm(args: Sequence[str]) -> str | None:
    if not args or not args[0].startswith("-q"):
        return "rpm is limited to queries (-q...)"
    for a in args:
        low = a.lower().split("=", 1)[0]
        if low in _RPM_FORBIDDEN:
            return f"rpm option '{a}' is not permitted"
        if "%(" in a or "%{lua" in a.lower():
            return "rpm macros that execute code are not permitted"
    return None


def _dnf(args: Sequence[str]) -> str | None:
    lowered = [a.lower() for a in args]
    if "--cacheonly" not in lowered and "-C" not in args:
        return "dnf must run with --cacheonly (no repository refresh or network access)"
    for low in lowered:
        if low.startswith(("--setopt", "--config", "--installroot")) or low in ("-y", "--assumeyes"):
            return f"dnf option '{low}' is not permitted"
    return _require_first({"check-update", "updateinfo", "list", "info"})(args)


def _dpkg_query(args: Sequence[str]) -> str | None:
    return None if args and args[0] in ("-W", "--show") else "dpkg-query is limited to -W/--show"


def _openssl(args: Sequence[str]) -> str | None:
    lowered = [a.lower() for a in args]
    if lowered == ["version"]:
        return None
    if not lowered or lowered[0] != "x509":
        return "openssl is limited to 'x509 -noout' and 'version'"
    if "-noout" not in lowered:
        return "openssl x509 must use -noout"
    bad = set(lowered) & {"-out", "-keyout", "-signkey", "-req", "-new", "-ca", "-cakey", "-x509toreq", "-engine"}
    return f"openssl option(s) {sorted(bad)} are not permitted" if bad else None


@dataclass
class ReadOnlyPolicy:
    """Maps allowed executables to a rule returning a denial reason or None.

    The default policy is least-privilege: it lists only the programs the
    shipped checks actually run, each restricted to the read-only forms the
    checks use. Adding a check that needs another program means adding it
    here, with a rule and tests (tests/test_safe_exec.py).
    """

    rules: dict[str, Callable[[Sequence[str]], str | None]] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "ReadOnlyPolicy":
        ok: Callable[[Sequence[str]], str | None] = lambda args: None  # noqa: E731
        return cls(rules={
            # --- Windows -------------------------------------------------
            "powershell": _powershell,
            "net": _net,
            "auditpol": _auditpol,
            # --- Linux ---------------------------------------------------
            "systemctl": _require_first({"status", "is-active", "is-enabled", "list-units",
                                         "list-unit-files", "show"}),
            "lsblk": ok,
            "dpkg-query": _dpkg_query,
            "rpm": _rpm,
            "ip": _ip,
            "ufw": _require_first({"status"}),
            "nft": _nft,
            "iptables": _iptables,
            "apt": _apt,
            "dnf": _dnf,
            "sshd": lambda a: None if list(a) == ["-T"] else "sshd is limited to 'sshd -T'",
            # --- Optional tool (system copy or USB tools/ folder) ---------
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


def _windows_root() -> Path:
    """The Windows directory from the OS itself (not the inheritable SystemRoot variable)."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(260)
        n = ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 260)  # type: ignore[attr-defined]
        if 0 < n < 260:
            return Path(buf.value)
    except Exception:  # noqa: BLE001 - non-Windows or restricted environment
        pass
    return Path(os.environ.get("SystemRoot", r"C:\Windows"))


def _windows_system_dirs() -> list[Path]:
    root = _windows_root()
    return [root / "System32", root / "System32" / "WindowsPowerShell" / "v1.0", root]


# Environment variables Windows programs need; everything else (PATH, PSModulePath,
# PYTHON*, COR_* profilers, ...) is replaced or dropped so the host cannot redirect them.
_WINDOWS_ENV_KEEP = (
    "SystemRoot", "SystemDrive", "windir", "ComSpec", "PATHEXT", "OS", "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION", "TEMP", "TMP", "USERPROFILE", "USERNAME", "USERDOMAIN", "COMPUTERNAME",
    "ALLUSERSPROFILE", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
    "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432", "APPDATA", "LOCALAPPDATA",
    "PUBLIC", "HOMEDRIVE", "HOMEPATH",
)


def windows_child_env(environ: dict[str, str] | os._Environ, windows_root: Path) -> dict[str, str]:
    lookup = {k.upper(): v for k, v in environ.items()}
    env = {k: lookup[k.upper()] for k in _WINDOWS_ENV_KEEP if k.upper() in lookup}
    root = PureWindowsPath(windows_root)
    sys32 = root / "System32"
    env["SystemRoot"] = str(root)
    env["PATH"] = ";".join(str(p) for p in (sys32, root, sys32 / "Wbem",
                                            sys32 / "WindowsPowerShell" / "v1.0"))
    program_files = env.get("ProgramFiles", r"C:\Program Files")
    env["PSModulePath"] = ";".join((str(PureWindowsPath(program_files) / "WindowsPowerShell" / "Modules"),
                                    str(sys32 / "WindowsPowerShell" / "v1.0" / "Modules")))
    return env


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
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", base):
            raise PolicyViolation(f"'{name}' is not a valid executable name")
        search: list[Path] = list(self.tool_dirs) if base in BUNDLED_TOOLS else []
        # Explicit lookup instead of shutil.which(): on Windows, which() also searches the
        # current directory (Python < 3.12) and accepts .bat/.cmd through PATHEXT.
        if IS_WINDOWS:
            for directory in [*search, *_windows_system_dirs()]:
                candidate = directory / f"{base}.exe"
                if candidate.is_file():
                    return str(candidate)
            return None
        for directory in [*search, *(Path(d) for d in POSIX_SECURE_PATH.split(":"))]:
            candidate = directory / base
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

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

        # Output is drained by reader threads and capped while it is read, so a command
        # that prints gigabytes cannot exhaust memory; the excess is discarded.
        out_buf, err_buf = bytearray(), bytearray()
        readers = [threading.Thread(target=self._drain, args=(proc.stdout, out_buf), daemon=True),
                   threading.Thread(target=self._drain, args=(proc.stderr, err_buf), daemon=True)]
        for t in readers:
            t.start()
        while True:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                result.timed_out = True
                break
            if self.stop_token.stopped:
                result.cancelled = True
                break
            try:
                proc.wait(timeout=min(0.25, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        if result.timed_out or result.cancelled:
            self._kill(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        for t in readers:
            t.join(timeout=5)       # a grandchild may keep a pipe open; never wait forever
        out_b, err_b = bytes(out_buf), bytes(err_buf)

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
    def _drain(self, pipe, sink: bytearray) -> None:
        limit = self.max_output_bytes + 1          # one extra byte records truncation
        try:
            while True:
                chunk = pipe.read1(65536)
                if not chunk:
                    break
                room = limit - len(sink)
                if room > 0:
                    sink += chunk[:room]
        except (OSError, ValueError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def _decode(self, data: bytes) -> tuple[str, bool]:
        truncated = len(data) > self.max_output_bytes
        text = data[: self.max_output_bytes].decode("utf-8", errors="replace")
        return redact_text(text), truncated

    @staticmethod
    def _env() -> dict[str, str]:
        if IS_WINDOWS:
            return windows_child_env(os.environ, _windows_root())
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

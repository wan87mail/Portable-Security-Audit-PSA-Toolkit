# Portable Security Audit (PSA) Toolkit — Architecture

> Defensive, read-only security assessment toolkit for **authorized** IT audits,
> designed to be launched manually from a USB flash drive.

## 1. Design principles

| Principle | How it is enforced |
|---|---|
| Authorized use only | The engine refuses to start without an `AuthorizationRecord` (operator name, scope, confirmation). Remote targets need their own per-target permission reference. |
| Read-only by default | All external commands go through `core/safe_exec.py`, which only runs **allow-listed executables** and rejects known state-changing sub-commands (e.g. `netsh ... set`, `reg add`, `sc config`, `systemctl start`). |
| No shell, no injection | Commands are argument arrays (`shell=False`). User input is validated (`core/validation.py`) and never concatenated into a command line. |
| Fail-soft | Each check runs in isolation with its own timeout. An exception or timeout becomes a `CheckResult` with status `error`/`timeout` and a recorded limitation — the assessment continues. |
| Explainable findings | Every `Finding` carries evidence, severity rationale, confidence, status (confirmed / potential / informational / inconclusive), references, remediation and verification steps. |
| Local-only data | Nothing is transmitted. `offline_mode = true` is the default. Reports are written to the USB or an operator-chosen directory. |
| Accountability | Hash-chained JSONL audit log (`logs/audit-*.jsonl`) records who ran what, when, against which scope. |
| Emergency stop | A shared `StopToken` is checked between checks and polled inside every running subprocess; Stop (GUI) or Ctrl+C (CLI) terminates child processes. |
| No autorun | No `autorun.inf` is shipped. Modern Windows ignores USB autorun anyway; the operator must launch the tool manually. |

## 2. Component view

```
                 ┌──────────────────────────────────────────────┐
                 │  Interfaces:  gui/app.py (Tkinter)  cli.py   │
                 └───────────────┬──────────────────────────────┘
                                 │ AuthorizationRecord, selected modules, scope
                 ┌───────────────▼──────────────────────────────┐
                 │ core/engine.py  AssessmentEngine             │
                 │  - module registry & OS filtering            │
                 │  - privilege / tool / network gating         │
                 │  - per-check timeout, error isolation, stop  │
                 └──┬─────────────┬─────────────┬───────────────┘
                    │             │             │
      ┌─────────────▼──┐ ┌────────▼───────┐ ┌───▼────────────────┐
      │ modules/*      │ │ core/safe_exec │ │ core/authorization │
      │ (checks)       │ │ allow-list,    │ │ notice, operator   │
      │ system_info    │ │ no shell,      │ │ confirmation,      │
      │ windows_audit* │ │ timeouts,      │ │ remote scope       │
      │ linux_audit*   │ │ output caps    │ └────────────────────┘
      │ network*       │ └────────────────┘
      │ vuln*/baseline*│
      │ demo           │
      └──────┬─────────┘
             │ Finding / CheckResult (core/models.py)
      ┌──────▼──────────────────────┐   ┌──────────────────────────┐
      │ normalization* / scoring*   │──▶│ reporting/ (JSON now;    │
      └─────────────────────────────┘   │ HTML/PDF/CSV in Phase 6) │
                                        └──────────────────────────┘
  Cross-cutting: core/config.py, core/paths.py, core/logging_setup.py,
                 core/redaction.py, core/integrity.py, core/tempfiles.py,
                 core/osdetect.py, core/privileges.py
  (* = later phase)
```

### Data model (core/models.py)

- `Severity` – critical / high / medium / low / informational (ordered).
- `FindingStatus` – `confirmed`, `potential`, `informational`, `inconclusive`.
- `Confidence` – high / medium / low.
- `Reference` – CVE / CWE / baseline / URL, optional CVSS score, version, vector and source.
- `Evidence` – what was observed, how it was collected (command or API), and the redacted raw data.
- `Finding` – the fields required by §7 of the specification.
- `CheckResult` – outcome of one check (passed, findings, skipped, not_applicable, error, timeout, cancelled) plus the reason.
- `AssessmentResult` – the full run: assessment ID, tool version, host, authorization, scope, timings, check results, limitations.

### Check contract (core/engine.py)

```python
class Check:
    check_id: str            # "LNX-SSH-001"
    title: str
    supported_os: frozenset  # {"linux"}, {"windows"}, {"windows","linux"}
    requires_admin: bool     # skipped (and recorded as a limitation) if not elevated
    admin_reason: str        # why elevation is needed - shown to the operator
    required_tools: tuple    # e.g. ("sshd",) - skipped if missing
    requires_network: bool   # remote traffic → needs an authorized scope
    def run(self, ctx: AssessmentContext) -> list[Finding]: ...
```

Adding a check = subclass `Check`, add it to a `Module`, register the module in
`modules/__init__.py`. No engine change needed.

## 3. Technical limitations (read before deploying)

1. **A Windows `.exe` is not portable to Linux.** PyInstaller produces a binary
   for the OS/architecture it was built on. The Linux edition runs from source
   with the target's Python 3.10+ interpreter, or from a Linux PyInstaller
   build made on the *oldest* glibc you need to support.
2. **Python on Linux targets.** Ubuntu 22.04/24.04 ship Python 3.10/3.12.
   The toolkit uses only the standard library at runtime, so a stock Python is
   sufficient. Minimal containers without Python need the frozen Linux build.
3. **Tkinter may be missing.** Ubuntu Server has no `python3-tk` (and no display).
   The CLI provides every function headless; the GUI is optional.
4. **Privileges.** Many checks (BitLocker status, security policy export,
   `/etc/shadow` permissions, `sshd -T`, full SUID enumeration, Defender
   preferences) need Administrator/root. The tool never elevates itself; such
   checks are **skipped** and listed in the report's *Limitations* section.
5. **Execution from USB may be blocked** by AppLocker/WDAC, Defender ASR rules,
   `noexec` mount options, or device-control policy. Coordinate with the
   endpoint team; the tool does not attempt to bypass any control.
6. **AV/EDR false positives.** PyInstaller binaries and anything that bundles
   Nmap are frequently flagged. Sign the executable and pre-register its hash
   with the EDR team rather than disabling protection.
7. **Read-only media.** If the USB stick is write-protected, choose another
   output directory (`--output` / GUI prompt). Logs follow the output directory.
8. **Version-based vulnerability data is not proof.** Distribution back-ports
   mean an "old" version string can be fully patched. Such results are
   reported as *potential* with *manual validation required*.
9. **Offline vulnerability data ages.** Offline mode uses whatever data was
   last synced to the USB; the report records the data snapshot date.
10. **Bundled third-party tools** (Nmap, OpenSSL) have their own licences
    (Nmap uses the NPSL, which restricts redistribution in some contexts).
    They are **optional**, not bundled by default, and are discovered at runtime.
11. **CIS Benchmark content is licensed.** The toolkit ships an open
    *example* baseline format; organisations import their own baseline content.
12. **Python threads cannot be killed.** A check that exceeds its timeout is
    abandoned and its subprocesses terminated; pure-Python work inside it may
    finish in the background (it cannot alter results already recorded).

## 4. Repository and USB layout

Repository (development):

```
Claude-project-1/
├── README.md                 Quick start
├── LICENSES.md               Licence of the toolkit and of every dependency
├── pyproject.toml            Package metadata, pytest config
├── requirements-dev.txt      Dev/test/build dependencies (not needed at runtime)
├── config/
│   └── default.toml          Default configuration (safe, conservative limits)
├── baselines/
│   └── README.md             Baseline import notes (Module F, Phase 7)
├── docs/
│   ├── ARCHITECTURE.md       This document
│   ├── DEVELOPMENT.md        Developer setup, adding checks
│   ├── PHASES.md             Phase plan and current status
│   └── USER_GUIDE.md         Operator guide (expanded in Phase 10)
├── scripts/
│   ├── PortableSecurityAudit.sh   Linux manual launcher
│   ├── PortableSecurityAudit.bat  Windows manual launcher (source build)
│   └── build_manifest.py          Writes checksums/manifest.json
├── src/psatoolkit/
│   ├── __init__.py           Version
│   ├── __main__.py           `python -m psatoolkit`
│   ├── cli.py                Headless interface
│   ├── core/                 Engine and cross-cutting services
│   ├── modules/              Assessment modules (A–F + demo)
│   ├── reporting/            Report writers and report integrity
│   └── gui/                  Tkinter dashboard
└── tests/                    pytest suite (mocked, no real system changes)
```

USB drive (release):

```
PortableSecurityAudit/
├── PortableSecurityAudit.exe     Windows standalone build (Phase 8)
├── PortableSecurityAudit.sh      Linux launcher (runs linux/ build or source)
├── app/                          Python source for the Linux edition
├── linux/                        Optional Linux frozen build
├── config/                       default.toml + local.toml overrides
├── modules/                      (reserved for data-only check packs)
├── baselines/                    Imported organisational baselines
├── tools/                        Optional third-party tools (nmap, ...) by OS
│   ├── windows/  linux/
├── vulndata/                     Offline vulnerability data snapshots
├── reports/                      Generated reports (one folder per assessment)
├── logs/                         Application and audit logs
├── docs/                         User manual, developer docs
├── checksums/manifest.json       SHA-256 of every shipped file
├── README.md
└── LICENSES.md
```

The application locates this root as follows: the directory of the frozen
executable; otherwise `$PSA_HOME`; otherwise the repository root.

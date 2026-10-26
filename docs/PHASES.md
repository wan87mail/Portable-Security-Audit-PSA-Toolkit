# Delivery phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, limitations, project structure | **Done** |
| 2 | Portable shell, authorization workflow, engine, GUI/CLI, JSON report, integrity, demo mode | **Done** |
| 3 | Windows (Module B) and Linux (Module C) read-only checks; Module A inventory | Planned |
| 4 | Module D controlled network assessment (rate-limited TCP connect, TLS checks, optional Nmap) | Planned |
| 5 | Finding normalisation, risk scoring, Module E vulnerability data (offline CVE/CVSS snapshots, optional Greenbone) | Planned |
| 6 | HTML, PDF, CSV reports; executive summary; remediation roadmap | Planned |
| 7 | Module F baselines and custom baseline import; expanded demo and test checklists | Planned |
| 8 | PyInstaller Windows `.exe`, Linux frozen build, USB preparation scripts | Planned |
| 9 | Security, dependency and usability review | Planned |
| 10 | Final documentation and release checklist | Planned |

## Phase 1–2 deliverables

| File | Purpose |
|---|---|
| `src/psatoolkit/core/models.py` | Typed data model: Finding, Evidence, Reference, CheckResult, AssessmentResult |
| `src/psatoolkit/core/osdetect.py` | Windows (10/11/Server 2019/2022/2025 by build) and Linux (`/etc/os-release`) detection |
| `src/psatoolkit/core/privileges.py` | Admin/root detection and operator guidance; never elevates |
| `src/psatoolkit/core/validation.py` | Target, CIDR, port, text and path validation with hard limits |
| `src/psatoolkit/core/authorization.py` | Notice, confirmation record, per-target remote scope, dry-run preview |
| `src/psatoolkit/core/safe_exec.py` | Allow-listed, read-only, shell-free subprocess runner with timeouts and stop |
| `src/psatoolkit/core/engine.py` | Check/Module contract, gating, isolation, timeouts, emergency stop |
| `src/psatoolkit/core/config.py` | TOML configuration with clamped safe bounds (Python 3.10 fallback parser) |
| `src/psatoolkit/core/paths.py` | Portable root discovery, writable output directory selection |
| `src/psatoolkit/core/logging_setup.py` | App log and hash-chained audit log |
| `src/psatoolkit/core/redaction.py` | Secret redaction for evidence, logs and reports |
| `src/psatoolkit/core/integrity.py` | SHA-256 manifest build/verify |
| `src/psatoolkit/core/tempfiles.py` | 0700 temporary workspace, always removed |
| `src/psatoolkit/core/session.py` | Façade shared by CLI and GUI |
| `src/psatoolkit/modules/system_info.py` | Module A part 1: asset identification, platform support |
| `src/psatoolkit/modules/demo.py` | Demo module: labelled sample findings, no commands |
| `src/psatoolkit/reporting/json_report.py` | JSON report with canonical SHA-256 and `.sha256` sidecar |
| `src/psatoolkit/cli.py` | Headless interface |
| `src/psatoolkit/gui/app.py` | Tkinter dashboard with the 8 required controls |
| `scripts/PortableSecurityAudit.{sh,bat}` | Manual launchers (isolated interpreter mode) |
| `scripts/build_manifest.py` | Drive-preparation integrity manifest |
| `tests/` | 200+ automated tests |

## Known limitations after Phase 2

- Only Module A asset identification has live checks. Windows/Linux audit
  checks arrive in Phase 3, and the network scanner in Phase 4. "Run Network
  Assessment" says so when it is pressed, and target configuration already works.
- Reports are JSON only; HTML/PDF/CSV arrive in Phase 6.
- The GUI was tested on Linux under Xvfb (Tk 9.0). It has not yet been tested
  on a physical Windows desktop; that is part of Phase 8/9 testing.
- Windows-specific code paths (`IsUserAnAdmin`, `GetTickCount64`, System32
  resolution, `CREATE_NO_WINDOW`) are covered by mocked tests only until a
  Windows CI runner or manual test is available.
- The read-only command policy is defence in depth for the toolkit's own
  checks, not a sandbox: it cannot judge arbitrary scripts, so new checks
  still need code review (Phase 9).
- The audit log is tamper-*evident*, not tamper-proof. Copy logs to
  protected storage after each engagement.

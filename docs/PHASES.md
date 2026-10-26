# Delivery phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, limitations, project structure | **Done** |
| 2 | Portable shell, authorization workflow, engine, GUI/CLI, JSON report, integrity, demo mode | **Done** |
| 3 | Windows (Module B) and Linux (Module C) read-only checks; Module A inventory | **Done** |
| 4 | Module D controlled network assessment | Not included in this build |
| 5 | Finding normalisation, risk scoring, Module E vulnerability data (offline CVE/CVSS snapshots) | **Done** |
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

## Phase 3 deliverables

| File | Purpose |
|---|---|
| `src/psatoolkit/modules/system_info.py` | Module A: interfaces/connections, listening ports, exposed risky services, software inventory |
| `src/psatoolkit/modules/windows_audit.py` | Module B: 16 checks (firewall, Defender, SMB, RDP, UAC, password/lockout, accounts, admins, patching, BitLocker, services, service ACLs, LSA/NTLM/WDigest/LLMNR, SCHANNEL, certificates, audit policy) |
| `src/psatoolkit/modules/linux_audit.py` | Module C: 15 checks (updates, SSH, firewall, privileged accounts, sudo, shadow flags, PAM policy, world-writable, sensitive files, SUID/SGID, services, encryption, AppArmor/SELinux, sysctl, certificates) |
| `src/psatoolkit/modules/certificates.py` | Shared certificate expiry/algorithm evaluation |
| `src/psatoolkit/modules/_common.py` | PowerShell JSON queries, registry reads, `/proc/net` socket parsing, references |
| `src/psatoolkit/core/hostfs.py` | Read-only filesystem view (no write methods, never follows symlinks, rootable for tests) |
| `scripts/gen_checks_doc.py` | Generates [CHECKS.md](CHECKS.md) from the code; a test fails if it is stale |
| `tests/fakes.py` | Fake command runner (still enforces the read-only policy) and in-memory filesystem |
| `docs/TEST_CHECKLIST.md` | Manual verification checklist for real Windows and Linux hosts |

Engine additions: `ctx.note()` explains passed checks in the report, and
`ctx.limitation()` records reduced coverage (e.g. "run as root for sshd -T")
without skipping the check.

## Phase 5 deliverables

| File | Purpose |
|---|---|
| `src/psatoolkit/core/normalize.py` | Consistency rules (status/severity/validation), reference validation, redaction, de-duplication, stable fingerprints |
| `src/psatoolkit/core/scoring.py` | Risk score (severity x status x confidence), remediation priority buckets, overall posture rating with coverage caveat |
| `src/psatoolkit/core/cvss.py` | CVSS v3.x base-score calculator and qualitative bands (verified against published scores) |
| `src/psatoolkit/core/versions.py` | dpkg, rpm and generic version ordering (dpkg differential-tested against the real `dpkg`) |
| `src/psatoolkit/core/vulndb.py` | Offline snapshot format, SHA-256 verification, range evaluation and package matching |
| `src/psatoolkit/modules/vuln_assessment.py` | Module E: VULN-PKG-001 known vulnerabilities in installed software |
| `scripts/vulndata_from_osv.py` | Builds a snapshot from OSV exports on an admin workstation (zip read in memory, never extracted) |
| `docs/VULNDATA.md` | How matching works, confidence levels, and how to update data safely |

Every finding now has `fingerprint`, `risk_score` and `priority`; every
result has `posture` and `data_sources`. These are shown in the CLI and GUI
and written to the JSON report.

Validation on real data: the converter processed the full OSV Debian export
(191,611 records in 12 s). The host's real `openssl` package was correctly
reported as not affected by two real Ubuntu advisories, and a simulated older
Debian 12 openssl matched 55 advisories, recommending the highest fixed version.

## Known limitations after Phase 5

- Matching is version-based. Results are *potential*: reachability of the
  vulnerable code is not tested, and nothing is exploited.
- No snapshot ships with the toolkit; build one before each engagement
  ([VULNDATA.md](VULNDATA.md)). Without it, VULN-PKG-001 is skipped with
  instructions.
- Windows has no distribution advisory feed in OSV; only organisation-supplied
  records are matched, with low confidence.
- Debian OSV records usually carry no CVSS score; those advisories default to
  Medium, as the rationale states.
- CVSS v4.0 vectors are recorded but not scored locally.
- Integration with external scanners (Nmap, Greenbone/OpenVAS) is not included.

## Known limitations after Phase 3

- **Windows checks have not yet run on a real Windows host.** They are tested
  against mocked PowerShell output (55 tests, and every script is verified
  against the read-only policy). Work through
  [TEST_CHECKLIST.md](TEST_CHECKLIST.md) on Windows 10/11 and Server
  2019/2022/2025 before field use.
- `net accounts` (WIN-ACCT-001) is parsed in English only; other display
  languages produce a *skipped* result with an explanation.
- Patch checks are offline: Windows infers missing updates from install dates;
  Linux uses the local package cache (the tool never runs `apt update`).
  Catalogue-based CVE matching arrives in Phase 5.
- Linux process names for listening sockets owned by other users, `sshd -T`,
  sudoers, `/etc/shadow` flags and firewall rule sets need root.
- Filesystem sweeps (LNX-PERM-001, LNX-SUID-001) can take minutes on large
  servers with cold caches; each has a 600-second budget.
- Inside containers, systemd service and disk encryption checks are skipped
  (they describe the host, not the container).

## Known limitations after Phase 2 (still applicable)

- No network assessment module is included in this build. "Run Network
  Assessment" says so when pressed; target configuration still works.
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

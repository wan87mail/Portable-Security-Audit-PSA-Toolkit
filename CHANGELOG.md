# Changelog

All notable changes to the Portable Security Audit toolkit. Versions follow
[semantic versioning](https://semver.org/): a breaking change to the report format,
the command line or the baseline format increases the major version.

## [1.0.0] - 2026-10-27

First production release (Phase 10).

### Added
- Full IT administrator manual (`docs/USER_GUIDE.md`): roles, the engagement
  workflow, GUI and CLI reference, the toolkit's footprint on the target, how to
  read results, retention and hand-over, drive maintenance and a configuration
  reference.
- Release and per-engagement checklist (`docs/RELEASE_CHECKLIST.md`), this
  changelog, and a security policy (`SECURITY.md`).
- Documentation tests: relative links and anchors resolve, the version and the
  changelog agree, and the docs make no stale "planned" or "Phase N" promises.

### Changed
- The GUI, configuration comments and launchers no longer refer to future phases.
  They state that this build has no network assessment module.
- The README and the example report are updated for 1.0.

## [0.9.0] - 2026-10-27

Security, dependency and usability review (Phase 9); see `docs/SECURITY_REVIEW.md`.

### Security
- Windows commands are resolved as `<name>.exe` from the system directory only.
  `shutil.which()` searched the current directory and accepted `.bat`/`.cmd`
  files (SR-01).
- HostFS reads regular files only. Device nodes (`/dev/watchdog`) and FIFOs are
  refused before they are opened (SR-02).
- Baseline paths must be canonical, and symlinks to protected files are refused
  at run time (SR-03, SR-04).
- Least-privilege command allow-list: 15 programs with strict rules, down from 28 (SR-08–SR-10).
- Output is capped while it is read. Redirection hooks are removed from the Windows
  child environment. Report and log folders are created `0700`. Launchers are
  hardened. Baseline import is TOCTOU-safe, and inputs from other people are
  read with size and file-type limits.
- Supply chain: GitHub Actions are pinned to commit SHAs, and build dependencies
  are hash-locked (`requirements-build.lock`, `--require-hashes`).

### Changed
- The CLI states that this build has no network module, and reports `--target`
  as ignored in demo mode. Missing help texts were added.

## [0.8.0] - 2026-10-27

Standalone builds and USB preparation (Phase 8).

### Added
- PyInstaller one-folder builds for Windows and Linux. The executable never
  requests elevation.
- `scripts/prepare_usb.py` (assemble and update drives) and the `selftest` command.
- GitHub Actions: tests on Ubuntu 22.04/24.04 and Windows Server 2022/2025
  (Python 3.10/3.12) with a live read-only audit of each runner, plus both
  builds and a drive image.

### Fixed
- Integrity files are written with LF line endings on Windows (`sha256sum -c`).
- Windows version detection no longer starts `cmd /c ver` (Python 3.10).
- Without `default.toml`, the configuration defaults produced JSON-only reports.

## [0.7.0] - 2026-10-27

Organisational baselines (Phase 7).

### Added
- Module F: `psa-baseline-1` baselines with 11 read-only collectors, strict
  validation, secret-file protection, `import-baseline`, and example baselines
  for Ubuntu and Windows.
- An expanded demo covering every severity and status, and a manual test checklist.

## [0.6.0] - 2026-10-26

Reports (Phase 6).

### Added
- HTML (no JavaScript, strict CSP), PDF (dependency-free writer) and CSV
  (formula-injection safe) reports, with an executive summary, posture and a
  remediation roadmap.
- `SHA256SUMS`, `verify-report` and `export-report`.

## [0.5.0] - 2026-10-26

Scoring and vulnerability data (Phase 5).

### Added
- Finding normalization, de-duplication, stable fingerprints, risk score,
  priority and posture.
- CVSS v3.1 calculator, and dpkg/rpm/generic version comparison.
- Module E: offline, integrity-checked vulnerability snapshots (`psa-vulndata-1`)
  built from OSV exports.

## [0.3.0] - 2026-10-26

Read-only checks (Phase 3).

### Added
- Module A inventory (interfaces, ports, risky services, software), Module B
  (16 Windows checks) and Module C (15 Linux checks).
- The HostFS read-only filesystem view, and a generated check catalogue
  (`docs/CHECKS.md`).

## [0.2.0] - 2026-10-24

Foundation (Phases 1–2).

### Added
- Architecture and limitations, the authorization workflow (notice and
  confirmation phrase), and an allow-listed, shell-free command runner.
- Check engine with gating, timeouts and emergency stop; Tkinter dashboard with
  8 controls, and a CLI.
- JSON report with a canonical hash, a hash-chained audit log, the integrity
  manifest and demo mode.

Phase 4 (controlled network assessment) is not included in any release.

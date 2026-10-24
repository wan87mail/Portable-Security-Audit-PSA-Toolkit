# Portable Security Audit (PSA) Toolkit

A portable, **read-only** security assessment toolkit for IT administrators,
designed to run from a USB flash drive on systems they are **authorized** to
assess (Windows 10/11, Windows Server 2019/2022/2025, Ubuntu 22.04/24.04 and
other Linux distributions on a best-effort basis).

> **Authorized use only.** The toolkit refuses to run until the operator
> confirms authorization. It contains no exploitation, credential-access,
> persistence or evasion features, and it never changes the target's
> configuration.

**Status:** Phases 1–2 of 10 are complete (architecture, portable shell,
authorization workflow, engine, GUI/CLI, JSON reports, integrity
verification, demo mode). See [docs/PHASES.md](docs/PHASES.md).

## Quick start (from source)

```bash
# Linux
bash scripts/PortableSecurityAudit.sh info            # detected OS, privileges, check plan
bash scripts/PortableSecurityAudit.sh audit --demo    # safe demo with sample findings
sudo bash scripts/PortableSecurityAudit.sh audit      # authorized local audit
bash scripts/PortableSecurityAudit.sh                 # GUI (needs python3-tk and a display)
```

```bat
rem Windows (development; field use will use PortableSecurityAudit.exe from Phase 8)
scripts\PortableSecurityAudit.bat info
scripts\PortableSecurityAudit.bat audit --demo
scripts\PortableSecurityAudit.bat
```

Non-interactive (scripted) runs must state the authorization explicitly:

```bash
bash scripts/PortableSecurityAudit.sh audit --operator "Jane Admin" \
     --reference "CHG-1234" --confirm "I AM AUTHORIZED" --output /mnt/reports
```

## Commands

| Command | Purpose |
|---|---|
| `gui` (default) | Tkinter dashboard |
| `info` | OS detection, privilege state, and which checks will run or be skipped and why |
| `modules [-v]` | List modules and checks with their requirements |
| `audit [--demo] [--modules ...] [--output DIR] [--target T --target-ref REF]...` | Run an authorized assessment |
| `preview-scan --target T [--ports P]` | Dry run: what a network scan would contact (sends nothing) |
| `verify` | Verify the drive against `checksums/manifest.json` |
| `verify-report PATH` / `verify-log PATH` | Verify a report's hashes / an audit log's hash chain |
| `reports` | List previous reports |
| `build-manifest` | (Drive preparation) write the integrity manifest |

Exit codes: `0` ok, `1` error, `2` usage, `3` authorization refused, `4` integrity failure, `130` stopped.

## Tests

```bash
python -m pip install pytest
python -m pytest                                  # 200+ tests, mocked; no system changes
xvfb-run -a python -m pytest tests/test_gui_smoke.py   # GUI smoke test (Linux, needs python3-tk)
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): design, components, limitations, directory layout
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md): operator guide
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): developer setup, adding checks
- [docs/PHASES.md](docs/PHASES.md): delivery plan and current status
- [LICENSES.md](LICENSES.md): licences of the toolkit and its dependencies

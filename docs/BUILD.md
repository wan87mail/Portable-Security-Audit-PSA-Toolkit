# Building, packaging and deploying

This guide covers building the standalone Windows executable, the Linux
build, preparing the USB drive, and keeping it up to date.

> **A Windows `.exe` does not run on Linux, and a Linux build does not run on
> Windows.** PyInstaller bundles the interpreter for the OS it runs on, so each
> edition is built on its own OS. The drive can carry both, plus the Python
> source edition for Linux hosts that have Python 3.10+.

## 1. Option A: download the builds from CI (no local build needed)

Every push runs `.github/workflows/build.yml` on GitHub:

| Job | What it does |
|---|---|
| `test` | Full test suite on Ubuntu 22.04/24.04 and Windows Server 2022/2025 (Python 3.10, 3.12), plus a live read-only audit of each runner |
| `build-windows` | Builds `PortableSecurityAudit.exe`, self-tests it (`selftest --require-gui`) |
| `build-linux` | Builds the Linux binary on Ubuntu 22.04 (oldest supported glibc), self-tests it |
| `usb-image` | Assembles a complete drive with both builds, verifies it and runs a demo assessment |

On GitHub, open **Actions**, select the run, and download **PortableSecurityAudit-usb** (the complete drive) or
the individual builds. Artifacts are kept for 30 days.

CI builds are **unsigned**. For production use, build locally and sign (section 2), or
sign the downloaded executable before preparing the drive.

## 2. Option B: build the Windows executable locally

On a Windows 10/11 **build workstation** (not an assessment target):

1. Install Python 3.12 from <https://www.python.org/downloads/windows/>, with the *py launcher* and *tcl/tk* options selected.
2. Clone or download this repository, then in PowerShell:

   ```powershell
   cd C:\src\Claude-project-1
   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
   ```

   The script creates an isolated `.build-venv`, installs the hash-locked build tools
   (`requirements-build.lock`, with `--require-hashes`), runs the test suite, builds with PyInstaller, smoke-tests the
   result (`--version`, a demo assessment, report verification) and prints the SHA-256.

3. Output: `dist\windows\PortableSecurityAudit\` (`PortableSecurityAudit.exe` plus `_internal\`).

| Option | Effect |
|---|---|
| *(default)* one-folder build | No unpacking on the target, faster start, fewer antivirus false positives |
| `-OneFile` | A single `.exe` that unpacks itself into `%TEMP%` on each run (removed on exit) |
| `-SignThumbprint <sha1>` | Authenticode-sign with a code-signing certificate from your store (needs `signtool`, Windows SDK) |
| `-SkipTests` | Skip the test suite (not recommended) |
| `-PythonExe <path>` | Build with a specific interpreter |

The executable never requests elevation (`uac_admin=False`); operators choose *Run as
administrator* when their authorization covers it. When it is double-clicked, the GUI
starts and the console window it owns is hidden; when run from `cmd`/PowerShell with
arguments it behaves as the CLI.

**Antivirus / EDR:** sign the executable and give its SHA-256 to your endpoint-security
team for allow-listing *before* field use. Never disable protection to run the tool.

## 3. Build the Linux edition

On the **oldest** distribution you support (e.g. Ubuntu 22.04), with Python 3.10+ and Tk:

```bash
sudo apt install python3-venv python3-tk
bash packaging/build_linux.sh            # or --onefile
```

Output: `dist/linux/PortableSecurityAudit/`. Self-test it: `dist/linux/PortableSecurityAudit/PortableSecurityAudit selftest --require-gui`.

> Use a distribution Python or the python.org/`actions/setup-python` builds. Standalone
> interpreters that embed Tcl/Tk 9 (some `uv`/python-build-standalone versions) build a
> working CLI, but PyInstaller cannot bundle their GUI libraries; `selftest --require-gui`
> detects this.

Linux targets without a compatible glibc, or USB drives mounted `noexec`, fall back to the
source edition in `app/` automatically (the launcher handles this), provided the target has
Python 3.10+.

## 4. Prepare the USB drive

On the build workstation, with the drive mounted (e.g. `E:` or `/media/$USER/PSA`):

```bash
python scripts/prepare_usb.py E:\PortableSecurityAudit ^
       --windows-build dist\windows\PortableSecurityAudit ^
       --linux-build  dist\linux\PortableSecurityAudit ^
       --vulndata build\vulndata ^
       --baseline my-org-windows.json --baseline my-org-linux.json
```

Resulting layout:

```
PortableSecurityAudit/
├── PortableSecurityAudit.exe, _internal/     Windows edition (double-click; Run as administrator for full checks)
├── PortableSecurityAudit.sh                  Linux launcher (bash PortableSecurityAudit.sh)
├── linux/PortableSecurityAudit/              Linux edition
├── app/psatoolkit/                           Source edition (fallback for Linux with Python 3.10+)
├── PortableSecurityAudit-source.bat          Source edition on Windows hosts with Python
├── config/default.toml                       Settings (put overrides in config/local.toml)
├── baselines/  (+ examples/)                 Imported organisational baselines
├── vulndata/                                 Offline vulnerability snapshot
├── tools/windows, tools/linux                Optional third-party tools (empty by default)
├── reports/, logs/                           Created during assessments
├── docs/, README.md, LICENSES.md, RELEASE-INFO.txt
└── checksums/manifest.json                   SHA-256 of every program and data file
```

The script validates the baselines and vulnerability snapshot **before** writing anything,
refuses to write into a folder that is not empty or not a toolkit drive, and prints the
**manifest SHA-256**: record it in your change ticket or release notes.

To update an existing drive (new version, new snapshot), add `--update`. Program files are
replaced; `reports/`, `logs/`, `config/local.toml`, imported baselines and `vulndata/`
(unless `--vulndata` is given) are kept.

Optionally write-protect the drive afterwards (hardware switch, or a read-only filesystem)
and set `output_dir` in `config/local.toml`, or use `--output`, so reports go elsewhere.

## 5. Updating vulnerability data safely

See [VULNDATA.md](VULNDATA.md): download the OSV exports on the connected build workstation,
convert them with `scripts/vulndata_from_osv.py`, then `prepare_usb.py --update --vulndata …`.

## 6. Verifying tool and dependency integrity

| What | How |
|---|---|
| The drive | `PortableSecurityAudit verify`; compare the printed manifest SHA-256 with your records |
| The build contents | `PortableSecurityAudit selftest` (add `--require-gui` for GUI builds) |
| The executable signature (Windows) | `Get-AuthenticodeSignature .\PortableSecurityAudit.exe` |
| Vulnerability data | Checked automatically before use (its own `manifest.json` hashes) |
| Reports | `verify-report <report folder>` |
| Build dependencies | `requirements-build.lock` hash-locks PyInstaller and its dependencies; CI actions are pinned to commit SHAs. To update, see [SECURITY_REVIEW.md](SECURITY_REVIEW.md) section 4 |

## 7. Running on an authorized target and exporting reports

1. Insert the drive. Nothing runs automatically.
2. Windows: double-click `PortableSecurityAudit.exe` (or right-click, *Run as administrator*).
   Linux: `bash /media/$USER/PSA/PortableSecurityAudit/PortableSecurityAudit.sh` (or with `sudo`).
3. Run `verify` first (GUI: **7. Verify Tool Integrity**).
4. Complete the authorization dialog and run the assessment.
5. Hand over the results: **6. Export Report** in the GUI, or `export-report <report folder> <destination>`.
   Exports are refused if the report fails integrity verification.

## 8. Troubleshooting builds

| Problem | Fix |
|---|---|
| `selftest --require-gui` fails: Tkinter or `libtcl…so` missing | Install `python3-tk` (Linux) or reinstall Python with *tcl/tk* (Windows); avoid Tcl/Tk 9 standalone interpreters |
| Linux binary: `GLIBC_2.xx not found` | Build on an older distribution (Ubuntu 22.04), or use the source edition |
| `Permission denied` running from USB on Linux | The drive is mounted `noexec`; the launcher falls back to the source edition (needs Python 3.10+) |
| Antivirus quarantines the `.exe` | Sign it, prefer the one-folder build, and have the EDR team allow-list its SHA-256 |
| `prepare_usb.py` refuses the target | It is not empty or not a toolkit drive; choose an empty folder, or use `--update` for an existing drive |
| `verify` lists *unexpected files* after importing a baseline | Run `build-manifest` (or `prepare_usb.py --update`) to include the new file |

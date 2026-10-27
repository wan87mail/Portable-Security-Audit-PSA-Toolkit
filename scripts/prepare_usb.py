#!/usr/bin/env python3
"""Assemble a Portable Security Audit drive (run on a trusted admin workstation).

    python scripts/prepare_usb.py E:\\PortableSecurityAudit --windows-build dist\\windows\\PortableSecurityAudit
    python scripts/prepare_usb.py /media/$USER/PSA/PortableSecurityAudit \\
           --linux-build dist/linux/PortableSecurityAudit --vulndata build/vulndata \\
           --baseline my-org-linux.json

Creates the drive layout, copies the builds, the source edition (for Linux
hosts with Python 3.10+), configuration, docs, optional vulnerability data and
baselines, then writes checksums/manifest.json and prints its SHA-256 for the
release notes.

Safety: the target must be empty or an existing toolkit drive. With --update,
program files are replaced while reports/, logs/, config/local.toml, imported
baselines and vulndata/ (unless --vulndata is given) are kept.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from psatoolkit import TOOL_NAME, __version__  # noqa: E402
from psatoolkit.core.baseline import BaselineError, load_baseline  # noqa: E402
from psatoolkit.core.integrity import verify_manifest, write_manifest  # noqa: E402
from psatoolkit.core.validation import safe_filename  # noqa: E402
from psatoolkit.core.vulndb import VulnDataError, open_snapshot  # noqa: E402

PROGRAM_ITEMS = ["PortableSecurityAudit.exe", "_internal", "linux", "app", "docs", "PortableSecurityAudit.sh",
                 "PortableSecurityAudit-source.bat", "README.md", "LICENSES.md", "RELEASE-INFO.txt",
                 "config/default.toml", "baselines/README.md", "baselines/examples", "tools/README.txt"]
KEEP_ON_UPDATE = ["reports", "logs", "config/local.toml", "vulndata", "baselines/*.json"]
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".pytest_cache")


class PrepareError(Exception):
    pass


def is_toolkit_drive(target: Path) -> bool:
    return (target / "config" / "default.toml").is_file() or (target / "checksums" / "manifest.json").is_file()


def check_target(target: Path, update: bool) -> None:
    if target.exists() and not target.is_dir():
        raise PrepareError(f"{target} exists and is not a directory")
    if target.exists() and any(target.iterdir()):
        if not is_toolkit_drive(target):
            raise PrepareError(f"{target} is not empty and is not a {TOOL_NAME} drive; refusing to write into it.")
        if not update:
            raise PrepareError(f"{target} already contains a {TOOL_NAME} drive; use --update to refresh the "
                               "program files (reports, logs, local.toml and baselines are kept).")


def remove_program_files(target: Path) -> None:
    for item in PROGRAM_ITEMS:
        p = target / item
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        elif p.exists() or p.is_symlink():
            p.unlink()


def copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, ignore=IGNORE, dirs_exist_ok=True, symlinks=False)


def copy_build(build: Path, target: Path, kind: str) -> str:
    if kind == "windows":
        if build.is_dir():
            if not (build / "PortableSecurityAudit.exe").is_file():
                raise PrepareError(f"{build} does not contain PortableSecurityAudit.exe")
            copy_tree(build, target)
            return "Windows executable (one-folder build) in the drive root"
        if build.suffix.lower() != ".exe":
            raise PrepareError(f"{build} is not a Windows executable")
        shutil.copy2(build, target / "PortableSecurityAudit.exe")
        return "Windows executable (single file) in the drive root"
    dest = target / "linux"
    dest.mkdir(parents=True, exist_ok=True)
    if build.is_dir():
        if not (build / "PortableSecurityAudit").is_file():
            raise PrepareError(f"{build} does not contain the PortableSecurityAudit binary")
        copy_tree(build, dest / "PortableSecurityAudit")
        (dest / "PortableSecurityAudit" / "PortableSecurityAudit").chmod(0o755)
        return "Linux binary (one-folder build) in linux/PortableSecurityAudit/"
    shutil.copy2(build, dest / "PortableSecurityAudit")
    (dest / "PortableSecurityAudit").chmod(0o755)
    return "Linux binary (single file) in linux/"


def prepare(target: Path, windows_build: Path | None, linux_build: Path | None, include_source: bool,
            vulndata: Path | None, baselines: list[Path], update: bool) -> dict:
    check_target(target, update)
    # Validate inputs before touching the drive.
    snapshot = None
    if vulndata:
        try:
            snapshot = open_snapshot(vulndata)
        except (FileNotFoundError, VulnDataError) as exc:
            raise PrepareError(f"vulnerability data in {vulndata} is invalid: {exc}") from None
    loaded = []
    for b in baselines:
        try:
            loaded.append((b, load_baseline(b)))
        except BaselineError as exc:
            raise PrepareError(f"baseline {b} rejected: {exc}") from None
    if not (windows_build or linux_build or include_source):
        raise PrepareError("nothing to install: give --windows-build and/or --linux-build, or keep the source edition")

    target.mkdir(parents=True, exist_ok=True)
    if update:
        remove_program_files(target)
    contents = []
    if windows_build:
        contents.append(copy_build(windows_build, target, "windows"))
    if linux_build:
        contents.append(copy_build(linux_build, target, "linux"))
    if include_source:
        copy_tree(REPO / "src" / "psatoolkit", target / "app" / "psatoolkit")
        shutil.copy2(REPO / "scripts" / "PortableSecurityAudit.bat", target / "PortableSecurityAudit-source.bat")
        contents.append("Source edition in app/ (needs Python 3.10+ on the host)")
    shutil.copy2(REPO / "scripts" / "PortableSecurityAudit.sh", target / "PortableSecurityAudit.sh")
    (target / "PortableSecurityAudit.sh").chmod(0o755)

    (target / "config").mkdir(exist_ok=True)
    shutil.copy2(REPO / "config" / "default.toml", target / "config" / "default.toml")
    copy_tree(REPO / "docs", target / "docs")
    for name in ("README.md", "LICENSES.md"):
        shutil.copy2(REPO / name, target / name)
    (target / "baselines").mkdir(exist_ok=True)
    shutil.copy2(REPO / "baselines" / "README.md", target / "baselines" / "README.md")
    copy_tree(REPO / "baselines" / "examples", target / "baselines" / "examples")
    for src, baseline in loaded:
        shutil.copy2(src, target / "baselines" / f"{safe_filename(baseline.name)}.json")
        contents.append(f"Baseline '{baseline.name}' v{baseline.version} ({len(baseline.rules)} rules)")
    for sub in ("windows", "linux"):
        (target / "tools" / sub).mkdir(parents=True, exist_ok=True)
    (target / "tools" / "README.txt").write_text(
        "Optional third-party tools. Review their licences (LICENSES.md) before copying them here.\n",
        encoding="utf-8")
    if snapshot:
        dest = target / "vulndata"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(vulndata, dest)
        contents.append(f"Vulnerability data snapshot {snapshot.manifest.get('snapshot_date')} "
                        f"({snapshot.record_count} records)")
    for sub in ("reports", "logs", "checksums", "vulndata"):
        (target / sub).mkdir(exist_ok=True)

    built = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (target / "RELEASE-INFO.txt").write_text(
        f"{TOOL_NAME} {__version__}\nPrepared: {built}\n\nContents:\n" + "".join(f"  - {c}\n" for c in contents)
        + "\nVerify before every engagement:  PortableSecurityAudit verify\n"
          "Compare the manifest SHA-256 printed by 'verify' with the value recorded when the drive was prepared.\n",
        encoding="utf-8")
    manifest_path, digest = write_manifest(target, __version__)
    report = verify_manifest(target)
    if not report.ok:
        raise PrepareError("integrity verification of the prepared drive failed:\n" + report.summary())
    return {"target": str(target), "contents": contents, "manifest": str(manifest_path), "manifest_sha256": digest,
            "files": report.verified}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", type=Path, help="drive folder, e.g. E:\\PortableSecurityAudit")
    p.add_argument("--windows-build", type=Path, help="dist/windows/PortableSecurityAudit (folder) or the .exe")
    p.add_argument("--linux-build", type=Path, help="dist/linux/PortableSecurityAudit (folder) or the binary")
    p.add_argument("--no-source", action="store_true", help="do not include the Python source edition")
    p.add_argument("--vulndata", type=Path, help="offline vulnerability snapshot directory to include")
    p.add_argument("--baseline", type=Path, action="append", default=[], help="baseline JSON to include (repeatable)")
    p.add_argument("--update", action="store_true", help="refresh an existing drive, keeping reports and settings")
    args = p.parse_args(argv)
    try:
        result = prepare(args.target.resolve(), args.windows_build, args.linux_build, not args.no_source,
                         args.vulndata, args.baseline, args.update)
    except PrepareError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Prepared {result['target']} ({TOOL_NAME} {__version__}):")
    for c in result["contents"]:
        print(f"  - {c}")
    print(f"Integrity manifest: {result['files']} files -> {result['manifest']}")
    print(f"Manifest SHA-256: {result['manifest_sha256']}")
    print("Record this value in your change ticket / release notes, then eject the drive safely.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

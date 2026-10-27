# PyInstaller spec for PortableSecurityAudit (Windows and Linux).
#
# Build with packaging/build_windows.ps1 or packaging/build_linux.sh, which set
# PSA_ONEFILE and generate packaging/version_info.txt (Windows only).
#
# Default is a one-folder ("onedir") build: the executable plus an _internal\
# folder. Unlike --onefile it does not unpack itself into the target's %TEMP%
# on every run, starts faster and triggers fewer antivirus false positives.
# UPX compression is disabled for the same reason.
# pylint: disable=undefined-variable
import os
from pathlib import Path

ROOT = Path(SPECPATH).parent                       # noqa: F821 - provided by PyInstaller
ONEFILE = os.environ.get("PSA_ONEFILE") == "1"
VERSION_FILE = ROOT / "packaging" / "version_info.txt"

a = Analysis(                                       # noqa: F821
    [str(ROOT / "packaging" / "psa_entry.py")],
    pathex=[str(ROOT / "src")],
    hiddenimports=["psatoolkit.gui.app"],          # imported lazily by the CLI
    excludes=["unittest", "pydoc", "doctest", "lib2to3", "pytest", "setuptools", "pip", "test"],
    noarchive=False,
)
pyz = PYZ(a.pure)                                   # noqa: F821

exe_kwargs = dict(
    name="PortableSecurityAudit",
    console=True,              # the CLI needs a console; the GUI hides a console it owns (gui/app.py)
    upx=False,
    strip=False,
    debug=False,
    disable_windowed_traceback=False,
    uac_admin=False,           # never request elevation; operators choose "Run as administrator"
    version=str(VERSION_FILE) if VERSION_FILE.exists() else None,
)

if ONEFILE:
    exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], runtime_tmpdir=None, **exe_kwargs)  # noqa: F821
else:
    exe = EXE(pyz, a.scripts, [], exclude_binaries=True, **exe_kwargs)                     # noqa: F821
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="PortableSecurityAudit")  # noqa: F821

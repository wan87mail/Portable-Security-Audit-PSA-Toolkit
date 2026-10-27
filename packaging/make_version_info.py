#!/usr/bin/env python3
"""Write packaging/version_info.txt (Windows file version resource) from psatoolkit.__version__."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from psatoolkit import TOOL_NAME, __version__  # noqa: E402

TEMPLATE = """# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(filevers={t}, prodvers={t}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
                    subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', ''),
      StringStruct('FileDescription', '{name} - authorized, read-only security assessment'),
      StringStruct('FileVersion', '{v}'),
      StringStruct('InternalName', 'PortableSecurityAudit'),
      StringStruct('OriginalFilename', 'PortableSecurityAudit.exe'),
      StringStruct('ProductName', '{name}'),
      StringStruct('ProductVersion', '{v}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main() -> int:
    parts = [int(p) for p in __version__.split(".")[:3]]
    parts += [0] * (4 - len(parts))
    out = ROOT / "packaging" / "version_info.txt"
    out.write_text(TEMPLATE.format(t=tuple(parts), v=__version__, name=TOOL_NAME), encoding="utf-8")
    print(f"Wrote {out} ({__version__})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Write checksums/manifest.json for a prepared USB drive or release folder.

Usage:  python scripts/build_manifest.py [ROOT]
ROOT defaults to the repository root. Run this as the LAST step of drive
preparation, then record the printed manifest SHA-256 in the release notes
or change ticket so operators can compare it out-of-band.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from psatoolkit import __version__  # noqa: E402
from psatoolkit.core.integrity import verify_manifest, write_manifest  # noqa: E402


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else REPO
    if not root.is_dir():
        print(f"{root} is not a directory", file=sys.stderr)
        return 1
    path, digest = write_manifest(root, __version__)
    report = verify_manifest(root)
    print(f"Wrote {path} ({report.verified} files)")
    print(f"Manifest SHA-256: {digest}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())

"""Private temporary workspace that is always removed afterwards."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


class SecureTempDir:
    """Context manager for a 0700 temporary directory.

    Some read-only checks need scratch space (e.g. ``secedit /export`` writes
    the policy to a file). The directory is created under ``base`` when given
    (normally the output drive), otherwise the system temp directory.
    """

    def __init__(self, base: Path | None = None, prefix: str = "psa-") -> None:
        self.base = base
        self.prefix = prefix
        self.path: Path | None = None

    def __enter__(self) -> Path:
        base = str(self.base) if self.base and self.base.is_dir() else None
        self.path = Path(tempfile.mkdtemp(prefix=self.prefix, dir=base))
        try:
            os.chmod(self.path, 0o700)
        except OSError:
            pass
        return self.path

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self.path and self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
        self.path = None

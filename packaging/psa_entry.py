"""PyInstaller entry point for the frozen PortableSecurityAudit executable."""

import sys

from psatoolkit.cli import main

if __name__ == "__main__":
    sys.exit(main())

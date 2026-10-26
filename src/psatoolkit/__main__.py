"""Allow ``python -m psatoolkit``."""

import sys

from psatoolkit.cli import main

if __name__ == "__main__":
    sys.exit(main())

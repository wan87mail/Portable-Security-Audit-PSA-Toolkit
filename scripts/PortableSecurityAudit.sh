#!/usr/bin/env bash
# Portable Security Audit - Linux launcher.
#
# Launch MANUALLY from the USB drive. Nothing runs automatically on insertion.
#   bash PortableSecurityAudit.sh info
#   sudo bash PortableSecurityAudit.sh audit          # elevated checks
#   bash PortableSecurityAudit.sh audit --demo
# Using "bash <script>" works even when the USB is mounted noexec.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1) Frozen Linux build on the USB drive (built in Phase 8), if present.
if [[ -x "$DIR/linux/PortableSecurityAudit" ]]; then
    exec "$DIR/linux/PortableSecurityAudit" "$@"
fi

# 2) Source edition: USB layout (app/) or repository layout (../src).
if [[ -d "$DIR/app/psatoolkit" ]]; then
    APP="$DIR/app"; export PSA_HOME="$DIR"
elif [[ -d "$DIR/../src/psatoolkit" ]]; then
    APP="$(cd "$DIR/../src" && pwd)"; export PSA_HOME="$(cd "$DIR/.." && pwd)"
else
    echo "Cannot find the psatoolkit package next to this launcher." >&2
    exit 1
fi

# Only trust interpreters in system locations, never one from the current directory.
PY=""
for candidate in /usr/bin/python3 /usr/local/bin/python3 /usr/bin/python3.13 /usr/bin/python3.12 \
                 /usr/bin/python3.11 /usr/bin/python3.10; do
    if [[ -x "$candidate" ]] && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
        PY="$candidate"; break
    fi
done
if [[ -z "$PY" ]]; then
    echo "Python 3.10+ was not found in /usr/bin or /usr/local/bin." >&2
    echo "Use the frozen Linux build (linux/PortableSecurityAudit) instead; see docs/USER_GUIDE.md." >&2
    exit 1
fi

# -I: isolated mode - ignore PYTHON* environment variables and the user site
# directory on the target, so nothing on the host can inject code.
# -B: do not write .pyc files to the USB drive or the target.
exec "$PY" -I -B -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from psatoolkit.cli import main; sys.exit(main())' "$APP" "$@"

#!/usr/bin/env bash
# Build the frozen Linux edition with PyInstaller.
#
#   bash packaging/build_linux.sh [--onefile] [--skip-tests]
#
# Build on the OLDEST distribution you need to support (e.g. Ubuntu 22.04):
# PyInstaller binaries depend on the build machine's glibc version and will not
# run on older systems. The output does NOT run on Windows (build the .exe on
# Windows with packaging/build_windows.ps1).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
ONEFILE=0
SKIP_TESTS=0
for arg in "$@"; do
    case "$arg" in
        --onefile) ONEFILE=1 ;;
        --skip-tests) SKIP_TESTS=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "Python 3.10+ required" >&2; exit 1; }
"$PY" -m venv .build-venv
# shellcheck disable=SC1091
. .build-venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements-build.txt

if [[ "$SKIP_TESTS" == 0 ]]; then
    PYTHONPATH=src python -m pytest -q
fi

rm -rf build/linux dist/linux
PSA_ONEFILE="$ONEFILE" pyinstaller --noconfirm --clean --distpath dist/linux --workpath build/linux packaging/psa.spec

if [[ "$ONEFILE" == 1 ]]; then
    BIN="dist/linux/PortableSecurityAudit"
else
    BIN="dist/linux/PortableSecurityAudit/PortableSecurityAudit"
fi

# Smoke test: version and a demo assessment (demo mode runs no commands).
"$BIN" --version
SMOKE="$(mktemp -d)"
"$BIN" audit --demo --operator "Build smoke test" --reference "BUILD" --confirm "I AM AUTHORIZED" \
    --output "$SMOKE" >/dev/null
"$BIN" verify-report "$(ls -d "$SMOKE"/PSA-*)" >/dev/null
rm -rf "$SMOKE"

echo "Built: $BIN"
sha256sum "$BIN"
echo "Next: python scripts/prepare_usb.py <USB>/PortableSecurityAudit --linux-build dist/linux/PortableSecurityAudit"

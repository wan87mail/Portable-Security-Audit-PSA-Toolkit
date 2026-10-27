#!/usr/bin/env python3
"""Generate docs/CHECKS.md from the registered modules (run after adding checks).

Usage:  python scripts/gen_checks_doc.py           # writes docs/CHECKS.md
        python scripts/gen_checks_doc.py --check   # exit 1 if the file is out of date (used in tests)
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from psatoolkit import __version__  # noqa: E402
from psatoolkit.modules import load_modules  # noqa: E402

OUT = REPO / "docs" / "CHECKS.md"


def render() -> str:
    lines = [
        "# Check catalogue",
        "",
        f"Generated from the code by `scripts/gen_checks_doc.py` (toolkit {__version__}). Do not edit by hand.",
        "",
        "All checks are read-only. **Admin** means the check is skipped without Administrator/root and the "
        "reason is listed in the report's limitations. Checks marked *partial* run without elevation but "
        "record reduced coverage.",
        "",
    ]
    for module in load_modules():
        if module.category == "demo":
            continue
        lines += [f"## {module.name}", "", module.description, "",
                  "| ID | Check | OS | Admin | Needs | What it verifies |", "|---|---|---|---|---|---|"]
        for c in module.checks:
            admin = f"**Yes**: {c.admin_reason}" if c.requires_admin else "No"
            needs = ", ".join(f"`{t}`" for t in c.required_tools) or "-"
            os_ = ", ".join(sorted(c.supported_os & {"windows", "linux"})) or "all"
            lines.append(f"| {c.check_id} | {c.title} | {os_} | {admin} | {needs} | {c.description} |")
        lines.append("")
    lines += [
        "## Checks that use elevation when available (partial without it)",
        "",
        "| ID | Without elevation | With elevation |",
        "|---|---|---|",
        "| SYS-PORTS-001 | Ports listed; process names only for your own sockets | Process names for all sockets |",
        "| WIN-SMB-001 | Registry values (SMBv1 may be *inconclusive*) | `Get-SmbServerConfiguration` |",
        "| LNX-SSH-001 | Parses sshd_config files (root-only includes are skipped) | `sshd -T` effective config |",
        "| LNX-FW-001 | Service state and ufw.conf (*potential*) | Full ufw/nftables/iptables rule sets |",
        "| LNX-PERM-001, LNX-SUID-001 | Directories readable by the user | Complete sweep |",
        "| LNX-MAC-001 | AppArmor enabled flag | Profile enforce/complain counts |",
        "| LNX-TLS-001 | Readable certificate directories | Includes /etc/letsencrypt |",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("docs/CHECKS.md is out of date; run scripts/gen_checks_doc.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

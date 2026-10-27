"""Documentation stays consistent with the code (Phase 10).

Broken links, a changelog that lags the version, or operator-facing text that still
promises "Phase N" features would mislead the people running assessments.
"""

import re

import pytest

from conftest import REPO_ROOT
from psatoolkit import __version__

DOCS = sorted([*REPO_ROOT.glob("*.md"), *(REPO_ROOT / "docs").glob("*.md"), REPO_ROOT / "baselines" / "README.md"])
OPERATOR_DOCS = ["README.md", "SECURITY.md", "docs/USER_GUIDE.md", "docs/RELEASE_CHECKLIST.md", "docs/BUILD.md"]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
FENCE = re.compile(r"^```.*?^```", re.S | re.M)


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower case, punctuation removed, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(path):
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    return {_slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.+?)\s*#*$", text, re.M)}


def _links(path):
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    text = re.sub(r"`[^`\n]*`", "", text)                 # inline code is not a link
    return [m.group(1) for m in LINK.finditer(text)]


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_relative_links_and_anchors_resolve(doc):
    broken = []
    for target in _links(doc):
        if re.match(r"(https?|mailto):", target):
            continue
        file_part, _, anchor = target.partition("#")
        dest = (doc.parent / file_part).resolve() if file_part else doc
        if not dest.exists():
            broken.append(f"{target}: no such file")
        elif anchor and dest.suffix == ".md" and anchor not in _anchors(dest):
            broken.append(f"{target}: no heading '#{anchor}'")
    assert not broken, broken


def test_changelog_has_an_entry_for_this_version():
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    versions = re.findall(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", changelog, re.M)
    assert versions and versions[0] == __version__, f"newest changelog entry {versions[:1]} != {__version__}"


def test_checks_catalogue_names_this_version():
    assert f"(toolkit {__version__})" in (REPO_ROOT / "docs" / "CHECKS.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("rel", OPERATOR_DOCS)
def test_operator_docs_make_no_stale_promises(rel):
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    stale = re.findall(r"(?i:(?:arrives|delivered|expanded|coming|added) in phase \d+|wait for the)|⏳|\|\s*Planned\s*\|",
                       text)
    assert not stale, stale


def test_user_facing_code_does_not_promise_future_phases():
    paths = [REPO_ROOT / "src" / "psatoolkit" / "gui" / "app.py", REPO_ROOT / "src" / "psatoolkit" / "cli.py",
             REPO_ROOT / "config" / "default.toml", REPO_ROOT / "scripts" / "PortableSecurityAudit.bat",
             REPO_ROOT / "scripts" / "PortableSecurityAudit.sh"]
    for path in paths:
        assert not re.search(r"(?i)\bphase \d+\b", path.read_text(encoding="utf-8")), path.name


def test_example_report_verifies_and_uses_the_current_format():
    import json

    from psatoolkit.reporting import verify_report_folder
    from psatoolkit.reporting.json_report import REPORT_FORMAT_VERSION
    folder = REPO_ROOT / "docs" / "examples" / "demo-report"
    assert verify_report_folder(folder).ok
    doc = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    assert doc["assessment"]["mode"] == "demo"
    assert doc["report_format_version"] == REPORT_FORMAT_VERSION

"""Report generation: JSON (canonical), HTML, PDF and CSV, plus integrity files.

``report.json`` is written first; the other formats are rendered from that
same document. ``SHA256SUMS`` lists every file in the report folder in
``sha256sum -c`` format.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from psatoolkit.core.models import AssessmentResult
from psatoolkit.reporting.csv_report import write_csv_report
from psatoolkit.reporting.html_report import write_html_report
from psatoolkit.reporting.json_report import build_document, verify_json_report, write_document
from psatoolkit.reporting.pdf_report import write_pdf_report

SUMS_FILE = "SHA256SUMS"
RENDERERS: dict[str, Callable[[dict[str, Any], Path], Path]] = {
    "html": write_html_report, "pdf": write_pdf_report, "csv": write_csv_report,
}


@dataclass
class ReportOutput:
    folder: Path
    files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def primary(self) -> Path | None:
        """The file to open for a person: HTML if present, otherwise JSON."""
        for name in ("report.html", "report.json"):
            p = self.folder / name
            if p in self.files:
                return p
        return self.files[0] if self.files else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_sums(folder: Path) -> Path:
    names = sorted(p.name for p in folder.iterdir() if p.is_file() and p.name != SUMS_FILE)
    path = folder / SUMS_FILE
    # newline="\n": LF on every OS so `sha256sum -c` works on files prepared under Windows.
    path.write_text("".join(f"{_sha256(folder / n)}  {n}\n" for n in names), encoding="utf-8", newline="\n")
    return path


def render_formats(doc: dict[str, Any], folder: Path, formats: list[str], out: ReportOutput) -> None:
    for fmt in formats:
        if fmt == "json":
            continue
        renderer = RENDERERS.get(fmt)
        if renderer is None:
            out.errors.append(f"Unknown report format '{fmt}'.")
            continue
        try:
            out.files.append(renderer(doc, folder))
        except Exception as exc:  # noqa: BLE001 - one failed format must not lose the others
            out.errors.append(f"{fmt.upper()} report failed: {type(exc).__name__}: {exc}")


def write_reports(result: AssessmentResult, folder: Path, formats: list[str],
                  include_raw_evidence: bool = True) -> ReportOutput:
    out = ReportOutput(folder)
    doc = build_document(result, include_raw_evidence)
    out.files.append(write_document(doc, folder))       # JSON is always written
    render_formats(doc, folder, formats, out)
    out.files.append(write_sums(folder))
    return out


def regenerate(report_json: Path, formats: list[str], dest: Path) -> ReportOutput:
    """Re-render formats from a *verified* report.json into ``dest`` (for Export Report)."""
    check = verify_json_report(report_json)
    if not check.canonical_ok:
        raise ValueError(f"{report_json} failed integrity verification ({check.message}); refusing to export it.")
    doc = json.loads(report_json.read_text(encoding="utf-8"))
    dest.mkdir(parents=True, exist_ok=True)
    out = ReportOutput(dest)
    if dest.resolve() != report_json.parent.resolve():
        target = dest / "report.json"
        target.write_bytes(report_json.read_bytes())
        out.files.append(target)
    render_formats(doc, dest, formats, out)
    out.files.append(write_sums(dest))
    return out


@dataclass
class FolderVerification:
    ok: bool
    lines: list[str]


def verify_report_folder(folder: Path) -> FolderVerification:
    lines: list[str] = []
    ok = True
    report = folder / "report.json"
    if report.is_file():
        v = verify_json_report(report)
        lines.append(f"report.json: {v.message}")
        ok &= v.ok
    else:
        lines.append("report.json: missing")
        ok = False
    sums = folder / SUMS_FILE
    if not sums.is_file():
        lines.append(f"{SUMS_FILE}: missing (only report.json could be verified)")
        return FolderVerification(ok, lines)
    listed = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if name and "/" not in name and "\\" not in name:
            listed[name] = digest.strip().lower()
    for name, digest in sorted(listed.items()):
        p = folder / name
        if not p.is_file():
            lines.append(f"{name}: MISSING")
            ok = False
        elif _sha256(p) != digest:
            lines.append(f"{name}: MODIFIED (hash mismatch)")
            ok = False
        else:
            lines.append(f"{name}: OK")
    extra = sorted(p.name for p in folder.iterdir() if p.is_file() and p.name not in listed and p.name != SUMS_FILE)
    for name in extra:
        lines.append(f"{name}: not listed in {SUMS_FILE} (added after the report was generated)")
    return FolderVerification(ok, lines)


__all__ = ["write_reports", "regenerate", "verify_report_folder", "verify_json_report", "ReportOutput"]

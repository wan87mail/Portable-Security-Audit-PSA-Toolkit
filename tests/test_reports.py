"""Phase 6: HTML, PDF and CSV reports, integrity files and export."""

import csv
import io
import json
import re
import shutil
import subprocess
import sys
import zlib

import pytest

from conftest import LINUX_OS
from psatoolkit import cli
from psatoolkit.core.engine import AssessmentEngine, Check, Module, build_host_info
from psatoolkit.core.logging_setup import AuditLog
from psatoolkit.core.models import Confidence, Evidence, FindingStatus, Reference, ReferenceKind, Severity
from psatoolkit.core.safe_exec import CommandRunner
from psatoolkit.core.session import DEMO_OS
from psatoolkit.modules import demo
from psatoolkit.reporting import RENDERERS, regenerate, verify_report_folder, write_reports
from psatoolkit.reporting import csv_report, html_report, pdf_report, pdfgen
from psatoolkit.reporting.json_report import build_document, report_folder
from psatoolkit.reporting.view import ReportView

HOSTILE_TITLE = "<script>alert('x')</script> (paren) back\\slash – “quotes” … ✓"
FORMULA = "=HYPERLINK(\"http://evil.example\",\"click\")"


class HostileCheck(Check):
    check_id, title, supported_os = "HOST-1", "hostile", frozenset({"linux"})

    def run(self, ctx):
        return [ctx.finding(
            self, title=HOSTILE_TITLE, severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
            component=FORMULA, description="-2+3 starts like a formula\nsecond line", impact="@SUM(A1)",
            confidence=Confidence.HIGH, remediation="Fix <b>it</b>", verification="+cmd",
            severity_rationale="because", evidence=[Evidence("weird", "unit", {"html": "<img src=x onerror=alert(1)>"})],
            references=[Reference(ReferenceKind.URL, "javascript:alert(1)", "bad"),
                        Reference(ReferenceKind.URL, "https://example.com/advisory", "good"),
                        Reference(ReferenceKind.CVE, "CVE-2099-0001", "NVD", 9.8, "3.1")])]


def make_result(config, authorization, demo_mode=False):
    if demo_mode:
        engine = AssessmentEngine([demo.build_module()], config)
        return engine.run(authorization=authorization, selected=["demo"], host=build_host_info(DEMO_OS, "demo", False),
                          os_info=DEMO_OS, runner=CommandRunner(demo=True), audit=AuditLog(None), demo=True)
    engine = AssessmentEngine([Module("m", "M", "", "local", [HostileCheck()])], config)
    return engine.run(authorization=authorization, selected=["m"], host=build_host_info(LINUX_OS, "srv01", True),
                      os_info=LINUX_OS, runner=CommandRunner(), audit=AuditLog(None))


@pytest.fixture
def hostile_doc(config, authorization):
    return build_document(make_result(config, authorization))


@pytest.fixture
def demo_folder(tmp_path, config, authorization):
    result = make_result(config, authorization, demo_mode=True)
    folder = report_folder(tmp_path, result)
    out = write_reports(result, folder, ["json", "html", "pdf", "csv"])
    assert not out.errors
    return folder


# -- integrity files -----------------------------------------------------------------------------------

def test_all_formats_and_sums(demo_folder):
    names = sorted(p.name for p in demo_folder.iterdir())
    assert names == ["SHA256SUMS", "findings.csv", "report.html", "report.json", "report.json.sha256", "report.pdf"]
    res = verify_report_folder(demo_folder)
    assert res.ok, res.lines
    if shutil.which("sha256sum"):
        assert subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=demo_folder).returncode == 0


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permissions")
def test_report_folder_is_owner_only(demo_folder):
    assert demo_folder.stat().st_mode & 0o077 == 0


def test_verification_refuses_oversized_or_special_files(demo_folder, monkeypatch):
    from psatoolkit.reporting import json_report
    monkeypatch.setattr(json_report, "MAX_REPORT_BYTES", 100)
    result = json_report.verify_json_report(demo_folder / "report.json")
    assert not result.ok and "larger than 100 bytes" in result.message


def test_integrity_files_use_lf_line_endings(demo_folder):
    for name in ("SHA256SUMS", "report.json.sha256"):
        assert b"\r" not in (demo_folder / name).read_bytes(), name


def test_folder_verification_detects_tampering(demo_folder):
    (demo_folder / "report.html").write_text("<p>edited</p>")
    (demo_folder / "report.pdf").unlink()
    (demo_folder / "notes.txt").write_text("added later")
    res = verify_report_folder(demo_folder)
    text = "\n".join(res.lines)
    assert not res.ok and "report.html: MODIFIED" in text and "report.pdf: MISSING" in text
    assert "notes.txt: not listed" in text


def test_failed_format_does_not_block_others(tmp_path, config, authorization, monkeypatch):
    def boom(doc, folder):
        raise RuntimeError("renderer exploded")
    monkeypatch.setitem(RENDERERS, "pdf", boom)
    result = make_result(config, authorization, demo_mode=True)
    out = write_reports(result, report_folder(tmp_path, result), ["json", "html", "pdf", "csv"])
    assert out.errors == ["PDF report failed: RuntimeError: renderer exploded"]
    assert {p.name for p in out.files} == {"report.json", "report.html", "findings.csv", "SHA256SUMS"}
    assert out.primary().name == "report.html"


def test_regenerate_refuses_tampered_json(demo_folder, tmp_path):
    out = regenerate(demo_folder / "report.json", ["html", "csv"], tmp_path / "export")
    assert {p.name for p in out.files} == {"report.json", "report.html", "findings.csv", "SHA256SUMS"}
    assert verify_report_folder(tmp_path / "export").ok
    doc = json.loads((demo_folder / "report.json").read_text())
    doc["findings"][0]["severity"] = "low"
    (demo_folder / "report.json").write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="failed integrity"):
        regenerate(demo_folder / "report.json", ["html"], tmp_path / "export2")


# -- HTML ---------------------------------------------------------------------------------------------------

def test_html_is_escaped_and_self_contained(hostile_doc):
    html = html_report.render(hostile_doc)
    assert "<script" not in html and "onerror=alert" not in html.replace("onerror=alert(1)&gt;", "")
    assert "&lt;script&gt;" in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert 'href="javascript:' not in html                       # only https:// links become anchors
    assert '<a href="https://example.com/advisory" rel="noreferrer noopener">' in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert not re.search(r"""(src|href)=["']https?://(?!example\.com/advisory)""", html)   # no external resources
    assert not re.search(r"@import|url\(", html)


def test_html_contains_required_sections(demo_folder):
    html = (demo_folder / "report.html").read_text()
    for section in ("Executive summary", "Most important risks", "Key recommendations", "Target system",
                    "Assessment scope and authorization", "Remediation roadmap", "Immediate action",
                    "Short-term action", "Planned improvements", "Ongoing monitoring", "Technical findings",
                    "Checks performed", "Limitations", "Report integrity", "DEMONSTRATION REPORT",
                    "SHA-256 of canonical report contents", "Why this severity", "How to verify the fix"):
        assert section in html, section
    doc = json.loads((demo_folder / "report.json").read_text())
    assert doc["integrity"]["canonical_sha256"] in html
    for f in doc["findings"]:
        assert f'id="{f["finding_id"]}"' in html


# -- CSV ----------------------------------------------------------------------------------------------------

def test_csv_neutralises_formulas_and_round_trips(hostile_doc):
    text = csv_report.render(hostile_doc)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 1 and list(rows[0]) == csv_report.COLUMNS
    r = rows[0]
    assert r["affected_component"] == "'" + FORMULA
    assert r["description"].startswith("'-2+3") and "\nsecond line" in r["description"]
    assert r["impact"] == "'@SUM(A1)" and r["verification"] == "'+cmd"
    assert r["remediation_state"] == "open" and r["owner"] == ""
    assert "CVE-2099-0001 (CVSS v3.1 9.8, NVD)" in r["references"]
    for value in r.values():
        assert not value.startswith(("=", "+", "-", "@", "\t", "\r"))


def test_csv_file_has_bom(demo_folder):
    raw = (demo_folder / "findings.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf") and b"\r\n" in raw


# -- PDF ----------------------------------------------------------------------------------------------------

def _objects(pdf: bytes) -> dict[int, int]:
    return {int(m.group(1)): m.start() for m in re.finditer(rb"(\d+) 0 obj\n", pdf)}


def test_pdf_structure_xref_is_exact(demo_folder):
    pdf = (demo_folder / "report.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    start = int(re.search(rb"startxref\n(\d+)", pdf).group(1))
    assert pdf[start:start + 4] == b"xref"
    xref = pdf[start:].split(b"trailer")[0].split(b"\n")
    count = int(xref[1].split()[1])
    offsets = [int(line.split()[0]) for line in xref[3:3 + count - 1]]
    objs = _objects(pdf)
    assert [objs[i] for i in range(1, count)] == offsets


def test_pdf_text_escaping_and_encoding():
    assert pdfgen.pdf_string("a(b)c\\d") == "(a\\(b\\)c\\\\d)"
    assert pdfgen.pdf_string("–") == "(\\226)"              # en dash -> WinAnsi 0x96
    assert pdfgen.pdf_string("✓") == "(?)"                  # outside cp1252 -> '?'
    assert pdfgen.text_width("iiii", "F1", 10) < pdfgen.text_width("MMMM", "F1", 10)
    assert pdfgen.text_width("abc", "F3", 10) == 18.0       # Courier is monospaced (600/1000 em)


def test_pdf_wrap_respects_width():
    text = "word " * 80 + "x" * 300
    lines = pdfgen.wrap(text, "F1", 10, 200)
    assert len(lines) > 5 and all(pdfgen.text_width(l, "F1", 10) <= 200 for l in lines)
    assert pdfgen.wrap("a\n\nb", "F1", 10, 100) == ["a", "", "b"]


def test_pdf_hostile_content_renders(hostile_doc, tmp_path):
    data = pdf_report.render(hostile_doc)
    streams = [zlib.decompress(m.group(1)) for m in re.finditer(rb"stream\n(.*?)\nendstream", data, re.S)]
    joined = b"".join(streams)
    assert b"\\(paren\\)" in joined and b"back\\\\slash" in joined
    if shutil.which("pdftotext"):
        path = tmp_path / "h.pdf"
        path.write_bytes(data)
        text = subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True).stdout
        assert "<script>alert('x')</script> (paren) back\\slash" in text
        assert "Report integrity" in text and hostile_doc["integrity"]["canonical_sha256"] in text


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="poppler not installed")
def test_pdf_has_all_sections_and_page_numbers(demo_folder):
    text = subprocess.run(["pdftotext", str(demo_folder / "report.pdf"), "-"], capture_output=True, text=True).stdout
    for section in ("Executive summary", "Remediation roadmap", "Technical findings", "Checks performed",
                    "Limitations", "Report integrity", "DEMONSTRATION REPORT", "SMBv1 server protocol is enabled"):
        assert section in text, section
    pages = int(re.search(r"Page 1 of (\d+)", text).group(1))
    assert f"Page {pages} of {pages}" in text


# -- view -----------------------------------------------------------------------------------------------------

def test_view_recommendations_and_roadmap(demo_folder):
    v = ReportView(json.loads((demo_folder / "report.json").read_text()))
    recs = v.key_recommendations()
    assert recs[0]["priority"] == "immediate" and len({r["text"] for r in recs}) == len(recs)
    groups = v.by_priority()
    assert sum(len(x) for x in groups.values()) == len(v.findings)
    assert [f["risk_score"] for f in v.top_risks()] == sorted([f["risk_score"] for f in v.top_risks()], reverse=True)
    assert v.counts["high"] == 3 and v.counts["critical"] == 1 and v.is_demo


# -- CLI ------------------------------------------------------------------------------------------------------

AUTH = ["--operator", "Test Operator", "--reference", "CHG-1", "--confirm", "I AM AUTHORIZED"]


def test_cli_writes_all_formats_and_exports(portable_root, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    run = lambda *a: cli.main(["--root", str(portable_root), *a])  # noqa: E731
    assert run("audit", "--demo", *AUTH) == cli.EXIT_OK
    folder = next((portable_root / "reports").glob("PSA-*"))
    assert (folder / "report.pdf").exists() and (folder / "findings.csv").exists()
    assert run("verify-report", str(folder)) == cli.EXIT_OK
    assert run("export-report", str(folder), str(tmp_path / "share"), "--formats", "pdf") == cli.EXIT_OK
    assert {p.name for p in (tmp_path / "share").iterdir()} == {"report.json", "report.pdf", "SHA256SUMS"}
    assert run("export-report", str(folder), str(tmp_path / "x"), "--formats", "docx") == cli.EXIT_USAGE
    (folder / "findings.csv").write_text("tampered")
    assert run("verify-report", str(folder)) == cli.EXIT_INTEGRITY


def test_demo_covers_every_severity_status_and_data_source(demo_folder):
    doc = json.loads((demo_folder / "report.json").read_text())
    assert {f["severity"] for f in doc["findings"]} == {"critical", "high", "medium", "low", "informational"}
    assert {f["status"] for f in doc["findings"]} == {"confirmed", "potential", "informational", "inconclusive"}
    assert {s["type"] for s in doc["assessment"]["data_sources"]} == {"vulnerability_data", "baseline"}
    assert {c["status"] for c in doc["checks"]} >= {"findings", "error", "skipped"}
    html = (demo_folder / "report.html").read_text()
    assert "Baseline &#x27;Example Ubuntu Server Baseline&#x27; v1.0" in html and "Vulnerability data snapshot" in html

"""JSON report writer and report integrity verification.

Two integrity values are recorded:

* ``integrity.canonical_sha256`` (inside the report): SHA-256 of the report
  body serialised canonically (sorted keys, no whitespace, UTF-8) with the
  ``integrity`` block removed. It survives re-formatting of the JSON.
* ``report.json.sha256`` (beside the report): SHA-256 of the exact file bytes,
  in ``sha256sum`` format so it can be checked with standard tools.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from psatoolkit import TOOL_NAME, __version__
from psatoolkit.core.models import AssessmentResult, to_jsonable
from psatoolkit.core.paths import read_limited
from psatoolkit.core.redaction import redact
from psatoolkit.core.validation import safe_filename

REPORT_FORMAT_VERSION = "1.0"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_digest(document: dict[str, Any]) -> str:
    body = {k: v for k, v in document.items() if k != "integrity"}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def build_document(result: AssessmentResult, include_raw_evidence: bool = True) -> dict[str, Any]:
    assessment = to_jsonable(result)
    findings = assessment.pop("checks")
    flat_findings = [f for c in findings for f in c.pop("findings")]
    flat_findings.sort(key=lambda f: ("critical", "high", "medium", "low", "informational").index(f["severity"]))
    if not include_raw_evidence:
        for f in flat_findings:
            for ev in f["evidence"]:
                ev["data"] = None
    doc: dict[str, Any] = {
        "report_format_version": REPORT_FORMAT_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "assessment": assessment,
        "checks": findings,
        "findings": flat_findings,
    }
    doc = redact(doc)
    doc["integrity"] = {"algorithm": "sha256", "canonical_sha256": canonical_digest(doc)}
    return doc


MAX_REPORT_BYTES = 200_000_000   # verification reads report folders handed over by others


def report_folder(output_dir: Path, result: AssessmentResult) -> Path:
    folder = output_dir / f"{result.assessment_id}_{safe_filename(result.host.hostname)}"
    # Owner-only on POSIX: a report lists the host's weaknesses (no effect on FAT/exFAT USB drives).
    folder.parent.mkdir(parents=True, exist_ok=True)
    folder.mkdir(mode=0o700, exist_ok=False)
    return folder


def write_json_report(result: AssessmentResult, folder: Path, include_raw_evidence: bool = True) -> Path:
    return write_document(build_document(result, include_raw_evidence), folder)


def write_document(doc: dict[str, Any], folder: Path) -> Path:
    path = folder / "report.json"
    data = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    path.write_bytes(data)
    (folder / "report.json.sha256").write_text(f"{hashlib.sha256(data).hexdigest()}  report.json\n",
                                               encoding="utf-8", newline="\n")
    return path


@dataclass
class ReportVerification:
    path: Path
    canonical_ok: bool
    file_hash_ok: bool | None      # None when no sidecar file exists
    message: str

    @property
    def ok(self) -> bool:
        return self.canonical_ok and self.file_hash_ok is not False


def verify_json_report(path: Path) -> ReportVerification:
    try:
        raw = read_limited(path, MAX_REPORT_BYTES)
        doc = json.loads(raw.decode("utf-8"))
        recorded = doc["integrity"]["canonical_sha256"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return ReportVerification(path, False, None, f"Cannot read report integrity data: {exc}")
    canonical_ok = canonical_digest(doc) == recorded

    sidecar = path.with_name(path.name + ".sha256")
    file_ok: bool | None = None
    if sidecar.is_file():
        try:
            expected = (read_limited(sidecar, 4096).decode("utf-8", "replace").split() or [""])[0].lower()
        except OSError:
            expected = ""
        file_ok = hashlib.sha256(raw).hexdigest() == expected
    parts = ["content hash " + ("OK" if canonical_ok else "MISMATCH")]
    if file_ok is not None:
        parts.append("file hash " + ("OK" if file_ok else "MISMATCH"))
    else:
        parts.append("no .sha256 sidecar")
    return ReportVerification(path, canonical_ok, file_ok, "; ".join(parts))

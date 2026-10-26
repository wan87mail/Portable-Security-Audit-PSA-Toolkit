"""Tool and dependency integrity verification (SHA-256 manifest).

``checksums/manifest.json`` lists the SHA-256 of every shipped file. Before
each engagement the operator verifies the drive against it. Because an
attacker who can modify files could also rewrite the manifest, the release
notes publish the manifest's own SHA-256 (``manifest_digest``); compare it
out-of-band (e.g. against the value in your change ticket).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_NAME = "manifest.json"

# Directories that legitimately change on the drive and are not verified.
EXCLUDED_DIRS = {"reports", "logs", "checksums", ".git", "__pycache__", ".pytest_cache",
                 ".venv", "venv", "build", "dist", ".mypy_cache", ".ruff_cache", "node_modules"}
EXCLUDED_FILES = {"local.toml", ".gitkeep"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def iter_files(root: Path) -> list[Path]:
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in rel.parts[:-1]):
            continue
        if rel.parts and rel.parts[0] in EXCLUDED_DIRS:
            continue
        if p.is_file() and not p.is_symlink() and p.name not in EXCLUDED_FILES \
                and p.suffix not in EXCLUDED_SUFFIXES:
            out.append(p)
    return out


def build_manifest(root: Path, tool_version: str) -> dict:
    files = {p.relative_to(root).as_posix(): sha256_file(p) for p in iter_files(root)}
    return {
        "tool_version": tool_version,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "algorithm": "sha256",
        "files": files,
    }


def write_manifest(root: Path, tool_version: str) -> tuple[Path, str]:
    manifest = build_manifest(root, tool_version)
    out_dir = root / "checksums"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, sha256_file(path)


@dataclass
class IntegrityReport:
    manifest_path: Path
    manifest_found: bool = False
    manifest_digest: str = ""
    manifest_version: str = ""
    verified: int = 0
    missing: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.manifest_found and not self.error and not self.missing and not self.modified

    def summary(self) -> str:
        if not self.manifest_found:
            return f"No integrity manifest found at {self.manifest_path}. {self.error}".strip()
        if self.error:
            return f"Integrity check failed: {self.error}"
        state = "PASSED" if self.ok else "FAILED"
        lines = [
            f"Integrity check {state}: {self.verified} file(s) verified "
            f"(manifest for version {self.manifest_version}).",
            f"Manifest SHA-256: {self.manifest_digest}  <- compare with the release notes",
        ]
        if self.modified:
            lines.append("MODIFIED: " + ", ".join(self.modified))
        if self.missing:
            lines.append("MISSING: " + ", ".join(self.missing))
        if self.unexpected:
            lines.append("Unexpected files not in manifest (review): " + ", ".join(self.unexpected))
        return "\n".join(lines)


def verify_manifest(root: Path) -> IntegrityReport:
    path = root / "checksums" / MANIFEST_NAME
    report = IntegrityReport(manifest_path=path)
    if not path.is_file():
        report.error = "Run 'scripts/build_manifest.py' when preparing the drive."
        return report
    report.manifest_found = True
    report.manifest_digest = sha256_file(path)
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        files: dict[str, str] = manifest["files"]
        report.manifest_version = str(manifest.get("tool_version", "?"))
        if manifest.get("algorithm") != "sha256":
            raise ValueError("unsupported algorithm")
    except (ValueError, KeyError, TypeError) as exc:
        report.error = f"manifest is malformed: {exc}"
        return report

    for rel, expected in sorted(files.items()):
        target = (root / rel)
        try:
            target.resolve().relative_to(root.resolve())
        except ValueError:
            report.modified.append(f"{rel} (path escapes root)")
            continue
        if not target.is_file():
            report.missing.append(rel)
        elif sha256_file(target) != expected:
            report.modified.append(rel)
        else:
            report.verified += 1
    present = {p.relative_to(root).as_posix() for p in iter_files(root)}
    report.unexpected = sorted(present - set(files))
    return report

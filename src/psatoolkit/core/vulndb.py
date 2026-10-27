"""Offline vulnerability data ("psa-vulndata-1" snapshots).

A snapshot is a directory (normally ``<USB>/vulndata``) containing:

* ``manifest.json``: format, snapshot date, sources and the SHA-256 of
  every data file;
* one or more ``*.jsonl`` files with one advisory record per line.

Record fields::

    {"id": "CVE-2024-0001", "aliases": [...], "ecosystem": "ubuntu:24.04",
     "package": "openssl", "match": "exact" | "prefix",
     "ranges": [{"introduced": "0", "fixed": "3.0.13-0ubuntu3.5"}],
     "versions": [...],                       # optional explicit affected versions
     "severity": "medium",                    # vendor rating, optional
     "cvss": [{"version": "3.1", "vector": "CVSS:3.1/...", "score": 7.5, "source": "NVD"}],
     "summary": "...", "published": "2024-01-31", "references": ["https://..."]}

Snapshots are produced on a connected admin workstation (see
``scripts/vulndata_from_osv.py``) and copied to the drive; the toolkit itself
never downloads anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from psatoolkit.core.cvss import CvssError, score_vector
from psatoolkit.core.osdetect import OSInfo
from psatoolkit.core.versions import COMPARATORS

FORMAT = "psa-vulndata-1"
DISTRO_FAMILIES = {"ubuntu": "dpkg", "debian": "dpkg", "rhel": "rpm", "almalinux": "rpm", "rocky": "rpm",
                   "centos": "rpm", "fedora": "rpm"}
MAX_RECORD_BYTES = 200_000


class VulnDataError(Exception):
    pass


@dataclass
class Advisory:
    id: str
    ecosystem: str
    package: str
    ranges: list[dict[str, str]]
    versions: list[str] = field(default_factory=list)
    match: str = "exact"
    aliases: list[str] = field(default_factory=list)
    severity: str = ""
    cvss: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    published: str = ""
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Advisory":
        if not all(isinstance(d.get(k), str) and d[k] for k in ("id", "ecosystem", "package")):
            raise ValueError("record needs id, ecosystem and package")
        ranges = [r for r in d.get("ranges") or [] if isinstance(r, dict)]
        versions = [v for v in d.get("versions") or [] if isinstance(v, str)]
        if not ranges and not versions:
            raise ValueError("record needs ranges or versions")
        cvss = []
        for c in d.get("cvss") or []:
            if isinstance(c, dict) and isinstance(c.get("vector"), str):
                try:
                    computed = score_vector(c["vector"], c.get("score") if isinstance(c.get("score"), (int, float))
                                            else None)
                except CvssError:
                    continue
                cvss.append({"version": computed.version, "vector": c["vector"], "score": computed.score,
                             "source": str(c.get("source") or "unspecified")})
        return cls(id=d["id"], ecosystem=d["ecosystem"].lower(), package=d["package"], ranges=ranges,
                   versions=versions, match=d.get("match", "exact"),
                   aliases=[a for a in d.get("aliases") or [] if isinstance(a, str)],
                   severity=str(d.get("severity") or "").lower(), cvss=cvss, summary=str(d.get("summary") or "")[:2000],
                   published=str(d.get("published") or ""),
                   references=[r for r in d.get("references") or [] if isinstance(r, str)][:10])

    @property
    def best_cvss(self) -> dict[str, Any] | None:
        scored = [c for c in self.cvss if c.get("score") is not None]
        if not scored:
            return None
        # Prefer the newest scored version, then the highest score.
        return max(scored, key=lambda c: (c["version"], c["score"]))

    @property
    def fixed_versions(self) -> list[str]:
        return [r["fixed"] for r in self.ranges if r.get("fixed")]


def is_affected(version: str, adv: Advisory, compare: Callable[[str, str], int]) -> bool:
    if version in adv.versions:
        return True
    for r in adv.ranges:
        introduced = r.get("introduced", "0")
        if introduced not in ("", "0") and compare(version, introduced) < 0:
            continue
        fixed, last = r.get("fixed"), r.get("last_affected")
        if fixed:
            if compare(version, fixed) < 0:
                return True
        elif last:
            if compare(version, last) <= 0:
                return True
        else:
            return True   # introduced with no fix yet
    return False


def ecosystem_for(os_info: OSInfo) -> tuple[str, str] | None:
    """Map the detected OS to (ecosystem key, version scheme), e.g. ('ubuntu:24.04', 'dpkg')."""
    if os_info.family == "windows":
        return "windows", "generic"
    if os_info.family != "linux":
        return None
    distro = os_info.distro_id
    scheme = DISTRO_FAMILIES.get(distro)
    if scheme is None:
        return None
    version = os_info.version
    if scheme == "rpm":
        version = version.split(".")[0]
    return f"{distro}:{version}", scheme


@dataclass
class Snapshot:
    path: Path
    manifest: dict[str, Any]
    snapshot_date: date | None
    record_count: int
    sources: list[dict[str, Any]]

    def age_days(self, today: date | None = None) -> int | None:
        if self.snapshot_date is None:
            return None
        return ((today or date.today()) - self.snapshot_date).days


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def open_snapshot(directory: Path) -> Snapshot:
    """Validate the manifest and the SHA-256 of every data file."""
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(str(manifest_path))
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VulnDataError(f"manifest.json is unreadable: {exc}") from None
    if manifest.get("format") != FORMAT:
        raise VulnDataError(f"unsupported vulnerability data format {manifest.get('format')!r}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise VulnDataError("manifest lists no data files")
    for name, digest in files.items():
        p = (directory / name)
        if "/" in name or "\\" in name or name.startswith(".") or not name.endswith(".jsonl"):
            raise VulnDataError(f"invalid data file name {name!r}")
        if not p.is_file():
            raise VulnDataError(f"data file {name} is missing")
        if _sha256(p) != digest:
            raise VulnDataError(f"data file {name} failed SHA-256 verification")
    try:
        snap_date = datetime.strptime(str(manifest.get("snapshot_date")), "%Y-%m-%d").date()
    except ValueError:
        snap_date = None
    return Snapshot(directory, manifest, snap_date, int(manifest.get("record_count") or 0),
                    [s for s in manifest.get("sources") or [] if isinstance(s, dict)])


def load_advisories(snapshot: Snapshot, ecosystem: str) -> tuple[dict[str, list[Advisory]], int]:
    """Load records for one ecosystem, indexed by lower-case package name. Returns (index, bad_records)."""
    index: dict[str, list[Advisory]] = {}
    bad = 0
    for name in snapshot.manifest["files"]:
        with (snapshot.path / name).open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                if len(line) > MAX_RECORD_BYTES:
                    bad += 1
                    continue
                if ecosystem not in line.lower():
                    continue   # cheap pre-filter; the parsed value is checked exactly below
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict) or str(raw.get("ecosystem", "")).lower() != ecosystem:
                        continue
                    adv = Advisory.from_dict(raw)
                except (ValueError, TypeError):
                    bad += 1
                    continue
                index.setdefault(adv.package.lower(), []).append(adv)
    return index, bad


@dataclass
class Match:
    package: str            # installed package name (binary)
    version: str
    matched_on: str         # the name that matched (binary or source package)
    advisory: Advisory


def match_packages(packages: Iterable[dict[str, str]], index: dict[str, list[Advisory]],
                   scheme: str) -> list[Match]:
    """Match installed packages against advisories.

    Each package dict has ``name``/``version`` and optionally ``source``/``source_version``
    (distribution advisories are usually keyed by source package).
    """
    compare = COMPARATORS[scheme]
    prefix_advs = [a for advs in index.values() for a in advs if a.match == "prefix"]
    matches: list[Match] = []
    seen: set[tuple[str, str]] = set()
    for pkg in packages:
        candidates = [(pkg.get("name", ""), pkg.get("version", ""))]
        if pkg.get("source"):
            candidates.append((pkg["source"], pkg.get("source_version") or pkg.get("version", "")))
        for name, version in candidates:
            if not name or not version:
                continue
            advs = [a for a in index.get(name.lower(), []) if a.match != "prefix"]
            advs += [a for a in prefix_advs if name.lower().startswith(a.package.lower())]
            for adv in advs:
                key = (pkg.get("name", ""), adv.id)
                if key in seen:
                    continue
                try:
                    affected = is_affected(version, adv, compare)
                except (ValueError, IndexError):
                    continue
                if affected:
                    seen.add(key)
                    matches.append(Match(pkg.get("name", ""), version, name, adv))
    return matches

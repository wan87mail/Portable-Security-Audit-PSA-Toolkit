#!/usr/bin/env python3
"""Build a PSA offline vulnerability snapshot from OSV data files.

Run this on a CONNECTED ADMIN WORKSTATION, never on an assessment target.
The script works offline on files you downloaded beforehand:

    # e.g. https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip
    python scripts/vulndata_from_osv.py --out build/vulndata  Ubuntu-all.zip Debian-all.zip

Inputs may be .zip archives, .json files or directories of .json files. Zip
members are read in memory and never extracted (no path traversal). Each
record is treated as untrusted data and validated before it is written.

Then copy the output directory to <USB>/vulndata and rebuild the drive's
integrity manifest (scripts/build_manifest.py). See docs/VULNDATA.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from psatoolkit.core.cvss import CvssError, score_vector  # noqa: E402
from psatoolkit.core.vulndb import FORMAT  # noqa: E402

MAX_MEMBER_BYTES = 5_000_000
OSV_SOURCE_URL = "https://osv.dev/"


def map_ecosystem(osv_ecosystem: str) -> str | None:
    """'Ubuntu:24.04:LTS' -> 'ubuntu:24.04'; 'Debian:12' -> 'debian:12'; 'Rocky Linux:9' -> 'rocky:9'."""
    parts = [p.strip() for p in (osv_ecosystem or "").split(":")]
    if len(parts) < 2:
        return None
    name = parts[0].lower()
    if name == "ubuntu":
        return f"ubuntu:{parts[1]}" if re.fullmatch(r"\d{2}\.\d{2}", parts[1]) else None
    if name == "debian":
        return f"debian:{parts[1]}" if parts[1].isdigit() else None
    mapping = {"almalinux": "almalinux", "rocky linux": "rocky"}
    if name in mapping and re.fullmatch(r"\d+", parts[1]):
        return f"{mapping[name]}:{parts[1]}"
    return None


def events_to_ranges(events: list[dict[str, str]]) -> list[dict[str, str]]:
    ranges, current = [], None
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            if current:
                ranges.append(current)
            current = {"introduced": str(ev["introduced"])}
        elif current is not None and ("fixed" in ev or "last_affected" in ev):
            key = "fixed" if "fixed" in ev else "last_affected"
            current[key] = str(ev[key])
            ranges.append(current)
            current = None
    if current:
        ranges.append(current)
    return ranges


def convert(entry: dict[str, Any], wanted: set[str] | None) -> Iterator[dict[str, Any]]:
    oid = entry.get("id")
    if not isinstance(oid, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{3,80}", oid):
        return
    aliases = [a for a in entry.get("aliases") or [] if isinstance(a, str) and re.fullmatch(r"[A-Za-z0-9._:-]{3,80}", a)]
    embedded = re.search(r"CVE-\d{4}-\d{4,}", oid)   # e.g. UBUNTU-CVE-2024-5535 has no aliases
    if embedded and embedded.group(0) != oid and embedded.group(0) not in aliases:
        aliases.append(embedded.group(0))
    cvss, vendor = [], ""
    for sev in entry.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        kind, score = sev.get("type"), sev.get("score")
        if kind in ("CVSS_V3", "CVSS_V4") and isinstance(score, str):
            try:
                computed = score_vector(score)
            except CvssError:
                continue
            cvss.append({"version": computed.version, "vector": score, "score": computed.score,
                         "source": f"OSV {oid} (base score computed from vector by PSA)"
                         if computed.score is not None else f"OSV {oid}"})
        elif isinstance(score, str) and score.lower() in ("critical", "high", "medium", "low", "negligible",
                                                           "important", "moderate"):
            vendor = score.lower()
    refs = [r.get("url") for r in entry.get("references") or [] if isinstance(r, dict)
            and isinstance(r.get("url"), str) and r["url"].startswith("https://")][:5]
    for aff in entry.get("affected") or []:
        if not isinstance(aff, dict) or not isinstance(aff.get("package"), dict):
            continue
        eco = map_ecosystem(str(aff["package"].get("ecosystem", "")))
        name = aff["package"].get("name")
        if eco is None or not isinstance(name, str) or (wanted and eco.split(":")[0] not in wanted):
            continue
        ranges = []
        for rng in aff.get("ranges") or []:
            if isinstance(rng, dict) and rng.get("type") == "ECOSYSTEM":
                ranges += events_to_ranges(rng.get("events") or [])
        versions = [v for v in aff.get("versions") or [] if isinstance(v, str)][:500]
        if not ranges and not versions:
            continue
        yield {"id": oid, "aliases": aliases, "ecosystem": eco, "package": name, "match": "exact",
               "ranges": ranges, "versions": versions, "severity": vendor, "cvss": cvss,
               "summary": str(entry.get("summary") or entry.get("details") or "")[:500],
               "published": str(entry.get("published") or "")[:10], "references": refs}


def read_inputs(paths: list[Path]) -> Iterator[tuple[str, bytes]]:
    for path in paths:
        if path.is_dir():
            for p in sorted(path.rglob("*.json")):
                if p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_MEMBER_BYTES:
                    yield str(p), p.read_bytes()
        elif path.suffix == ".zip":
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir() or not info.filename.endswith(".json") or info.file_size > MAX_MEMBER_BYTES:
                        continue
                    yield f"{path}!{info.filename}", zf.read(info)
        elif path.suffix == ".json":
            yield str(path), path.read_bytes()
        else:
            raise SystemExit(f"Unsupported input: {path}")


def build(inputs: list[Path], out: Path, wanted: set[str] | None, snapshot_date: str) -> dict[str, Any]:
    if out.exists() and any(out.iterdir()) and not (out / "manifest.json").exists():
        raise SystemExit(f"{out} is not empty and is not a vulndata snapshot; refusing to overwrite it.")
    out.mkdir(parents=True, exist_ok=True)
    tmp = out / "records.jsonl.tmp"
    count, bad, per_eco = 0, 0, Counter()
    with tmp.open("w", encoding="utf-8") as fh:
        for _name, data in read_inputs(inputs):
            try:
                entry = json.loads(data)
            except ValueError:
                bad += 1
                continue
            if not isinstance(entry, dict):
                bad += 1
                continue
            for rec in convert(entry, wanted):
                fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
                count += 1
                per_eco[rec["ecosystem"]] += 1
    final = out / "records.jsonl"
    tmp.replace(final)
    manifest = {
        "format": FORMAT,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "snapshot_date": snapshot_date,
        "record_count": count,
        "ecosystems": dict(sorted(per_eco.items())),
        "sources": [{"name": "OSV (Open Source Vulnerabilities) export", "url": OSV_SOURCE_URL,
                     "inputs": [p.name for p in inputs],
                     "license": "Licences vary by originating database; see https://google.github.io/osv.dev/"
                                "data/ before redistributing."}],
        "files": {"records.jsonl": hashlib.sha256(final.read_bytes()).hexdigest()},
        "skipped_invalid_entries": bad,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("inputs", nargs="+", type=Path, help="OSV .zip / .json files or directories")
    p.add_argument("--out", type=Path, required=True, help="output snapshot directory")
    p.add_argument("--distro", action="append", help="keep only these distributions (ubuntu, debian, rocky, almalinux)")
    p.add_argument("--snapshot-date", default=date.today().isoformat(),
                   help="date the source data was downloaded (YYYY-MM-DD; default today)")
    args = p.parse_args(argv)
    datetime.strptime(args.snapshot_date, "%Y-%m-%d")
    manifest = build(args.inputs, args.out, {d.lower() for d in args.distro} if args.distro else None,
                     args.snapshot_date)
    print(f"Wrote {manifest['record_count']} records to {args.out}")
    for eco, n in manifest["ecosystems"].items():
        print(f"  {eco}: {n}")
    if manifest["skipped_invalid_entries"]:
        print(f"Skipped {manifest['skipped_invalid_entries']} invalid input file(s).")
    print("Next: copy the directory to <USB>/vulndata and run scripts/build_manifest.py on the drive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Phase 5: CVSS, version comparison, vulnerability data, Module E, normalization and scoring."""

import json
import random
import shutil
import subprocess
import zipfile
from datetime import date

import pytest

from conftest import LINUX_OS, REPO_ROOT
from fakes import WINDOWS_OS, FakeRunner, make_ctx
from psatoolkit.core import cvss, versions
from psatoolkit.core.engine import SkipCheck
from psatoolkit.core.models import (AssessmentResult, CheckResult, CheckStatus, Confidence, Finding, FindingStatus,
                                    HostInfo, Reference, ReferenceKind, Severity, utcnow)
from psatoolkit.core.normalize import finalize, fingerprint, normalize_finding
from psatoolkit.core.scoring import IMMEDIATE, MONITORING, PLANNED, SHORT_TERM, remediation_priority, risk_score
from psatoolkit.core.vulndb import (Advisory, VulnDataError, ecosystem_for, is_affected, load_advisories,
                                    match_packages, open_snapshot)
from psatoolkit.modules.vuln_assessment import VulnerablePackagesCheck, advisory_severity, cve_ids

# -- CVSS ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 9.1),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss31_base_scores_match_published_values(vector, score):
    assert cvss.base_score_v3(vector) == score


@pytest.mark.parametrize("bad", ["", "AV:N/AC:L", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
                                 "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:2.0/AV:N"])
def test_cvss_rejects_bad_vectors(bad):
    with pytest.raises(cvss.CvssError):
        cvss.base_score_v3(bad)


def test_cvss_v4_kept_but_not_scored_and_bands():
    s = cvss.score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert s.version == "4.0" and s.score is None
    assert [cvss.severity_from_score(x) for x in (9.0, 7.0, 4.0, 0.1, 0.0, None)] == [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, None]
    assert cvss.roundup(4.000000001) == 4.0 and cvss.roundup(4.02) == 4.1


# -- version comparison -------------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0~rc1", 1), ("1:1.0", "2.0", 1), ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", -1),
    ("1.2.3", "1.2.3-1", -1), ("2.30-0ubuntu2", "2.30-0ubuntu2.1", -1), ("1.0a", "1.0", 1),
    ("1.0+dfsg", "1.0", 1), ("9.1.0016-1ubuntu7.3", "9.1.0016-1ubuntu7.10", -1), ("1.0", "1.0", 0),
    ("0:1.0", "1.0", 0), ("1.0~~", "1.0~", -1), ("3.0.11-1~deb12u1", "3.0.11-1~deb12u2", -1),
])
def test_dpkg_compare(a, b, expected):
    assert versions.dpkg_compare(a, b) == expected
    assert versions.dpkg_compare(b, a) == -expected


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg not installed")
def test_dpkg_compare_matches_real_dpkg_on_random_versions():
    rng = random.Random(1234)
    def rand():
        epoch = f"{rng.randint(0, 2)}:" if rng.random() < 0.2 else ""
        up = str(rng.randint(0, 9)) + "".join(rng.choice("0123456789.~+ab") for _ in range(rng.randint(0, 6)))
        rev = "-" + "".join(rng.choice("0123456789.~+ub") for _ in range(rng.randint(1, 5))) if rng.random() < 0.7 else ""
        return epoch + up + rev
    for _ in range(150):
        a, b = rand(), rand()
        ours = versions.dpkg_compare(a, b)
        real = 0 if subprocess.run(["dpkg", "--compare-versions", a, "eq", b]).returncode == 0 else (
            -1 if subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0 else 1)
        assert ours == real, (a, b, ours, real)


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0), ("1.0", "1.1", -1), ("1.10", "1.9", 1), ("1.0a", "1.0", 1), ("1.0~rc1", "1.0", -1),
    ("1.0^git1", "1.0", 1), ("1.0^git1", "1.0.1", -1), ("2a", "2.0", -1), ("1:3.0.7-25.el9", "3.0.8-1.el9", 1),
    ("3.0.7-25.el9", "3.0.7-27.el9", -1), ("5.14.0-427.el9_4", "5.14.0-427.el9_4", 0),
])
def test_rpm_compare(a, b, expected):
    assert versions.rpm_compare(a, b) == expected


@pytest.mark.parametrize("a,b,expected", [("1.2", "1.2.0", 0), ("1.2.10", "1.2.9", 1), ("23.01", "24.08", -1),
                                          ("10.0.19045.1", "10.0.19045", 1), ("1.0 beta", "1.0", 1)])
def test_generic_compare(a, b, expected):
    assert versions.generic_compare(a, b) == expected


# -- vulnerability data ----------------------------------------------------------------------------------

def adv(**over):
    base = {"id": "PSA-TEST-0001", "ecosystem": "ubuntu:24.04", "package": "examplelib",
            "ranges": [{"introduced": "0", "fixed": "1.2-1ubuntu0.2"}]}
    return Advisory.from_dict({**base, **over})


def test_is_affected_ranges():
    cmp = versions.dpkg_compare
    a = adv()
    assert is_affected("1.2-1ubuntu0.1", a, cmp) and not is_affected("1.2-1ubuntu0.2", a, cmp)
    b = adv(ranges=[{"introduced": "2.0", "fixed": "2.5"}, {"introduced": "3.0", "last_affected": "3.1"}])
    assert [is_affected(v, b, cmp) for v in ("1.9", "2.0", "2.4", "2.5", "3.1", "3.2")] == [
        False, True, True, False, True, False]
    c = adv(ranges=[{"introduced": "0"}])         # no fix yet
    assert is_affected("99", c, cmp) and c.fixed_versions == []
    d = adv(ranges=[], versions=["1.0-1"])
    assert is_affected("1.0-1", d, cmp) and not is_affected("1.0-2", d, cmp)


def test_advisory_validation_and_cvss():
    with pytest.raises(ValueError):
        Advisory.from_dict({"id": "X", "ecosystem": "ubuntu:24.04", "package": "p"})      # no ranges
    a = adv(cvss=[{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 1.0, "source": "S"},
                  {"vector": "garbage"}])
    assert a.cvss == [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8,
                       "source": "S"}]          # score recomputed from the vector, bad vector dropped


@pytest.mark.parametrize("distro,version,expected", [
    ("ubuntu", "24.04", ("ubuntu:24.04", "dpkg")), ("debian", "12", ("debian:12", "dpkg")),
    ("rocky", "9.4", ("rocky:9", "rpm")), ("alpine", "3.20", None)])
def test_ecosystem_for(distro, version, expected):
    import dataclasses
    assert ecosystem_for(dataclasses.replace(LINUX_OS, distro_id=distro, version=version)) == expected
    assert ecosystem_for(WINDOWS_OS) == ("windows", "generic")


def write_snapshot(directory, records, snapshot_date="2026-10-20", tamper=False):
    import hashlib
    directory.mkdir(parents=True, exist_ok=True)
    data = "".join(json.dumps(r) + "\n" for r in records).encode()
    (directory / "records.jsonl").write_bytes(data)          # exact bytes (no CRLF translation on Windows)
    digest = hashlib.sha256(data).hexdigest()
    if tamper:
        (directory / "records.jsonl").write_bytes(data + (json.dumps(records[0]) + "\n").encode())
    (directory / "manifest.json").write_text(json.dumps({
        "format": "psa-vulndata-1", "snapshot_date": snapshot_date, "record_count": len(records),
        "sources": [{"name": "unit test"}], "files": {"records.jsonl": digest}}))
    return directory


RECORDS = [
    {"id": "PSA-TEST-0001", "aliases": ["CVE-2099-0001"], "ecosystem": "ubuntu:24.04", "package": "examplelib",
     "ranges": [{"introduced": "0", "fixed": "1.2-1ubuntu0.2"}], "severity": "low",
     "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "source": "unit"}]},
    {"id": "UBUNTU-CVE-2099-0002", "ecosystem": "ubuntu:24.04", "package": "examplelib",
     "ranges": [{"introduced": "0", "fixed": "1.2-1ubuntu0.5"}], "severity": "medium"},
    {"id": "PSA-TEST-0003", "ecosystem": "ubuntu:24.04", "package": "examplelib", "ranges": [{"introduced": "0"}]},
    {"id": "PSA-TEST-0004", "ecosystem": "ubuntu:22.04", "package": "examplelib",
     "ranges": [{"introduced": "0", "fixed": "9"}]},
    {"id": "PSA-TEST-0005", "ecosystem": "ubuntu:24.04", "package": "otherpkg",
     "ranges": [{"introduced": "0", "fixed": "1.0"}]},
    {"id": "PSA-WIN-0001", "ecosystem": "windows", "package": "Example Viewer", "match": "prefix",
     "ranges": [{"introduced": "0", "fixed": "5.2"}], "severity": "high"},
]


def test_snapshot_integrity(tmp_path):
    snap = open_snapshot(write_snapshot(tmp_path / "ok", RECORDS))
    assert snap.age_days(date(2026, 10, 25)) == 5
    with pytest.raises(VulnDataError, match="SHA-256"):
        open_snapshot(write_snapshot(tmp_path / "bad", RECORDS, tamper=True))
    with pytest.raises(FileNotFoundError):
        open_snapshot(tmp_path / "missing")
    evil = write_snapshot(tmp_path / "evil", RECORDS)
    m = json.loads((evil / "manifest.json").read_text())
    m["files"] = {"../../etc/passwd": "0" * 64}
    (evil / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(VulnDataError, match="invalid data file name"):
        open_snapshot(evil)


def test_load_and_match(tmp_path):
    snap = open_snapshot(write_snapshot(tmp_path / "s", RECORDS + [{"id": "broken", "ecosystem": "ubuntu:24.04"}]))
    index, bad = load_advisories(snap, "ubuntu:24.04")
    assert bad == 1 and sorted(index) == ["examplelib", "otherpkg"] and len(index["examplelib"]) == 3
    pkgs = [{"name": "libexample1:amd64", "version": "1.2-1ubuntu0.3", "source": "examplelib",
             "source_version": "1.2-1ubuntu0.3"}, {"name": "otherpkg", "version": "1.0"}]
    found = sorted(m.advisory.id for m in match_packages(pkgs, index, "dpkg"))
    assert found == ["PSA-TEST-0003", "UBUNTU-CVE-2099-0002"]   # 0001 fixed in 0.2; otherpkg at fixed version


# -- Module E ----------------------------------------------------------------------------------------------

DPKG = ("libexample1:amd64\t1.2-1ubuntu0.1\tii \texamplelib\t1.2-1ubuntu0.1\n"
        "examplelib-bin\t1.2-1ubuntu0.1\tii \texamplelib\t1.2-1ubuntu0.1\nbash\t5.2\tii \tbash\t5.2\n")


def vuln_ctx(tmp_path, os_info=LINUX_OS, runner=None, records=RECORDS, **snap):
    ctx = make_ctx(os_info, runner or FakeRunner().on("dpkg-query", stdout=DPKG))
    ctx.config.vulndata.directory = str(write_snapshot(tmp_path / "vulndata", records, **snap))
    return ctx


def test_vulnerable_packages_finding(tmp_path):
    ctx = vuln_ctx(tmp_path)
    f = VulnerablePackagesCheck(today=date(2026, 10, 25)).run(ctx)
    assert len(f) == 1
    x = f[0]
    assert x.title == "examplelib: 3 known vulnerabilities affect the installed version"
    assert x.severity == Severity.CRITICAL and x.status == FindingStatus.POTENTIAL
    assert x.confidence == Confidence.HIGH and x.manual_validation_required
    assert "CVSS v3.1 base score 9.8 (unit)" in x.severity_rationale and "rates it 'low'" in x.severity_rationale
    assert "Update examplelib to 1.2-1ubuntu0.5 or later" in x.remediation      # highest fix, not text order
    assert "1 advisory(ies) have no fix yet" in x.remediation
    assert "2 of them are fixed in a newer package; 1 have no fixed package yet" in x.description
    assert "--only-upgrade examplelib-bin libexample1" in x.remediation
    cves = [r for r in x.references if r.kind == ReferenceKind.CVE]
    assert cves[0].identifier == "CVE-2099-0001" and cves[0].cvss_score == 9.8 and cves[0].cvss_version == "3.1"
    assert {r.identifier for r in cves} == {"CVE-2099-0001", "CVE-2099-0002"}
    assert ctx.data_sources[0]["snapshot_date"] == "2026-10-20" and not ctx.partial


def test_vulnerability_data_missing_stale_tampered(tmp_path):
    ctx = make_ctx(LINUX_OS, FakeRunner())
    ctx.config.vulndata.directory = str(tmp_path / "nothing")
    with pytest.raises(SkipCheck, match="No offline vulnerability snapshot"):
        VulnerablePackagesCheck().run(ctx)
    ctx = vuln_ctx(tmp_path / "t", tamper=True)
    with pytest.raises(SkipCheck, match="FAILED validation"):
        VulnerablePackagesCheck().run(ctx)
    ctx = vuln_ctx(tmp_path / "old", snapshot_date="2026-01-01")
    VulnerablePackagesCheck(today=date(2026, 10, 25)).run(ctx)
    assert "days old" in ctx.partial[0].description


def test_no_records_for_ecosystem_and_no_matches(tmp_path):
    import dataclasses
    deb = dataclasses.replace(LINUX_OS, distro_id="debian", version="12")
    ctx = vuln_ctx(tmp_path / "a", os_info=deb)
    assert VulnerablePackagesCheck(today=date(2026, 10, 25)).run(ctx) == []
    assert "no records for 'debian:12'" in ctx.partial[0].description
    ctx = vuln_ctx(tmp_path / "b", runner=FakeRunner().on("dpkg-query", stdout="bash\t5.2\tii \tbash\t5.2\n"))
    assert VulnerablePackagesCheck(today=date(2026, 10, 25)).run(ctx) == []
    assert "compared with 4 advisory record(s)" in ctx.notes[0]


def test_windows_prefix_match_is_low_confidence(tmp_path):
    runner = FakeRunner().on("powershell", contains="Uninstall", json_=[
        {"DisplayName": "Example Viewer 5", "DisplayVersion": "5.1.3", "Publisher": "Example"},
        {"DisplayName": "Example Viewer Pro", "DisplayVersion": "5.2.0", "Publisher": "Example"}])
    ctx = vuln_ctx(tmp_path, os_info=WINDOWS_OS, runner=runner)
    f = VulnerablePackagesCheck(today=date(2026, 10, 25)).run(ctx)
    assert [x.title for x in f] == ["Example Viewer 5: 1 known vulnerability affect the installed version"]
    assert f[0].confidence == Confidence.LOW and f[0].severity == Severity.HIGH
    assert "non-distribution data" in f[0].severity_rationale


def test_advisory_severity_fallbacks_and_cve_extraction():
    assert advisory_severity(adv(severity="important"))[0] == Severity.HIGH
    sev, why = advisory_severity(adv())
    assert sev == Severity.MEDIUM and "defaulted" in why
    assert cve_ids(adv(id="DEBIAN-CVE-2024-1234", aliases=["GHSA-x", "CVE-2024-9999"])) == [
        "CVE-2024-1234", "CVE-2024-9999"]


# -- normalization and scoring --------------------------------------------------------------------------------

def finding(**over):
    base = dict(title="t", severity=Severity.HIGH, status=FindingStatus.CONFIRMED, affected_host="h",
                affected_component="c", description="d", impact="i", confidence=Confidence.HIGH, remediation="r",
                verification="v", severity_rationale="because", check_id="X-1")
    return Finding(**{**base, **over})


@pytest.mark.parametrize("sev,status,conf,score,prio", [
    (Severity.CRITICAL, FindingStatus.CONFIRMED, Confidence.HIGH, 10.0, IMMEDIATE),
    (Severity.CRITICAL, FindingStatus.POTENTIAL, Confidence.LOW, 5.2, IMMEDIATE),
    (Severity.HIGH, FindingStatus.CONFIRMED, Confidence.HIGH, 7.5, IMMEDIATE),
    (Severity.HIGH, FindingStatus.POTENTIAL, Confidence.MEDIUM, 5.1, SHORT_TERM),
    (Severity.MEDIUM, FindingStatus.CONFIRMED, Confidence.HIGH, 5.0, PLANNED),
    (Severity.LOW, FindingStatus.INCONCLUSIVE, Confidence.LOW, 0.8, PLANNED),
    (Severity.INFO, FindingStatus.INFORMATIONAL, Confidence.HIGH, 0.0, MONITORING),
])
def test_risk_score_and_priority(sev, status, conf, score, prio):
    f = finding(severity=sev, status=status, confidence=conf)
    assert risk_score(f) == score and remediation_priority(f) == prio


def test_normalize_consistency_rules():
    f = finding(severity=Severity.MEDIUM, status=FindingStatus.INFORMATIONAL)
    normalize_finding(f)
    assert f.severity == Severity.INFO and "[Normalized:" in f.severity_rationale
    g = finding(status=FindingStatus.POTENTIAL, references=[
        Reference(ReferenceKind.CVE, "CVE-2024-1"), Reference(ReferenceKind.CVE, "CVE-2024-12345", cvss_score=11.0,
                                                              cvss_version="3.1"),
        Reference(ReferenceKind.CWE, "CWE-79"), Reference(ReferenceKind.CVE, "CVE-2024-23456", cvss_score=5.0)])
    normalize_finding(g)
    assert g.manual_validation_required
    assert [r.identifier for r in g.references] == ["CVE-2024-12345", "CWE-79", "CVE-2024-23456"]
    assert all(r.cvss_score is None for r in g.references)
    h = finding(description="leaked password=hunter2")
    normalize_finding(h)
    assert "hunter2" not in h.description


def test_fingerprint_is_stable_across_count_changes():
    a = finding(title="3 security update(s) pending")
    b = finding(title="7 security update(s) pending")
    c = finding(title="3 security update(s) pending", affected_host="other")
    assert fingerprint(a) == fingerprint(b) != fingerprint(c)


def result_with(*findings, statuses=()):
    host = HostInfo("h", "linux", "Ubuntu", "24.04", "6.8", "x86_64", True, True, "supported")
    checks = [CheckResult("X-1", "m", "x", CheckStatus.FINDINGS, findings=list(findings))]
    checks += [CheckResult(f"S-{i}", "m", "s", s) for i, s in enumerate(statuses)]
    return AssessmentResult("PSA-1", "0", "live", host, {}, ["m"], utcnow(), checks=checks)


def test_finalize_dedupes_scores_and_rates():
    dup1 = finding(title="Dup issue")
    dup2 = finding(title="Dup issue", evidence=[])
    r = finalize(result_with(finding(severity=Severity.CRITICAL, title="Crit"), dup1, dup2))
    assert len(r.findings) == 2 and any(l.category == "normalization" for l in r.limitations)
    assert r.posture["rating"] == "Critical risk" and r.posture["top_risks"][0]["title"] == "Crit"
    assert all(f.fingerprint and f.priority for f in r.findings)


@pytest.mark.parametrize("findings,rating", [
    ([], "Low risk"),
    ([dict(severity=Severity.MEDIUM)], "Moderate risk"),
    ([dict(severity=Severity.HIGH, status=FindingStatus.POTENTIAL)], "Elevated risk"),
    ([dict(severity=Severity.HIGH, title=f"h{i}x") for i in "abc"], "High risk"),
    ([dict(severity=Severity.CRITICAL, status=FindingStatus.POTENTIAL)], "High risk"),
    ([dict(severity=Severity.CRITICAL)], "Critical risk"),
])
def test_posture_ratings(findings, rating):
    r = finalize(result_with(*(finding(**f) for f in findings)))
    assert r.posture["rating"] == rating


def test_posture_flags_low_coverage():
    r = finalize(result_with(statuses=[CheckStatus.SKIPPED, CheckStatus.ERROR, CheckStatus.NOT_APPLICABLE]))
    assert r.posture["coverage_percent"] == 33 and "33%" in r.posture["caveat"]


# -- OSV converter ------------------------------------------------------------------------------------------

OSV_ENTRY = {
    "id": "UBUNTU-CVE-2099-0100", "aliases": None, "published": "2099-01-02T00:00:00Z", "summary": "Example flaw",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                 {"type": "Ubuntu", "score": "medium"}],
    "references": [{"type": "WEB", "url": "https://ubuntu.com/security/CVE-2099-0100"},
                   {"type": "WEB", "url": "http://insecure.example/"}],
    "affected": [
        {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "examplelib"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2-1ubuntu0.9"}]}]},
        {"package": {"ecosystem": "Ubuntu:Pro:18.04:LTS", "name": "examplelib"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
        {"package": {"ecosystem": "Debian:12", "name": "examplelib"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.1"}, {"introduced": "2.0"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "examplelib"}, "ranges": [{"type": "SEMVER", "events": []}]},
    ]}


def test_osv_converter(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("osvconv", REPO_ROOT / "scripts" / "vulndata_from_osv.py")
    conv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(conv)
    assert conv.map_ecosystem("Ubuntu:22.04:LTS") == "ubuntu:22.04"
    assert conv.map_ecosystem("Ubuntu:Pro:18.04:LTS") is None and conv.map_ecosystem("Rocky Linux:9") == "rocky:9"
    zpath = tmp_path / "Ubuntu-all.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("UBUNTU-CVE-2099-0100.json", json.dumps(OSV_ENTRY))
        zf.writestr("../../escape.json", json.dumps(OSV_ENTRY | {"id": "UBUNTU-CVE-2099-0101"}))
        zf.writestr("broken.json", "{not json")
    out = tmp_path / "vd"
    assert conv.main(["--out", str(out), "--snapshot-date", "2099-01-03", str(zpath)]) == 0
    assert not (tmp_path.parent / "escape.json").exists()
    snap = open_snapshot(out)
    assert snap.manifest["skipped_invalid_entries"] == 1 and snap.manifest["ecosystems"] == {
        "debian:12": 2, "ubuntu:24.04": 2}
    ubuntu, _ = load_advisories(snap, "ubuntu:24.04")
    a = ubuntu["examplelib"][0]
    assert a.aliases == ["CVE-2099-0100"] and a.severity == "medium" and a.cvss[0]["score"] == 7.5
    assert a.references == ["https://ubuntu.com/security/CVE-2099-0100"]
    debian, _ = load_advisories(snap, "debian:12")
    assert debian["examplelib"][0].ranges == [{"introduced": "1.0", "fixed": "1.1"}, {"introduced": "2.0"}]
    (out / "stray.txt").unlink(missing_ok=True)
    other = tmp_path / "not-a-snapshot"
    other.mkdir()
    (other / "important.doc").write_text("x")
    with pytest.raises(SystemExit):
        conv.main(["--out", str(other), str(zpath)])

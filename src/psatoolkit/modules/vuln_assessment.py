"""Module E: vulnerability assessment against offline advisory data.

Installed packages (Module A inventory) are compared with an offline
vulnerability snapshot on the drive (``vulndata/``). Nothing is downloaded and
no vulnerability is exploited or probed.

Evidence standard: a package version below the vendor's fixed version is
strong but *indirect* evidence. Findings are therefore always ``potential``.
Confidence is high only when the advisory comes from the host's own
distribution (which accounts for back-ported fixes); generic upstream data is
low confidence and needs manual validation.
"""

from __future__ import annotations

import re
from collections import defaultdict
from functools import cmp_to_key
from datetime import date
from pathlib import Path

from psatoolkit.core.cvss import severity_from_score
from psatoolkit.core.engine import AssessmentContext, Check, Module, SkipCheck
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Reference, ReferenceKind, Severity
from psatoolkit.core.versions import COMPARATORS
from psatoolkit.core.vulndb import (Advisory, Match, VulnDataError, ecosystem_for, load_advisories, match_packages,
                                    open_snapshot)
from psatoolkit.modules._common import url
from psatoolkit.modules.system_info import collect_software

VENDOR_SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "important": Severity.HIGH,
                   "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM, "low": Severity.LOW,
                   "negligible": Severity.LOW}
MAX_GROUPS = 300
MAX_ADVISORIES_PER_FINDING = 50


def advisory_severity(adv: Advisory) -> tuple[Severity, str]:
    """Severity and the sentence explaining where it came from."""
    best = adv.best_cvss
    if best:
        vendor = (f"; the distribution rates it '{adv.severity}' in its own context"
                  if adv.severity else "")
        return (severity_from_score(best["score"]) or Severity.INFO,
                f"CVSS v{best['version']} base score {best['score']} ({best['source']}){vendor}")
    if adv.severity in VENDOR_SEVERITY:
        return VENDOR_SEVERITY[adv.severity], f"vendor rating '{adv.severity}' (no CVSS score in the data)"
    return Severity.MEDIUM, "no CVSS score or vendor rating in the data; defaulted to Medium"


_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def cve_ids(adv: Advisory) -> list[str]:
    """CVE identifiers from the record ID (e.g. UBUNTU-CVE-2024-5535) and its aliases."""
    return sorted({m.group(0) for i in [adv.id, *adv.aliases] for m in [_CVE.search(i)] if m})


class VulnerablePackagesCheck(Check):
    check_id = "VULN-PKG-001"
    title = "Known vulnerabilities in installed software (offline data)"
    description = ("Compares installed package versions with the offline vulnerability snapshot (vendor fixed "
                   "versions); no network access and no exploitation.")
    supported_os = frozenset({"linux", "windows"})
    timeout_seconds = 300

    def __init__(self, today: date | None = None) -> None:
        self.today = today

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        eco = ecosystem_for(ctx.os_info)
        if eco is None:
            raise SkipCheck(f"No vulnerability data ecosystem is defined for {ctx.os_info.name}.", "platform")
        ecosystem, scheme = eco
        directory = Path(ctx.config.vulndata.directory)
        try:
            snapshot = open_snapshot(directory)
        except FileNotFoundError:
            raise SkipCheck(f"No offline vulnerability snapshot was found in {directory}. Prepare one on an "
                            "admin workstation (docs/VULNDATA.md) and copy it to the drive.", "dependency") from None
        except VulnDataError as exc:
            raise SkipCheck(f"Vulnerability data FAILED validation and was not used: {exc}. Rebuild the "
                            "snapshot from a trusted source.", "error") from None
        age = snapshot.age_days(self.today)
        ctx.data_sources.append({"type": "vulnerability_data", "path": str(directory),
                                 "snapshot_date": snapshot.manifest.get("snapshot_date"), "age_days": age,
                                 "record_count": snapshot.record_count, "sources": snapshot.sources,
                                 "ecosystem": ecosystem})
        if age is None or age > ctx.config.vulndata.max_age_days:
            ctx.limitation(f"Vulnerability data is {age if age is not None else 'of unknown'} days old "
                           f"(limit {ctx.config.vulndata.max_age_days}); vulnerabilities published since then are "
                           "not detected.", "dependency")
        index, bad = load_advisories(snapshot, ecosystem)
        if bad:
            ctx.limitation(f"{bad} malformed vulnerability record(s) were ignored.", "error")
        if not index:
            ctx.limitation(f"The vulnerability snapshot contains no records for '{ecosystem}', so installed "
                           "software was not matched.", "dependency")
            ctx.note(f"No advisory data for {ecosystem}")
            return []
        packages, source, inv_scheme = collect_software(ctx)
        scheme = inv_scheme if inv_scheme != "generic" else scheme
        matches = match_packages(packages, index, scheme)
        ctx.note(f"{len(packages)} package(s) compared with {sum(len(v) for v in index.values())} advisory "
                 f"record(s) for {ecosystem} (snapshot {snapshot.manifest.get('snapshot_date')})")
        if not matches:
            return []
        groups: dict[str, list[Match]] = defaultdict(list)
        for m in matches:
            groups[m.matched_on].append(m)
        distro_data = ecosystem != "windows"
        findings = []
        for name, group in sorted(groups.items(), key=lambda kv: -max(advisory_severity(m.advisory)[0].rank
                                                                         for m in kv[1]))[:MAX_GROUPS]:
            findings.append(self._finding(ctx, name, group, distro_data, snapshot.manifest.get("snapshot_date"),
                                          source, scheme))
        if len(groups) > MAX_GROUPS:
            ctx.limitation(f"Only the {MAX_GROUPS} most severe affected packages are reported "
                           f"({len(groups)} affected).", "scope")
        return findings

    def _finding(self, ctx: AssessmentContext, name: str, group: list[Match], distro_data: bool,
                 snapshot_date: str | None, inventory_source: str, scheme: str) -> Finding:
        advisories = {m.advisory.id: m.advisory for m in group}
        rated = sorted(((advisory_severity(a), a) for a in advisories.values()),
                       key=lambda x: (x[0][0].rank, (x[1].best_cvss or {}).get("score") or 0), reverse=True)
        (severity, why), top = rated[0]
        installed = sorted({f"{m.package} {m.version}" for m in group})
        binaries = sorted({m.package.split(":")[0] for m in group})
        compare = COMPARATORS[scheme]
        installed_versions = {m.version for m in group}
        # The version to install is the highest fix among advisories that are fixable from this version.
        fixes = [max(a.fixed_versions, key=cmp_to_key(compare)) for a in advisories.values() if a.fixed_versions]
        target = max(fixes, key=cmp_to_key(compare)) if fixes else None
        unfixed = [a.id for a in advisories.values() if not a.fixed_versions]
        cves = sorted({c for a in advisories.values() for c in cve_ids(a)})
        refs = []
        for _sev_why, adv in rated[:20]:
            best = adv.best_cvss
            for cid in cve_ids(adv)[:1]:
                refs.append(Reference(ReferenceKind.CVE, cid, best["source"] if best else "advisory data",
                                      best["score"] if best else None, best["version"] if best else None,
                                      best["vector"] if best else None))
        for link in top.references[:2]:
            refs.append(url(link, f"Advisory {top.id}"))
        upgrade = (f"sudo apt install --only-upgrade {' '.join(binaries)}" if ctx.os_info.distro_id in
                   ("ubuntu", "debian") else f"sudo dnf upgrade {' '.join(binaries)}" if ctx.os_info.family == "linux"
                   else "the vendor's installer or your software distribution tool")
        evidence = [{"advisory": a.id, "cves": cve_ids(a), "severity_basis": s[1], "severity": s[0].value,
                     "fixed_versions": a.fixed_versions, "summary": a.summary[:300], "published": a.published}
                    for s, a in rated[:MAX_ADVISORIES_PER_FINDING]]
        count = len(advisories)
        cve_text = f" ({', '.join(cves[:8])}{' ...' if len(cves) > 8 else ''})" if cves else ""
        fixable = count - len(unfixed)
        if fixable and unfixed:
            state = (f"{fixable} of them are fixed in a newer package; {len(unfixed)} have no fixed package yet")
        elif fixable:
            state = "all of them are fixed in a newer package"
        else:
            state = "none of them has a fixed package yet"
        if target:
            remediation = (f"Update {name} to {target} or later ({upgrade}), then restart affected services (or "
                           "reboot for kernel/libc updates).")
            if unfixed:
                remediation += (f" {len(unfixed)} advisory(ies) have no fix yet: track them with the distribution "
                                "and apply the vendor's mitigations.")
        else:
            remediation = ("No fixed package is available yet. Follow the distribution's advisory for mitigations, "
                           "limit exposure of the affected software, and re-assess when a fix is released.")
        return ctx.finding(
            self, title=f"{name}: {count} known vulnerabilit{'y' if count == 1 else 'ies'} affect the installed "
                        "version",
            severity=severity, status=FindingStatus.POTENTIAL,
            component=f"Package {name} ({', '.join(installed[:5])}{' ...' if len(installed) > 5 else ''})",
            description=f"The installed version ({', '.join(sorted(installed_versions)[:3])}) is affected by {count} "
                        f"advisor{'y' if count == 1 else 'ies'}{cve_text}; {state}. Most severe: {top.id}"
                        + (f" - {top.summary[:200]}" if top.summary else "") + ".",
            impact="Publicly documented vulnerabilities may allow attackers to compromise the affected software, "
                   "depending on how it is used and exposed on this host.",
            confidence=Confidence.HIGH if distro_data else Confidence.LOW,
            remediation=remediation,
            verification=f"Re-run this assessment; or compare the installed version ({inventory_source}) with the "
                         f"advisory's fixed version.",
            severity_rationale=f"{severity.value.capitalize()}: highest rating among the matching advisories is "
                               f"{top.id} with {why}. Status is potential because the match is version-based "
                               + ("using the distribution's own advisory data (back-ports are accounted for); "
                                  "whether the vulnerable code is reachable on this host was not tested."
                                  if distro_data else "using non-distribution data; vendor back-ports or "
                                                      "configuration may make the host unaffected."),
            evidence=[ctx.evidence(f"Matching advisories (snapshot {snapshot_date})", "offline vulnerability data",
                                   evidence)],
            references=refs, manual_validation_required=True)


def build_module() -> Module:
    return Module(
        module_id="vuln_assessment",
        name="E. Vulnerability assessment (offline data)",
        description="Matches installed software against an offline, integrity-checked vulnerability snapshot.",
        category="local",
        checks=[VulnerablePackagesCheck()],
    )

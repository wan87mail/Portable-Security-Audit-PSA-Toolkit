"""Module F: comparison with organisation-supplied security baselines.

Baselines are JSON data files in ``<USB>/baselines/`` (see docs/BASELINES.md).
Each rule is evaluated with one of the read-only collectors below. A failed
rule becomes a finding with the severity chosen by the baseline author; rules
that cannot be evaluated (missing privilege, unreadable source) are reported
as limitations, never as passes.

Results describe deviations from the supplied baseline. They are not a
formal compliance assessment or certification.
"""

from __future__ import annotations

import stat as st
from pathlib import Path
from typing import Any

from psatoolkit.core.baseline import Baseline, Rule, evaluate, expected_text, is_secret_path, load_directory
from psatoolkit.core.engine import AssessmentContext, Check, Module, SkipCheck
from psatoolkit.core.models import Confidence, Finding, FindingStatus, Reference, ReferenceKind, Severity
from psatoolkit.modules._common import mode_str, parse_kv_lines, read_registry, run_ps

SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
            "informational": Severity.INFO}


class Inconclusive(Exception):
    """The value could not be collected; the rule is neither passed nor failed."""


def target_text(rule: Rule) -> str:
    p = rule.params
    return {
        "sshd": lambda: f"sshd setting '{p['key']}'",
        "sysctl": lambda: f"kernel parameter {p['name']}",
        "file_kv": lambda: f"'{p['key']}' in {p['path']}",
        "file_contains": lambda: f"{p['path']} containing '{p['text']}'",
        "file_mode": lambda: f"permissions of {p['path']}",
        "package": lambda: f"package {p['name']}",
        "service": lambda: f"service {p['unit']} ({p['property']})",
        "registry": lambda: f"registry value {p['path']}\\{p['name']}",
        "net_accounts": lambda: f"account policy '{p['key']}'",
        "windows_service": lambda: f"Windows service {p['name']} ({p['property']})",
        "auditpol": lambda: f"audit subcategory {p['guid']}",
    }[rule.check_type]()


class Collector:
    """Collects values for rules; expensive sources are read once per assessment."""

    def __init__(self, ctx: AssessmentContext) -> None:
        self.ctx = ctx
        self._cache: dict[str, Any] = {}
        self.confidence = Confidence.HIGH

    def _once(self, key: str, loader):
        if key not in self._cache:
            try:
                self._cache[key] = ("ok", loader())
            except (SkipCheck, Inconclusive) as exc:
                self._cache[key] = ("error", str(getattr(exc, "reason", exc)))
            except RuntimeError as exc:   # query refused by the read-only command policy
                self._cache[key] = ("error", f"query not permitted: {exc}")
        state, value = self._cache[key]
        if state == "error":
            raise Inconclusive(value)
        return value

    def prefetch(self, rules: list[Rule]) -> None:
        """Batch Windows queries so each baseline costs at most a few PowerShell calls."""
        reg = [r for r in rules if r.check_type == "registry"]
        if reg:
            spec = {f"r{i}": (r.params["path"], [r.params["name"]]) for i, r in enumerate(reg)}

            def load_registry():
                data = read_registry(self.ctx, spec, "baseline registry values")
                return {(r.params["path"].lower(), r.params["name"].lower()): data.get(f"r{i}.{r.params['name']}")
                        for i, r in enumerate(reg)}
            self._once("registry", load_registry)
        names = sorted({r.params["name"] for r in rules if r.check_type == "windows_service"})
        if names:
            quoted = ",".join(f"'{n}'" for n in names)   # names are validated against [A-Za-z0-9_.-]

            def load_services():
                rows = run_ps(self.ctx, f"Get-Service -Name {quoted} -ErrorAction SilentlyContinue | Select-Object "
                                        "Name,@{n='Status';e={[string]$_.Status}},"
                                        "@{n='StartType';e={[string]$_.StartType}}", "Windows services")
                return {str(r.get("Name", "")).lower(): r for r in rows if isinstance(r, dict)}
            self._once("services", load_services)

    def value(self, rule: Rule) -> Any:
        if rule.needs_admin and not self.ctx.host.elevated:
            raise Inconclusive("requires administrator/root privileges")
        value = getattr(self, f"_c_{rule.check_type}")(rule.params)
        if value is None and "default" in rule.params:
            value = rule.params["default"]
        return value

    # -- Linux collectors ------------------------------------------------------
    def _c_sshd(self, p: dict[str, Any]) -> Any:
        from psatoolkit.modules.linux_audit import parse_sshd_config

        def load():
            if self.ctx.host.elevated and self.ctx.runner.is_available("sshd"):
                res = self.ctx.runner.run(["sshd", "-T"])
                if res.ok:
                    return {k.lower(): v for k, v in parse_kv_lines(res.stdout, comment="").items()}
            if not self.ctx.fs.exists("/etc/ssh/sshd_config"):
                raise Inconclusive("OpenSSH server configuration not found")
            settings, _read, unreadable = parse_sshd_config(self.ctx.fs)
            if unreadable:
                self.confidence = Confidence.MEDIUM
            return settings
        settings = self._once("sshd", load)
        value = settings.get(p["key"])
        return value.split()[0] if value and p["key"] not in ("ciphers", "macs", "kexalgorithms") else value

    def _c_sysctl(self, p: dict[str, Any]) -> Any:
        text, err = self.ctx.fs.try_read("/proc/sys/" + p["name"].replace(".", "/"))
        if text is None:
            if err == "missing":
                return None
            raise Inconclusive(f"kernel parameter not readable ({err})")
        return text.strip()

    def _read(self, path: str) -> str | None:
        # Import-time validation checks the path as written; a symlink could still point at
        # a protected file (e.g. /tmp/x -> /etc/shadow), so check where it really leads.
        resolved = self.ctx.fs.resolve(path)
        if resolved is not None and resolved != path and is_secret_path(resolved):
            raise Inconclusive(f"{path} resolves to {resolved}, whose contents may not be read (may contain secrets)")
        text, err = self.ctx.fs.try_read(path)
        if text is None and err != "missing":
            raise Inconclusive(f"{path} could not be read ({err})")
        return text

    def _c_file_kv(self, p: dict[str, Any]) -> Any:
        text = self._read(p["path"])
        if text is None:
            return None
        sep = {"=": "=", ":": ":", "whitespace": None}[p.get("separator", "whitespace")]
        return parse_kv_lines(text, sep=sep).get(p["key"])

    def _c_file_contains(self, p: dict[str, Any]) -> Any:
        text = self._read(p["path"])
        if text is None:
            return None
        return p["text"].lower() in text.lower()

    def _c_file_mode(self, p: dict[str, Any]) -> Any:
        s = self.ctx.fs.lstat(p["path"])
        if s is None:
            return None
        if st.S_ISLNK(s.st_mode):
            raise Inconclusive(f"{p['path']} is a symbolic link")
        return {"mode": s.st_mode & 0o7777, "uid": s.st_uid}

    def _c_package(self, p: dict[str, Any]) -> Any:
        from psatoolkit.modules.system_info import collect_software

        def load():
            packages, _source, _scheme = collect_software(self.ctx)
            return {pkg["name"].split(":")[0].lower(): pkg["version"] for pkg in packages}
        return self._once("packages", load).get(p["name"].lower())

    def _c_service(self, p: dict[str, Any]) -> Any:
        if not self.ctx.runner.is_available("systemctl"):
            raise Inconclusive("systemctl is not available")
        verb = "is-enabled" if p["property"] == "enabled" else "is-active"
        res = self.ctx.runner.run(["systemctl", verb, p["unit"]])
        out = res.stdout.strip()
        if res.error or res.timed_out:
            raise Inconclusive(f"systemctl failed ({res.error or 'timeout'})")
        if "not been booted with systemd" in res.stderr or "Failed to connect" in res.stderr:
            raise Inconclusive("systemd is not running")
        if not out or "No such file" in res.stderr or out == "not-found":
            return None
        return out.splitlines()[0]

    # -- Windows collectors ----------------------------------------------------
    def _c_registry(self, p: dict[str, Any]) -> Any:
        return self._once("registry", dict).get((p["path"].lower(), p["name"].lower()))

    def _c_net_accounts(self, p: dict[str, Any]) -> Any:
        from psatoolkit.modules.windows_audit import _num, parse_net_accounts

        def load():
            res = self.ctx.runner.run(["net", "accounts"])
            if not res.ok:
                raise Inconclusive("'net accounts' failed")
            parsed = parse_net_accounts(res.stdout)
            if "min_length" not in parsed:
                raise Inconclusive("'net accounts' output is not in English")
            return parsed
        raw = self._once("net_accounts", load).get(p["key"])
        return _num(raw) if raw is not None else None

    def _c_windows_service(self, p: dict[str, Any]) -> Any:
        row = self._once("services", dict).get(p["name"].lower())
        if row is None:
            return None
        return row.get("StartType" if p["property"] == "start_type" else "Status")

    def _c_auditpol(self, p: dict[str, Any]) -> Any:
        from psatoolkit.modules.windows_audit import parse_auditpol_csv

        def load():
            res = self.ctx.runner.run(["auditpol", "/get", "/category:*", "/r"])
            if not res.ok:
                raise Inconclusive("auditpol failed")
            return parse_auditpol_csv(res.stdout)
        return self._once("auditpol", load).get(p["guid"].upper())


def display(rule: Rule, value: Any) -> str:
    if rule.check_type == "file_mode" and isinstance(value, dict):
        return f"mode {mode_str(value['mode'])}, owner uid {value['uid']}"
    return "not set / not present" if value is None else str(value)


def rule_passes(rule: Rule, value: Any) -> bool:
    if rule.check_type == "file_mode":
        if value is None:
            return rule.op == "absent"
        ok = evaluate(rule, value["mode"])
        owner = rule.params.get("owner_uid")
        return ok and (owner is None or value["uid"] == owner)
    return evaluate(rule, value)


class BaselineCheck(Check):
    check_id = "BASE-001"
    title = "Organisational security baselines"
    description = ("Compares the configuration with imported baseline files (baselines/*.json); reports "
                   "deviations, not formal compliance.")
    supported_os = frozenset({"linux", "windows"})
    timeout_seconds = 300

    def run(self, ctx: AssessmentContext) -> list[Finding]:
        directory = Path(ctx.config.baselines.directory)
        baselines, errors = load_directory(directory)
        for err in errors:
            ctx.limitation(f"Baseline file rejected: {err}", "error")
        wanted = {n.lower() for n in ctx.config.baselines.enabled}
        applicable = [b for b in baselines if b.applies_to(ctx.os_info.family, ctx.os_info.distro_id)
                      and (not wanted or b.name.lower() in wanted)]
        if not applicable:
            raise SkipCheck(f"No imported baseline applies to {ctx.os_info.name} (looked in {directory}). Import "
                            "one with 'import-baseline <file>' (see docs/BASELINES.md).", "dependency")
        findings: list[Finding] = []
        for baseline in applicable:
            findings += self._assess(ctx, baseline)
        return findings

    def _assess(self, ctx: AssessmentContext, baseline: Baseline) -> list[Finding]:
        collector = Collector(ctx)
        collector.prefetch(baseline.rules)
        results = []
        for rule in baseline.rules:
            ctx.stop.raise_if_stopped()
            try:
                value = collector.value(rule)
            except Inconclusive as exc:
                results.append({"rule": rule, "result": "inconclusive", "reason": str(exc)})
                continue
            results.append({"rule": rule, "result": "pass" if rule_passes(rule, value) else "fail",
                            "observed": display(rule, value)})
        passed = [r for r in results if r["result"] == "pass"]
        failed = [r for r in results if r["result"] == "fail"]
        unknown = [r for r in results if r["result"] == "inconclusive"]
        evaluated = len(passed) + len(failed)
        label = f"{baseline.name} v{baseline.version}"
        ctx.data_sources.append({"type": "baseline", "name": baseline.name, "version": baseline.version,
                                 "sha256": baseline.sha256, "file": baseline.path.name if baseline.path else "",
                                 "rules": len(results), "passed": len(passed), "failed": len(failed),
                                 "inconclusive": len(unknown)})
        if unknown:
            ctx.limitation(f"{label}: {len(unknown)} rule(s) could not be evaluated: " + "; ".join(
                f"{r['rule'].id} ({r['reason']})" for r in unknown[:15]) + (" ..." if len(unknown) > 15 else ""),
                "privilege" if any("privilege" in r["reason"] for r in unknown) else "dependency")
        ctx.note(f"{label}: {len(passed)}/{evaluated} evaluated rules met, {len(unknown)} inconclusive")
        ref = Reference(ReferenceKind.BASELINE, label, baseline.source or "Organisation-supplied baseline")
        findings = [self._summary(ctx, baseline, label, results, passed, failed, unknown, ref)]
        for r in failed:
            findings.append(self._deviation(ctx, baseline, label, r["rule"], r["observed"], ref,
                                            collector.confidence))
        return findings

    def _summary(self, ctx, baseline, label, results, passed, failed, unknown, ref) -> Finding:
        evaluated = len(passed) + len(failed)
        pct = round(100 * len(passed) / evaluated) if evaluated else 0
        table = [{"rule": r["rule"].id, "title": r["rule"].title, "severity": r["rule"].severity,
                  "result": r["result"], "observed": r.get("observed"), "reason": r.get("reason"),
                  "expected": expected_text(r["rule"])} for r in results]
        return ctx.finding(
            self, title=f"Baseline '{baseline.name}': {len(passed)} of {evaluated} evaluated rules met ({pct}%)",
            severity=Severity.INFO, status=FindingStatus.INFORMATIONAL, component=f"Baseline {label}",
            description=f"{len(failed)} rule(s) deviate from the baseline and {len(unknown)} could not be evaluated. "
                        f"Baseline file {baseline.path.name if baseline.path else ''} (SHA-256 {baseline.sha256[:16]}...). "
                        "This compares configuration with the supplied baseline; it is not a formal compliance "
                        "assessment.",
            impact="Deviations are listed as separate findings.", confidence=Confidence.HIGH,
            remediation="Remediate the deviations, or record approved exceptions in the baseline.",
            verification="Re-run the assessment after changes.",
            severity_rationale="Informational summary of the baseline comparison.",
            evidence=[ctx.evidence("Rule-by-rule results", f"baseline {label}", table)], references=[ref])

    def _deviation(self, ctx, baseline, label, rule: Rule, observed: str, ref, confidence) -> Finding:
        target = target_text(rule)
        expected = expected_text(rule)
        refs = [Reference(ReferenceKind.BASELINE, f"{label} rule {rule.id}", ref.source)]
        if rule.reference:
            refs.append(Reference(ReferenceKind.BASELINE, rule.reference, "Cited by the baseline author"))
        sev = SEVERITY[rule.severity]
        return ctx.finding(
            self, title=f"Baseline deviation: {rule.title}", severity=sev,
            status=FindingStatus.INFORMATIONAL if sev == Severity.INFO else FindingStatus.CONFIRMED,
            component=f"{target} ({label} {rule.id})",
            description=(rule.description + " " if rule.description else "")
                        + f"Expected {target} to be {expected}; observed: {observed}.",
            impact=rule.rationale or "The system deviates from the organisation's approved configuration baseline.",
            confidence=confidence,
            remediation=rule.remediation or f"Change {target} to be {expected}, through your configuration "
                                            "management process.",
            verification=rule.verification or f"Re-run the assessment and confirm rule {rule.id} passes.",
            severity_rationale=f"{sev.value.capitalize()}: severity assigned by the baseline author ({label}). "
                               "The observed value was read directly from the system.",
            evidence=[ctx.evidence("Observed vs expected", f"baseline collector '{rule.check_type}'",
                                   {"target": target, "expected": expected, "observed": observed})],
            references=refs)


def build_module() -> Module:
    return Module(
        module_id="baselines",
        name="F. Security baselines (organisation-supplied)",
        description="Compares the system with imported baseline files and lists deviations.",
        category="baseline",
        checks=[BaselineCheck()],
    )

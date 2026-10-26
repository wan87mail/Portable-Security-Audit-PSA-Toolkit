"""PDF report for management and audit documentation (uses the built-in pdfgen writer)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from psatoolkit.reporting.pdfgen import BOLD, MONO, REGULAR, Flow, PdfDocument, hex_color
from psatoolkit.reporting.view import (CHECK_STATUS_LABELS, PRIORITIES, PRIORITY_HELP, PRIORITY_TITLES,
                                       RECURRING_ACTIVITIES, SEVERITIES, STATUS_LABELS, ReportView, evidence_text,
                                       fmt_time, reference_text)

SEV_COLORS = {"critical": hex_color("7f1d1d"), "high": hex_color("b91c1c"), "medium": hex_color("b45309"),
              "low": hex_color("1d4ed8"), "informational": hex_color("4b5563")}
POSTURE_COLORS = {0: hex_color("7f1d1d"), 1: hex_color("b91c1c"), 2: hex_color("b45309"), 3: hex_color("1d4ed8"),
                  4: hex_color("15803d")}
INK = (0.1, 0.12, 0.16)
MUTED = (0.36, 0.4, 0.46)


def render(doc: dict[str, Any]) -> bytes:
    v = ReportView(doc)
    integ = v.integrity
    pdf = PdfDocument(v.title, author=str(v.auth.get("operator", "")), subject="Security assessment report")
    f = Flow(pdf, footer=f"{integ['assessment_id']}  -  Confidential: security findings")

    # Title block
    f.paragraph("Security Assessment Report", 22, BOLD, (0.12, 0.31, 0.55))
    f.paragraph(f"{v.host.get('hostname')}  -  {v.host.get('os_name')}", 12, REGULAR, INK)
    f.paragraph(f"Assessment {integ['assessment_id']}  -  {fmt_time(v.a.get('started_at'))}", 9.5, REGULAR, MUTED)
    f.space(6)
    if v.is_demo:
        top = f.box(26, hex_color("fef3c7"))
        pdf.text(f.page, f.left + 8, top - 17, "DEMONSTRATION REPORT: all findings are sample data and do not "
                                               "describe a real system.", BOLD, 9.5, hex_color("78350f"))
        f.space(8)

    # Executive summary
    f.heading("Executive summary", 1)
    p = v.posture
    top = f.box(54, (0.96, 0.97, 0.98))
    pdf.text(f.page, f.left + 10, top - 18, "Overall security posture", REGULAR, 9, MUTED)
    pdf.text(f.page, f.left + 10, top - 40, str(p.get("rating", "Not rated")), BOLD, 18,
             POSTURE_COLORS.get(p.get("level", 4), INK))
    f.space(6)
    f.paragraph(f"Reason: {p.get('reason', '-')}. {p.get('checks_completed')} of {p.get('checks_applicable')} "
                f"applicable checks completed ({p.get('coverage_percent')}% coverage).", 10)
    if p.get("caveat"):
        f.paragraph(f"Coverage note: {p['caveat']}", 9.5, BOLD, hex_color("b45309"))
    f.space(8)
    counts = v.counts
    f.paragraph(f"Findings by severity ({v.total_findings} total)", 10.5, BOLD)
    f.space(4)
    box_w = f.width / 5
    top = f.box(44, (1, 1, 1))
    for i, sev in enumerate(SEVERITIES):
        x = f.left + i * box_w
        pdf.rect(f.page, x + 2, top - 44, box_w - 4, 44, SEV_COLORS[sev])
        pdf.text(f.page, x + 10, top - 24, str(counts[sev]), BOLD, 16, (1, 1, 1))
        pdf.text(f.page, x + 10, top - 38, sev.capitalize(), REGULAR, 8.5, (1, 1, 1))
    f.space(10)

    f.heading("Most important risks", 3)
    risks = v.top_risks()
    if risks:
        f.table(["Severity", "Finding", "Risk", "Status"],
                [[r["severity"].upper(), r["title"], str(r.get("risk_score")), STATUS_LABELS.get(r["status"], "")]
                 for r in risks], [16, 60, 8, 16],
                cell_colors={(i, 0): SEV_COLORS[r["severity"]] for i, r in enumerate(risks)})
    else:
        f.paragraph("No significant risks were identified.")
    f.heading("Key recommendations", 3)
    recs = v.key_recommendations()
    for n, rec in enumerate(recs, 1):
        f.paragraph(f"{n}. [{PRIORITY_TITLES[rec['priority']]}] {rec['text']}  ({', '.join(rec['findings'][:4])})",
                    9.5, indent=4)
        f.space(2)
    if not recs:
        f.paragraph("No remediation actions are required.")
    f.heading("Target system", 3)
    f.key_values(v.identification())
    f.heading("Assessment scope and authorization", 3)
    f.key_values(v.scope())
    f.space(6)
    f.paragraph("Automated, read-only assessment. Results do not constitute formal compliance certification. "
                "'Potential' findings rely on indirect evidence and require manual validation.", 8.5,
                REGULAR, MUTED)

    # Roadmap
    f.page_break()
    f.heading("Remediation roadmap", 1)
    groups = v.by_priority()
    for prio in PRIORITIES:
        items = sorted(groups.get(prio, []), key=lambda x: -(x.get("risk_score") or 0))
        f.heading(f"{PRIORITY_TITLES[prio]} ({len(items)})", 2)
        f.paragraph(PRIORITY_HELP[prio], 9, REGULAR, MUTED)
        f.space(4)
        if items:
            f.table(["Severity", "ID", "Finding", "Action"],
                    [[x["severity"].upper(), x["finding_id"], x["title"], x["remediation"]] for x in items],
                    [12, 24, 28, 46], size=8, cell_colors={(i, 0): SEV_COLORS[x["severity"]]
                                                           for i, x in enumerate(items)})
        else:
            f.paragraph("None.", 9.5)
        if prio == "monitoring":
            f.space(4)
            f.paragraph("Recurring activities:", 9.5, BOLD)
            for item in RECURRING_ACTIVITIES:
                f.paragraph(f"-  {item}", 9, indent=8)

    # Technical findings
    f.page_break()
    f.heading("Technical findings", 1)
    for x in v.findings:
        f.ensure(80)
        top = f.box(22, SEV_COLORS[x["severity"]])
        pdf.text(f.page, f.left + 8, top - 15, f"{x['severity'].upper()}  -  {x['finding_id']}", BOLD, 9.5, (1, 1, 1))
        f.space(4)
        f.paragraph(x["title"], 11.5, BOLD)
        f.space(2)
        f.key_values([
            ("Status / confidence", f"{STATUS_LABELS.get(x['status'], x['status'])} / {x['confidence']}"),
            ("Risk score / priority", f"{x.get('risk_score')} / {PRIORITY_TITLES.get(x.get('priority'), '')}"),
            ("Affected host", x["affected_host"]),
            ("Affected service/configuration", x["affected_component"]),
            ("Manual validation required", "Yes" if x.get("manual_validation_required") else "No"),
            ("References", "; ".join(reference_text(r) for r in x.get("references") or []) or "None"),
        ], key_width=150, size=8.5)
        for label, key in (("Description", "description"), ("Potential impact", "impact"),
                           ("Why this severity", "severity_rationale"), ("Recommended remediation", "remediation"),
                           ("How to verify", "verification")):
            f.space(3)
            f.paragraph(label, 9, BOLD, MUTED)
            f.paragraph(str(x.get(key, "")), 9)
        for ev in x.get("evidence") or []:
            f.space(3)
            f.paragraph(f"Evidence: {ev.get('description')} (via {ev.get('source')})", 9, BOLD, MUTED)
            body = evidence_text(ev, limit=1500)
            if body:
                f.paragraph(body, 7.5, MONO, INK)
        f.space(14)

    # Checks, limitations, integrity
    f.page_break()
    f.heading("Checks performed", 1)
    f.table(["ID", "Check", "Result", "Details"],
            [[c["check_id"], c["title"], CHECK_STATUS_LABELS.get(c["status"], c["status"]), c.get("message") or ""]
             for c in v.checks], [24, 30, 11, 45], size=7.5)
    f.heading("Limitations", 1)
    f.paragraph("Factors that may affect the accuracy or completeness of this assessment.", 9, REGULAR, MUTED)
    groups_l = v.limitations_by_category()
    for cat, items in sorted(groups_l.items()):
        f.paragraph(cat.capitalize(), 10, BOLD)
        for lim in items:
            prefix = f"{lim['check_id']}: " if lim.get("check_id") else ""
            f.paragraph(f"-  {prefix}{lim['description']}", 9, indent=8)
        f.space(4)
    if not groups_l:
        f.paragraph("No limitations were recorded.", 9.5)
    for s in v.data_sources:
        f.paragraph(f"Data source: {s.get('type')} snapshot {s.get('snapshot_date')} ({s.get('age_days')} days old), "
                    f"{s.get('record_count')} records, ecosystem {s.get('ecosystem')}.", 9)
    f.heading("Report integrity", 1)
    f.key_values([("Assessment ID", str(integ["assessment_id"])), ("Tool version", str(integ["tool_version"])),
                  ("Report generated", fmt_time(integ["generated_at"])),
                  ("SHA-256 of canonical contents", str(integ["canonical_sha256"])),
                  ("Verification", "PortableSecurityAudit verify-report <report folder>")], key_width=170, size=8.5)
    f.finish()
    return pdf.to_bytes()


def write_pdf_report(doc: dict[str, Any], folder: Path) -> Path:
    path = folder / "report.pdf"
    path.write_bytes(render(doc))
    return path

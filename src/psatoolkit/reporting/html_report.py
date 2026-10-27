"""Self-contained HTML report.

Single file, no JavaScript, no external resources, and a restrictive Content
Security Policy, so it can be opened safely offline. Every value from the
assessment is HTML-escaped. Findings use <details open> so they are
collapsible on screen and fully expanded when printed.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Iterable

from psatoolkit.reporting.view import (CHECK_STATUS_LABELS, PRIORITIES, PRIORITY_HELP, PRIORITY_TITLES,
                                       RECURRING_ACTIVITIES, SEVERITIES, STATUS_LABELS, ReportView, data_source_text,
                                       evidence_text, fmt_time, reference_text)


def e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--muted:#5b6675;--line:#dde2e8;--accent:#1f4e8c;
--critical:#7f1d1d;--high:#b91c1c;--medium:#b45309;--low:#1d4ed8;--informational:#4b5563;--ok:#15803d}
@media (prefers-color-scheme:dark){:root{--bg:#11151b;--card:#1a2029;--ink:#e6e9ee;--muted:#9aa5b4;--line:#2c3440;
--accent:#7fb0ff;--critical:#f87171;--high:#fb7185;--medium:#fbbf24;--low:#93c5fd;--informational:#cbd5e1;--ok:#4ade80}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
a{color:var(--accent)}
.tw{overflow-x:auto;max-width:100%}
.grid>*{min-width:0}
td.nowrap{white-space:nowrap}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:20px 0 8px}
.sub{color:var(--muted);margin:0 0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
.demo{background:#fef3c7;color:#78350f;border:1px solid #f59e0b;border-radius:8px;padding:10px 14px;font-weight:600}
.conf{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid var(--line);overflow-wrap:break-word}
th{color:var(--muted);font-weight:600;white-space:nowrap}
.kv th{width:34%}
.sev{display:inline-block;min-width:92px;text-align:center;padding:2px 8px;border-radius:999px;font-size:12px;
font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:.03em}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}
.sev.low{background:var(--low)}.sev.informational{background:var(--informational)}
@media (prefers-color-scheme:dark){.sev{color:#11151b}}
.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.count{border-radius:10px;padding:12px;text-align:center;border:1px solid var(--line);background:var(--card)}
.count b{display:block;font-size:28px;line-height:1.1}
.count.critical b{color:var(--critical)}.count.high b{color:var(--high)}.count.medium b{color:var(--medium)}
.count.low b{color:var(--low)}.count.informational b{color:var(--informational)}
.posture{font-size:22px;font-weight:700}
.p0,.p1{color:var(--high)}.p2{color:var(--medium)}.p3{color:var(--low)}.p4{color:var(--ok)}
.bar{display:flex;height:10px;border-radius:6px;overflow:hidden;background:var(--line);margin-top:10px}
.bar span{display:block}
.bar .critical{background:var(--critical)}.bar .high{background:var(--high)}.bar .medium{background:var(--medium)}
.bar .low{background:var(--low)}.bar .informational{background:var(--informational)}
details.finding{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--line);border-radius:10px;
margin:12px 0;padding:0 16px}
details.finding.critical{border-left-color:var(--critical)}details.finding.high{border-left-color:var(--high)}
details.finding.medium{border-left-color:var(--medium)}details.finding.low{border-left-color:var(--low)}
details.finding.informational{border-left-color:var(--informational)}
details.finding>summary{cursor:pointer;padding:12px 0;font-weight:600;list-style-position:outside}
details.finding>summary .id{color:var(--muted);font-weight:400;font-size:13px;margin-left:6px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;font-size:12.5px;
max-height:360px;white-space:pre-wrap;overflow-wrap:anywhere}
.tag{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:0 6px;font-size:12px;color:var(--muted)}
ul.tight{margin:6px 0;padding-left:20px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;overflow-wrap:anywhere}
footer{color:var(--muted);font-size:12px;margin-top:40px;text-align:center}
@media (max-width:640px){.counts{grid-template-columns:repeat(3,1fr)}.kv th{width:42%}th{white-space:normal}
h1{font-size:22px;overflow-wrap:anywhere}.sev{min-width:64px;font-size:11px}th,td{padding:6px}.card{padding:12px}details.finding{padding:0 12px}}
@media print{body{background:#fff;color:#000}main{max-width:none;padding:0}.card,details.finding{break-inside:avoid}
h2{break-before:page}h2.first{break-before:auto}pre{max-height:none}a{color:#000}}
"""


def sev_badge(sev: str) -> str:
    return f'<span class="sev {e(sev)}">{e(sev)}</span>'


def kv_table(rows: Iterable[tuple[str, str]]) -> str:
    body = "".join(f"<tr><th scope=\"row\">{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows)
    return f'<table class="kv">{body}</table>'


def render_finding(f: dict[str, Any]) -> str:
    refs = f.get("references") or []
    ref_html = "".join(
        f"<li>{e(r.get('kind'))}: " + (f'<a href="{e(r["identifier"])}" rel="noreferrer noopener">{e(r["identifier"])}</a>'
                                       if r.get("kind") == "URL" and str(r.get("identifier", "")).startswith("https://")
                                       else e(reference_text(r))) + "</li>" for r in refs) or "<li>None</li>"
    evidence = "".join(
        f"<h3>Evidence: {e(ev.get('description'))}</h3><p class=\"conf\">Collected via {e(ev.get('source'))} at "
        f"{e(fmt_time(ev.get('collected_at')))}</p>" + (f"<pre>{e(evidence_text(ev))}</pre>" if ev.get("data") is not None
                                                        else "") for ev in f.get("evidence") or [])
    rows = [
        ("Severity", f.get("severity", "").capitalize()),
        ("Status", STATUS_LABELS.get(f.get("status"), f.get("status"))),
        ("Confidence", str(f.get("confidence", "")).capitalize()),
        ("Risk score / priority", f"{f.get('risk_score')} / {PRIORITY_TITLES.get(f.get('priority'), f.get('priority'))}"),
        ("Affected host", f.get("affected_host")),
        ("Affected service or configuration", f.get("affected_component")),
        ("Manual validation required", "Yes" if f.get("manual_validation_required") else "No"),
        ("Check", f.get("check_id")),
        ("Fingerprint", f.get("fingerprint")),
    ]
    return f"""
<details class="finding {e(f.get('severity'))}" open id="{e(f.get('finding_id'))}">
<summary>{sev_badge(f.get('severity', ''))} {e(f.get('title'))}<span class="id">{e(f.get('finding_id'))}</span></summary>
{kv_table(rows)}
<h3>Description</h3><p>{e(f.get('description'))}</p>
<h3>Potential impact</h3><p>{e(f.get('impact'))}</p>
<h3>Why this severity</h3><p>{e(f.get('severity_rationale'))}</p>
<h3>Recommended remediation</h3><p>{e(f.get('remediation'))}</p>
<h3>How to verify the fix</h3><p class="mono">{e(f.get('verification'))}</p>
<h3>References</h3><ul class="tight">{ref_html}</ul>
{evidence}
</details>"""


def render(doc: dict[str, Any]) -> str:
    v = ReportView(doc)
    p = v.posture
    counts = v.counts
    total = max(v.total_findings, 1)
    bar = "".join(f'<span class="{s}" style="width:{100 * counts[s] / total:.2f}%" title="{s}: {counts[s]}"></span>'
                  for s in SEVERITIES if counts[s])
    count_cards = "".join(f'<div class="count {s}"><b>{counts[s]}</b>{e(s.capitalize())}</div>' for s in SEVERITIES)
    top = "".join(f"<tr><td>{sev_badge(f['severity'])}</td><td><a href=\"#{e(f['finding_id'])}\">{e(f['title'])}</a>"
                  f"</td><td>{e(f.get('risk_score'))}</td><td>{e(STATUS_LABELS.get(f['status'], f['status']))}</td></tr>"
                  for f in v.top_risks()) or '<tr><td colspan="4">No significant risks were identified.</td></tr>'
    recs = "".join(f"<li><b>{e(PRIORITY_TITLES[r['priority']])}:</b> {e(r['text'])} "
                   f"<span class=\"tag\">{e(', '.join(r['findings'][:4]))}</span></li>"
                   for r in v.key_recommendations()) or "<li>No remediation actions are required.</li>"
    groups = v.by_priority()
    roadmap = ""
    for prio in PRIORITIES:
        items = groups.get(prio, [])
        rows = "".join(f"<tr><td>{sev_badge(f['severity'])}</td><td class=\"mono nowrap\"><a href=\"#{e(f['finding_id'])}\">"
                       f"{e(f['finding_id'])}</a></td><td>{e(f['title'])}</td><td>{e(f['remediation'])}</td></tr>"
                       for f in sorted(items, key=lambda x: -(x.get('risk_score') or 0)))
        extra = ("<h3>Recurring activities</h3><ul class=\"tight\">" + "".join(f"<li>{e(a)}</li>"
                                                                         for a in RECURRING_ACTIVITIES) + "</ul>"
                 if prio == "monitoring" else "")
        roadmap += (f'<div class="card"><h3>{e(PRIORITY_TITLES[prio])} ({len(items)})</h3>'
                    f'<p class="conf">{e(PRIORITY_HELP[prio])}</p>'
                    + (f"<table><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Action</th></tr>{rows}</table>"
                       if items else "<p>None.</p>") + extra + "</div>")
    findings = "".join(render_finding(f) for f in v.findings) or "<p>No findings.</p>"
    checks = "".join(f"<tr><td class=\"mono\">{e(c['check_id'])}</td><td>{e(c['title'])}</td>"
                     f"<td>{e(CHECK_STATUS_LABELS.get(c['status'], c['status']))}</td>"
                     f"<td>{e(c.get('message'))}</td></tr>" for c in v.checks)
    lim_groups = v.limitations_by_category()
    limitations = "".join(
        f"<h3>{e(cat.capitalize())}</h3><ul class=\"tight\">" + "".join(
            f"<li>{('<span class=mono>' + e(l['check_id']) + '</span>: ') if l.get('check_id') else ''}"
            f"{e(l['description'])}</li>" for l in items) + "</ul>" for cat, items in sorted(lim_groups.items())
    ) or "<p>No limitations were recorded.</p>"
    sources = "".join(f"<li>{e(data_source_text(s))}</li>" for s in v.data_sources)
    integ = v.integrity
    demo = ('<p class="demo">DEMONSTRATION REPORT: all findings are sample data and do not describe a real system.'
            '</p>' if v.is_demo else "")
    caveat = f"<p><b>Coverage note:</b> {e(p.get('caveat'))}</p>" if p.get("caveat") else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>{e(v.title)}</title><style>{CSS}</style></head>
<body><main>
<h1>{e(v.title)}</h1>
<p class="sub">Assessment {e(integ['assessment_id'])} &middot; generated {e(fmt_time(integ['generated_at']))} &middot;
<b>Confidential</b>: contains security findings; share only with authorized staff.</p>
{demo}
<h2 class="first">Executive summary</h2>
<div class="grid">
<div class="card"><div class="conf">Overall security posture</div>
<div class="posture p{e(p.get('level', 4))}">{e(p.get('rating', 'Not rated'))}</div>
<p>{e(p.get('reason', ''))}. {e(p.get('checks_completed'))} of {e(p.get('checks_applicable'))} applicable checks
completed ({e(p.get('coverage_percent'))}% coverage).</p>{caveat}</div>
<div class="card"><div class="conf">Findings by severity ({v.total_findings} total)</div>
<div class="counts">{count_cards}</div><div class="bar">{bar}</div></div>
</div>
<div class="card"><h3>Most important risks</h3>
<table><tr><th>Severity</th><th>Finding</th><th>Risk score</th><th>Status</th></tr>{top}</table></div>
<div class="card"><h3>Key recommendations</h3><ol>{recs}</ol></div>
<div class="grid"><div class="card"><h3>Target system</h3>{kv_table(v.identification())}</div>
<div class="card"><h3>Assessment scope and authorization</h3>{kv_table(v.scope())}</div></div>
<p class="conf">Automated, read-only assessment. Results do not constitute formal compliance certification.
"Potential" findings rely on indirect evidence and require manual validation.</p>
<h2>Remediation roadmap</h2>{roadmap}
<h2>Technical findings</h2>{findings}
<h2>Checks performed</h2><div class="card"><table><tr><th>ID</th><th>Check</th><th>Result</th><th>Details</th></tr>
{checks}</table></div>
<h2>Limitations</h2><div class="card"><p>Factors that may affect the accuracy or completeness of this assessment.</p>
{limitations}{('<h3>Data sources</h3><ul class="tight">' + sources + '</ul>') if sources else ''}</div>
<h2>Report integrity</h2><div class="card">{kv_table([
        ("Assessment ID", integ['assessment_id']), ("Tool version", integ['tool_version']),
        ("Report generated", fmt_time(integ['generated_at'])),
        ("SHA-256 of canonical report contents", integ['canonical_sha256']),
        ("Verification", "PortableSecurityAudit verify-report <report folder>  (checks SHA256SUMS and the "
                         "canonical hash in report.json)")])}</div>
<footer>{e(doc.get('tool', {}).get('name'))} {e(integ['tool_version'])} &middot; {e(integ['assessment_id'])}</footer>
</main></body></html>
"""


def write_html_report(doc: dict[str, Any], folder: Path) -> Path:
    path = folder / "report.html"
    # Wide tables scroll inside their own container instead of widening the page on small screens.
    html = render(doc).replace("<table", '<div class="tw"><table').replace("</table>", "</table></div>")
    path.write_text(html, encoding="utf-8")
    return path

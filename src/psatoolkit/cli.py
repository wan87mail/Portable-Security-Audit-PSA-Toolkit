"""Command-line interface (headless; works on servers without a display).

Run ``PortableSecurityAudit --help`` (or ``python -m psatoolkit --help``).
Without arguments the GUI starts if Tkinter and a display are available.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path
from typing import Any, Sequence

from psatoolkit import TOOL_NAME, __version__
from psatoolkit.core.authorization import (AUTHORIZATION_NOTICE, CONFIRMATION_PHRASE, AuthorizationError,
                                           create_authorization, phrase_matches)
from psatoolkit.core.config import ConfigError
from psatoolkit.core.integrity import write_manifest
from psatoolkit.core.logging_setup import setup_app_logging, verify_audit_log
from psatoolkit.core.paths import OutputDirError
from psatoolkit.core.privileges import elevation_help
from psatoolkit.core.session import SessionOutcome, Toolkit
from psatoolkit.core.stop import StopToken
from psatoolkit.core.validation import ValidationError, parse_ports
from psatoolkit.reporting.json_report import verify_json_report

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_UNAUTHORIZED, EXIT_INTEGRITY, EXIT_STOPPED = 0, 1, 2, 3, 4, 130


def _print(*args: Any) -> None:
    print(*args, flush=True)


def _err(*args: Any) -> None:
    print(*args, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_info(tk: Toolkit, args: argparse.Namespace) -> int:
    host = tk.host_info()
    _print(f"{TOOL_NAME} {__version__}")
    _print(f"Portable root : {tk.paths.root}")
    _print(f"Hostname      : {host.hostname}")
    _print(f"OS            : {host.os_name}  (version {host.os_version}, build {host.os_build})")
    _print(f"Architecture  : {host.architecture}   Server: {host.is_server}")
    _print(f"Support level : {host.support_level}")
    for note in tk.os_info.notes:
        _print(f"  note: {note}")
    _print(f"Elevated      : {host.elevated}")
    if not host.elevated:
        _print(f"  {elevation_help(host.os_family)}")
    _print(f"Offline mode  : {tk.config.offline_mode}")
    for warning in tk.config.warnings:
        _print(f"Config warning: {warning}")
    _print("\nAvailable modules and check plan:")
    stop = StopToken()
    runner = tk.create_runner(stop)
    for module in tk.available_modules():
        _print(f"  [{module.module_id}] {module.name}")
        for item in tk.engine.plan([module.module_id], tk.os_info, host.elevated, runner, tk.scope):
            state = "will run" if item.runnable else f"{item.skip_status.value}: {item.skip_reason}"
            admin = " (admin)" if item.check.requires_admin else ""
            _print(f"      {item.check.check_id:<16} {item.check.title}{admin} -> {state}")
    for module, reason in tk.unavailable_modules():
        _print(f"  [{module.module_id}] {module.name} -> unavailable: {reason}")
    return EXIT_OK


def cmd_modules(tk: Toolkit, args: argparse.Namespace) -> int:
    for m in tk.modules:
        avail = "available" if m in tk.available_modules(demo=m.category == "demo") else "not for this OS"
        _print(f"{m.module_id:<14} {m.category:<8} {avail:<16} {m.name}")
        if args.verbose:
            for c in m.checks:
                flags = [f for f, on in (("admin", c.requires_admin), ("network", c.requires_network),
                                         ("internet", c.requires_internet)) if on]
                tools = f" tools={','.join(c.required_tools)}" if c.required_tools else ""
                _print(f"    {c.check_id:<18} {c.title} [{', '.join(sorted(c.supported_os))}]"
                       f"{' ' + ','.join(flags) if flags else ''}{tools}")
    return EXIT_OK


def _prompt(label: str, provided: str | None, interactive: bool) -> str:
    if provided is not None:
        return provided
    if not interactive:
        return ""
    return input(f"{label}: ").strip()


def _authorize(tk: Toolkit, args: argparse.Namespace, demo: bool):
    interactive = sys.stdin.isatty() and args.confirm is None
    _print(AUTHORIZATION_NOTICE)
    if demo:
        _print("DEMO MODE: no commands are executed and no network traffic is sent.\n")
    operator = _prompt("Operator name", args.operator, interactive)
    organization = _prompt("Organization (optional)", args.organization, interactive)
    reference = _prompt("Authorization reference (ticket / engagement letter)", args.reference, interactive)
    scope = _prompt("Scope statement (optional)", args.scope, interactive)
    if args.confirm is not None:
        typed, method = args.confirm, "cli-argument"
    elif interactive:
        typed, method = input(f"Type '{CONFIRMATION_PHRASE}' to confirm: "), "cli-interactive"
    else:
        raise AuthorizationError(
            f"Non-interactive runs must pass --confirm \"{CONFIRMATION_PHRASE}\" together with "
            "--operator and --reference.")
    return create_authorization(operator=operator, organization=organization, engagement_reference=reference,
                                scope_statement=scope, host=tk.host_info(demo).hostname,
                                confirmed=phrase_matches(typed), method="demo" if demo else method)


def _add_targets(tk: Toolkit, args: argparse.Namespace) -> None:
    targets = args.target or []
    refs = args.target_ref or []
    if len(targets) != len(refs):
        raise AuthorizationError("Each --target needs a matching --target-ref (permission reference).")
    for raw, ref in zip(targets, refs):
        if args.confirm is not None:
            confirmed = phrase_matches(args.confirm)
        else:
            typed = input(f"Type '{CONFIRMATION_PHRASE}' to confirm written permission to assess {raw}: ")
            confirmed = phrase_matches(typed)
        entry = tk.scope.add(raw, ref, confirmed)
        _print(f"Authorized target added: {entry.target.raw} ({entry.target.host_count} host(s), ref {ref})")


def _progress_printer(event: dict[str, Any]) -> None:
    kind = event.get("type")
    if kind == "start":
        _err(f"Assessment {event['assessment_id']} started: {event['total']} check(s) planned")
    elif kind == "check_end":
        msg = f" - {event['message']}" if event.get("message") else ""
        _err(f"  [{event['index']}/{event['total']}] {event['check_id']}: {event['status']}"
             f" ({event['findings']} finding(s)){msg}")
    elif kind == "end":
        _err(f"Assessment {event['status']}.")


def _summarise(outcome: SessionOutcome) -> None:
    r = outcome.result
    _print("\n=== Assessment summary ===")
    _print(f"Assessment ID : {r.assessment_id}  ({r.mode})")
    _print(f"Host          : {r.host.hostname} - {r.host.os_name}")
    _print(f"Status        : {r.status}")
    _print("Findings      : " + ", ".join(f"{k}={v}" for k, v in r.severity_counts().items()))
    if r.posture:
        p = r.posture
        _print(f"Posture       : {p['rating']} - {p['reason']} (coverage {p['coverage_percent']}% of "
               f"{p['checks_applicable']} applicable checks)")
        if p.get("caveat"):
            _print(f"                {p['caveat']}")
    for f in r.findings:
        _print(f"  {f.severity.value.upper():<13} {f.risk_score or 0:>4.1f}  {f.priority:<10} "
               f"{f.finding_id:<24} {f.title} [{f.status.value}]")
    if r.limitations:
        _print("Limitations:")
        for lim in r.limitations:
            _print(f"  - ({lim.category}) {lim.check_id + ': ' if lim.check_id else ''}{lim.description}")
    if outcome.report_error:
        _err(outcome.report_error)
    for path in outcome.report_files:
        _print(f"Report        : {path}")
    _print(f"Audit log     : {outcome.audit_log}")


def cmd_audit(tk: Toolkit, args: argparse.Namespace) -> int:
    demo = args.demo
    try:
        output_dir = tk.resolve_output_dir(args.output)
    except OutputDirError as exc:
        _err(f"Error: {exc}")
        return EXIT_ERROR
    available = {m.module_id for m in tk.available_modules(demo)}
    if args.modules:
        selected = [m.strip() for m in args.modules.split(",") if m.strip()]
        bad = [m for m in selected if m not in available]
        if bad:
            _err(f"Error: module(s) not available {'in demo mode' if demo else 'on this OS'}: {', '.join(bad)}. "
                 f"Available: {', '.join(sorted(available))}")
            return EXIT_USAGE
    else:
        selected = sorted(available) if demo else [m.module_id for m in tk.available_modules()
                                                     if m.category == "local"]
    try:
        authorization = _authorize(tk, args, demo)
        if not demo:
            _add_targets(tk, args)
    except AuthorizationError as exc:
        _err(f"Authorization refused: {exc}")
        return EXIT_UNAUTHORIZED
    except (EOFError, KeyboardInterrupt):
        _err("\nAuthorization cancelled.")
        return EXIT_UNAUTHORIZED

    _print(f"Reports will be written to: {output_dir}")
    _print("Press Ctrl+C at any time for an emergency stop.\n")
    stop = StopToken()
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            box["outcome"] = tk.run_assessment(authorization, selected, demo=demo,
                                               output_override=str(output_dir), stop=stop,
                                               progress=_progress_printer)
        except Exception as exc:  # noqa: BLE001 - reported to the operator
            box["error"] = exc

    thread = threading.Thread(target=worker, name="assessment", daemon=True)
    thread.start()
    while thread.is_alive():
        try:
            thread.join(0.2)
        except KeyboardInterrupt:
            _err("\nEMERGENCY STOP requested - terminating running checks...")
            stop.stop("Operator pressed Ctrl+C")
    if "error" in box:
        _err(f"Assessment failed: {box['error']}")
        return EXIT_ERROR
    outcome: SessionOutcome = box["outcome"]
    _summarise(outcome)
    if outcome.report_error:
        return EXIT_ERROR
    return EXIT_STOPPED if outcome.result.status == "stopped" else EXIT_OK


def cmd_preview_scan(tk: Toolkit, args: argparse.Namespace) -> int:
    """Dry run: show what a network assessment would contact. Sends no traffic."""
    try:
        ports = parse_ports(args.ports or tk.config.network.default_ports, tk.config.network.max_ports)
        for raw in args.target:
            tk.scope.add(raw, "preview-only", confirmed=True)
    except (ValidationError, AuthorizationError) as exc:
        _err(f"Invalid scan scope: {exc}")
        return EXIT_USAGE
    preview = tk.scope.preview(ports, tk.config.network.rate_limit_per_second)
    preview["note"] = "DRY RUN - no packets were sent. Authorization is still required for a real scan."
    _print(json.dumps(preview, indent=2))
    return EXIT_OK


def cmd_verify(tk: Toolkit, args: argparse.Namespace) -> int:
    report = tk.verify_integrity()
    _print(report.summary())
    return EXIT_OK if report.ok else EXIT_INTEGRITY


def cmd_verify_report(tk: Toolkit, args: argparse.Namespace) -> int:
    result = verify_json_report(Path(args.path))
    _print(f"{result.path}: {result.message}")
    return EXIT_OK if result.ok else EXIT_INTEGRITY


def cmd_verify_log(tk: Toolkit, args: argparse.Namespace) -> int:
    ok, problems = verify_audit_log(Path(args.path))
    _print(f"{args.path}: {'audit chain intact' if ok else 'AUDIT LOG TAMPERING OR CORRUPTION DETECTED'}")
    for p in problems:
        _print(f"  - {p}")
    return EXIT_OK if ok else EXIT_INTEGRITY


def cmd_reports(tk: Toolkit, args: argparse.Namespace) -> int:
    base = Path(args.output) if args.output else None
    reports = tk.list_reports(base)
    if not reports:
        _print(f"No reports found in {base or tk.paths.reports_dir}")
    for r in reports:
        counts = " ".join(f"{k[:4]}={v}" for k, v in r.severity_counts.items())
        _print(f"{r.started_at}  {r.assessment_id}  {r.hostname:<28} {r.mode:<5} {r.status:<10} {counts}")
        _print(f"    {r.folder}")
    return EXIT_OK


def cmd_build_manifest(tk: Toolkit, args: argparse.Namespace) -> int:
    path, digest = write_manifest(tk.paths.root, __version__)
    _print(f"Wrote {path}\nManifest SHA-256: {digest}\nRecord this value in the release notes / change ticket.")
    return EXIT_OK


def cmd_gui(tk: Toolkit, args: argparse.Namespace) -> int:
    try:
        from psatoolkit.gui.app import run_gui
    except ImportError as exc:
        _err(f"The GUI is unavailable ({exc}). Use the command-line interface, e.g. "
             "'audit --demo' or 'audit'. On Ubuntu desktops install python3-tk.")
        return EXIT_ERROR
    return run_gui(tk)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="PortableSecurityAudit",
                                description=f"{TOOL_NAME} {__version__} - authorized, read-only security assessment.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    p.add_argument("--config", type=Path, help="additional TOML configuration file")
    p.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command")

    sub.add_parser("gui", help="start the graphical dashboard (default)")
    sub.add_parser("info", help="show detected OS, privileges and the check plan")
    m = sub.add_parser("modules", help="list assessment modules")
    m.add_argument("-v", "--verbose", action="store_true")

    a = sub.add_parser("audit", help="run an authorized assessment")
    a.add_argument("--demo", action="store_true", help="safe demonstration with sample findings")
    a.add_argument("--modules", help="comma-separated module ids (default: all local modules)")
    a.add_argument("--output", help="report output directory (if the USB drive is read-only)")
    a.add_argument("--operator")
    a.add_argument("--organization")
    a.add_argument("--reference", help="authorization reference (ticket, engagement letter)")
    a.add_argument("--scope", help="scope statement")
    a.add_argument("--confirm", metavar="PHRASE",
                   help=f"non-interactive confirmation; must be exactly \"{CONFIRMATION_PHRASE}\"")
    a.add_argument("--target", action="append", help="authorized remote target (IP, CIDR or hostname)")
    a.add_argument("--target-ref", action="append", help="permission reference for the matching --target")

    s = sub.add_parser("preview-scan", help="dry run: show what a network scan would contact")
    s.add_argument("--target", action="append", required=True)
    s.add_argument("--ports")

    sub.add_parser("verify", help="verify tool integrity against checksums/manifest.json")
    vr = sub.add_parser("verify-report", help="verify a report.json integrity hash")
    vr.add_argument("path")
    vl = sub.add_parser("verify-log", help="verify an audit log hash chain")
    vl.add_argument("path")
    r = sub.add_parser("reports", help="list previous reports")
    r.add_argument("--output", help="directory to look in (default: USB reports/)")
    sub.add_parser("build-manifest", help="(release preparation) write checksums/manifest.json")
    return p


COMMANDS = {
    "gui": cmd_gui, "info": cmd_info, "modules": cmd_modules, "audit": cmd_audit,
    "preview-scan": cmd_preview_scan, "verify": cmd_verify, "verify-report": cmd_verify_report,
    "verify-log": cmd_verify_log, "reports": cmd_reports, "build-manifest": cmd_build_manifest,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "gui"
    try:
        tk = Toolkit(root=args.root, config_file=args.config)
    except ConfigError as exc:
        _err(f"Configuration error: {exc}")
        return EXIT_ERROR
    logs_dir = tk.paths.logs_dir
    setup_app_logging(logs_dir if logs_dir.parent.exists() else None, tk.config.log_level)
    if command == "gui" and args.command is None and not sys.stdin.isatty():
        parser.print_help()
        return EXIT_USAGE
    try:
        return COMMANDS[command](tk, args)
    except KeyboardInterrupt:
        _err("Interrupted.")
        return EXIT_STOPPED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

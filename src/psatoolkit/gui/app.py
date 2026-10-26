"""Tkinter dashboard for IT administrators.

The GUI is a thin layer over :class:`psatoolkit.core.session.Toolkit`; all
safety logic (authorization, gating, read-only policy, stop) lives in the core
so the GUI cannot bypass it. Assessments run in a worker thread and report
progress through a queue polled by the Tk event loop.
"""

from __future__ import annotations

import queue
import shutil
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Callable

from psatoolkit import TOOL_NAME, __version__
from psatoolkit.core.authorization import (AUTHORIZATION_NOTICE, AuthorizationError, AuthorizationRecord,
                                           create_authorization)
from psatoolkit.core.models import Severity
from psatoolkit.core.paths import OutputDirError
from psatoolkit.core.privileges import elevation_help
from psatoolkit.core.session import SessionOutcome, Toolkit
from psatoolkit.core.stop import StopToken
from psatoolkit.core.validation import ValidationError, parse_ports, parse_target
from psatoolkit.reporting.json_report import verify_json_report

SEVERITY_COLOURS = {
    Severity.CRITICAL: "#7f1d1d", Severity.HIGH: "#b91c1c", Severity.MEDIUM: "#b45309",
    Severity.LOW: "#1d4ed8", Severity.INFO: "#4b5563",
}
PAD = {"padx": 6, "pady": 4}


def _modal(parent: tk.Misc, title: str) -> tk.Toplevel:
    win = tk.Toplevel(parent)
    win.title(title)
    win.transient(parent)
    win.resizable(True, True)
    win.grab_set()
    return win


# --------------------------------------------------------------------------
# Dialogs
# --------------------------------------------------------------------------

class AuthorizationDialog:
    """Shows the notice and collects the operator's explicit confirmation."""

    def __init__(self, parent: tk.Misc, host: str, demo: bool, remote_targets: int) -> None:
        self.record: AuthorizationRecord | None = None
        self.host, self.demo = host, demo
        self.win = win = _modal(parent, "Authorization required")
        win.geometry("720x640")

        text = scrolledtext.ScrolledText(win, wrap="word", height=18)
        text.insert("1.0", AUTHORIZATION_NOTICE)
        if demo:
            text.insert("end", "\nDEMO MODE: no commands are executed and no network traffic is sent.\n")
        if remote_targets:
            text.insert("end", f"\nThe scope includes {remote_targets} authorized remote target(s).\n")
        text.configure(state="disabled")
        text.pack(fill="both", expand=True, **PAD)

        form = ttk.Frame(win)
        form.pack(fill="x", **PAD)
        self.vars: dict[str, tk.StringVar] = {}
        for row, (key, label) in enumerate((("operator", "Operator name *"),
                                            ("organization", "Organization"),
                                            ("reference", "Authorization reference * (ticket / letter)"),
                                            ("scope", "Scope statement"))):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", **PAD)
            var = tk.StringVar()
            var.trace_add("write", lambda *_: self._refresh())
            ttk.Entry(form, textvariable=var, width=55).grid(row=row, column=1, sticky="we", **PAD)
            self.vars[key] = var
        form.columnconfigure(1, weight=1)

        self.confirm = tk.BooleanVar(value=False)
        ttk.Checkbutton(win, variable=self.confirm, command=self._refresh,
                        text=f"I confirm that I am authorized to assess {host} and every listed target."
                        ).pack(anchor="w", **PAD)

        buttons = ttk.Frame(win)
        buttons.pack(fill="x", **PAD)
        self.start_btn = ttk.Button(buttons, text="Start assessment", command=self._accept, state="disabled")
        self.start_btn.pack(side="right", **PAD)
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right", **PAD)
        win.wait_window()

    def _refresh(self) -> None:
        ready = (self.confirm.get() and self.vars["operator"].get().strip()
                 and self.vars["reference"].get().strip())
        self.start_btn.configure(state="normal" if ready else "disabled")

    def _accept(self) -> None:
        try:
            self.record = create_authorization(
                operator=self.vars["operator"].get(), organization=self.vars["organization"].get(),
                engagement_reference=self.vars["reference"].get(), scope_statement=self.vars["scope"].get(),
                host=self.host, confirmed=self.confirm.get(), method="demo" if self.demo else "gui")
        except AuthorizationError as exc:
            messagebox.showerror("Authorization", str(exc), parent=self.win)
            return
        self.win.destroy()


class ModuleSelectionDialog:
    def __init__(self, parent: tk.Misc, toolkit: Toolkit, selected: set[str]) -> None:
        self.result: set[str] | None = None
        win = self.win = _modal(parent, "Select assessment modules")
        ttk.Label(win, text="Modules available for this operating system:").pack(anchor="w", **PAD)
        self.vars: dict[str, tk.BooleanVar] = {}
        for module in toolkit.available_modules():
            if module.category == "network":
                continue  # run via 'Run Network Assessment'
            var = tk.BooleanVar(value=module.module_id in selected)
            admin = sum(c.requires_admin for c in module.checks)
            note = f"  ({len(module.checks)} checks, {admin} need admin)" if admin else f"  ({len(module.checks)} checks)"
            ttk.Checkbutton(win, text=module.name + note, variable=var).pack(anchor="w", padx=18, pady=2)
            self.vars[module.module_id] = var
        unavailable = toolkit.unavailable_modules()
        if unavailable:
            ttk.Label(win, text="Not available on this system:").pack(anchor="w", **PAD)
            for module, reason in unavailable:
                ttk.Checkbutton(win, text=f"{module.name} - {reason}", state="disabled").pack(anchor="w", padx=18)
        buttons = ttk.Frame(win)
        buttons.pack(fill="x", **PAD)
        ttk.Button(buttons, text="OK", command=self._ok).pack(side="right", **PAD)
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right", **PAD)
        win.wait_window()

    def _ok(self) -> None:
        chosen = {k for k, v in self.vars.items() if v.get()}
        if not chosen:
            messagebox.showwarning("Modules", "Select at least one module.", parent=self.win)
            return
        self.result = chosen
        self.win.destroy()


class RemoteTargetDialog:
    """Manage the explicit list of authorized remote targets."""

    def __init__(self, parent: tk.Misc, toolkit: Toolkit) -> None:
        self.toolkit = toolkit
        win = self.win = _modal(parent, "Authorized remote targets")
        win.geometry("700x460")
        ttk.Label(win, wraplength=660, text=(
            "Add only hosts or ranges you have written permission to assess. Each entry needs its own "
            f"permission reference. Limits: {toolkit.config.network.max_hosts_per_target} hosts per entry, "
            f"{toolkit.config.network.max_total_hosts} in total. Wildcards and lists are not accepted."
        )).pack(anchor="w", **PAD)

        self.listbox = tk.Listbox(win, height=8)
        self.listbox.pack(fill="both", expand=True, **PAD)

        form = ttk.Frame(win)
        form.pack(fill="x", **PAD)
        self.target, self.ref = tk.StringVar(), tk.StringVar()
        ttk.Label(form, text="Target (IP, CIDR or hostname)").grid(row=0, column=0, sticky="w", **PAD)
        ttk.Entry(form, textvariable=self.target, width=40).grid(row=0, column=1, sticky="we", **PAD)
        ttk.Label(form, text="Permission reference").grid(row=1, column=0, sticky="w", **PAD)
        ttk.Entry(form, textvariable=self.ref, width=40).grid(row=1, column=1, sticky="we", **PAD)
        self.confirm = tk.BooleanVar(value=False)
        ttk.Checkbutton(form, variable=self.confirm,
                        text="I confirm written permission to assess this target").grid(
            row=2, column=0, columnspan=2, sticky="w", **PAD)
        self.preview = ttk.Label(form, text="")
        self.preview.grid(row=3, column=0, columnspan=2, sticky="w", **PAD)
        form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(win)
        buttons.pack(fill="x", **PAD)
        ttk.Button(buttons, text="Preview", command=self._preview).pack(side="left", **PAD)
        ttk.Button(buttons, text="Add target", command=self._add).pack(side="left", **PAD)
        ttk.Button(buttons, text="Remove selected", command=self._remove).pack(side="left", **PAD)
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right", **PAD)
        self._reload()
        win.wait_window()

    def _reload(self) -> None:
        self.listbox.delete(0, "end")
        for t in self.toolkit.scope.targets:
            self.listbox.insert("end", f"{t.target.raw}  ({t.target.host_count} host(s))  ref: {t.permission_reference}")

    def _preview(self) -> None:
        try:
            target = parse_target(self.target.get(), self.toolkit.config.network.max_hosts_per_target)
            self.preview.configure(text=f"Valid {target.kind}: {target.host_count} host(s). No traffic sent.")
        except ValidationError as exc:
            self.preview.configure(text=f"Invalid: {exc}")

    def _add(self) -> None:
        try:
            self.toolkit.scope.add(self.target.get(), self.ref.get(), self.confirm.get())
        except AuthorizationError as exc:
            messagebox.showerror("Target not added", str(exc), parent=self.win)
            return
        self.target.set("")
        self.confirm.set(False)
        self.preview.configure(text="")
        self._reload()

    def _remove(self) -> None:
        for index in reversed(self.listbox.curselection()):
            self.toolkit.scope.remove(self.toolkit.scope.targets[index].target.raw)
        self._reload()


class ReportsDialog:
    def __init__(self, parent: tk.Misc, toolkit: Toolkit, base: Path, on_export: Callable[[Path], None]) -> None:
        win = self.win = _modal(parent, "Previous reports")
        win.geometry("900x420")
        self.reports = toolkit.list_reports(base)
        cols = ("started", "id", "host", "mode", "status", "findings")
        tree = self.tree = ttk.Treeview(win, columns=cols, show="headings", selectmode="browse")
        for col, width in zip(cols, (160, 220, 180, 60, 80, 180)):
            tree.heading(col, text=col.capitalize())
            tree.column(col, width=width, anchor="w")
        for i, r in enumerate(self.reports):
            counts = " ".join(f"{k[0].upper()}:{v}" for k, v in r.severity_counts.items())
            tree.insert("", "end", iid=str(i), values=(r.started_at, r.assessment_id, r.hostname, r.mode,
                                                       r.status, counts))
        tree.pack(fill="both", expand=True, **PAD)
        tree.bind("<Double-1>", lambda _e: self._open())
        if not self.reports:
            ttk.Label(win, text=f"No reports found in {base}").pack(**PAD)
        buttons = ttk.Frame(win)
        buttons.pack(fill="x", **PAD)
        ttk.Button(buttons, text="Open", command=self._open).pack(side="left", **PAD)
        ttk.Button(buttons, text="Verify integrity", command=self._verify).pack(side="left", **PAD)
        ttk.Button(buttons, text="Export...", command=lambda: self._selected() and on_export(self._selected())
                   ).pack(side="left", **PAD)
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right", **PAD)

    def _selected(self) -> Path | None:
        sel = self.tree.selection()
        return self.reports[int(sel[0])].folder if sel else None

    def _open(self) -> None:
        folder = self._selected()
        if folder:
            webbrowser.open((folder / "report.json").as_uri())

    def _verify(self) -> None:
        folder = self._selected()
        if folder:
            res = verify_json_report(folder / "report.json")
            (messagebox.showinfo if res.ok else messagebox.showerror)("Report integrity", res.message, parent=self.win)


# --------------------------------------------------------------------------
# Main dashboard
# --------------------------------------------------------------------------

class Dashboard:
    def __init__(self, root: tk.Tk, toolkit: Toolkit) -> None:
        self.root, self.tk = root, toolkit
        self.events: queue.Queue[dict[str, Any]] = queue.Queue()
        self.stop_token: StopToken | None = None
        self.worker: threading.Thread | None = None
        self.last_outcome: SessionOutcome | None = None
        self.selected = {m.module_id for m in toolkit.available_modules() if m.category == "local"}
        self.output_dir: Path | None = None

        root.title(f"{TOOL_NAME} {__version__}")
        root.geometry("1100x720")
        root.minsize(900, 600)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build()
        self._init_output_dir()
        self._log(f"{TOOL_NAME} {__version__} ready. Root: {toolkit.paths.root}")
        if not toolkit.elevated:
            self._log("Not elevated: privileged checks will be skipped. " + elevation_help(toolkit.os_info.family))
        for warning in toolkit.config.warnings:
            self._log(f"Configuration warning: {warning}")
        root.after(150, self._poll)

    # -- layout ----------------------------------------------------------
    def _build(self) -> None:
        style = ttk.Style(self.root)
        style.configure("Title.TLabel", font=("TkDefaultFont", 14, "bold"))
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True)

        side = ttk.Frame(main)
        side.pack(side="left", fill="y", padx=8, pady=8)
        ttk.Label(side, text="Controls", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
        self.buttons: dict[str, ttk.Button] = {}
        for key, label, cmd in (
            ("local", "1. Start Local Security Audit", self.start_local),
            ("targets", "2. Configure Authorized Remote Target", self.configure_targets),
            ("modules", "3. Select Assessment Modules", self.select_modules),
            ("network", "4. Run Network Assessment", self.start_network),
            ("reports", "5. View Previous Reports", self.view_reports),
            ("export", "6. Export Report", self.export_last),
            ("verify", "7. Verify Tool Integrity", self.verify_integrity),
            ("stop", "8. STOP ASSESSMENT", self.stop),
        ):
            btn = ttk.Button(side, text=label, command=cmd, width=36)
            btn.pack(fill="x", pady=3)
            self.buttons[key] = btn
        self.buttons["stop"].configure(state="disabled")
        ttk.Separator(side).pack(fill="x", pady=8)
        self.demo = tk.BooleanVar(value=False)
        ttk.Checkbutton(side, text="Demo mode (sample data, no scanning)", variable=self.demo).pack(anchor="w")
        ttk.Button(side, text="Change output folder...", command=self.choose_output_dir).pack(fill="x", pady=3)
        self.out_label = ttk.Label(side, text="", wraplength=260)
        self.out_label.pack(anchor="w", pady=3)

        body = ttk.Frame(main)
        body.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        host = self.tk.host_info()
        info = ttk.LabelFrame(body, text="Target system")
        info.pack(fill="x")
        self.info_vars: dict[str, tk.StringVar] = {}
        rows = (("Hostname", host.hostname),
                ("Operating system", f"{host.os_name} (build {host.os_build}, {host.architecture})"),
                ("Support level", host.support_level),
                ("Privileges", "Administrator/root" if host.elevated else "Standard user (limited checks)"),
                ("Selected modules", ""), ("Assessment ID", "-"), ("Started", "-"), ("Completed", "-"),
                ("Status", "Idle"))
        for r, (label, value) in enumerate(rows):
            ttk.Label(info, text=label + ":").grid(row=r // 2, column=(r % 2) * 2, sticky="w", **PAD)
            var = tk.StringVar(value=value)
            ttk.Label(info, textvariable=var, wraplength=360).grid(row=r // 2, column=(r % 2) * 2 + 1, sticky="w", **PAD)
            self.info_vars[label] = var
        self._update_selected_label()

        prog = ttk.LabelFrame(body, text="Progress")
        prog.pack(fill="x", pady=6)
        self.progress = ttk.Progressbar(prog, mode="determinate", maximum=1)
        self.progress.pack(fill="x", **PAD)
        self.current = ttk.Label(prog, text="")
        self.current.pack(anchor="w", **PAD)

        sev = ttk.LabelFrame(body, text="Findings by severity")
        sev.pack(fill="x")
        self.sev_vars: dict[str, tk.StringVar] = {}
        for i, s in enumerate(Severity.ordered()):
            var = tk.StringVar(value="0")
            box = tk.Frame(sev, bg=SEVERITY_COLOURS[s], padx=12, pady=6)
            box.grid(row=0, column=i, padx=6, pady=6, sticky="we")
            tk.Label(box, textvariable=var, fg="white", bg=SEVERITY_COLOURS[s],
                     font=("TkDefaultFont", 16, "bold")).pack()
            tk.Label(box, text=s.value.capitalize(), fg="white", bg=SEVERITY_COLOURS[s]).pack()
            sev.columnconfigure(i, weight=1)
            self.sev_vars[s.value] = var

        logf = ttk.LabelFrame(body, text="Status and errors")
        logf.pack(fill="both", expand=True, pady=6)
        self.logbox = scrolledtext.ScrolledText(logf, height=12, state="disabled", wrap="word")
        self.logbox.pack(fill="both", expand=True, **PAD)
        self.open_btn = ttk.Button(body, text="Open Generated Report", command=self.open_report, state="disabled")
        self.open_btn.pack(anchor="e")

    # -- helpers ---------------------------------------------------------
    def _log(self, text: str) -> None:
        self.logbox.configure(state="normal")
        self.logbox.insert("end", f"[{datetime.now():%H:%M:%S}] {text}\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _update_selected_label(self) -> None:
        names = {m.module_id: m.name for m in self.tk.modules}
        self.info_vars["Selected modules"].set(", ".join(names[m] for m in sorted(self.selected)) or "none")

    def _init_output_dir(self) -> None:
        try:
            self.output_dir = self.tk.resolve_output_dir()
        except OutputDirError as exc:
            messagebox.showwarning("Output folder", f"{exc}\n\nPlease choose a writable folder for reports.")
            self.choose_output_dir()
        self.out_label.configure(text=f"Reports: {self.output_dir or 'NOT SET'}")

    def choose_output_dir(self) -> None:
        chosen = filedialog.askdirectory(title="Choose report output folder")
        if not chosen:
            return
        try:
            self.output_dir = self.tk.resolve_output_dir(chosen)
            self.out_label.configure(text=f"Reports: {self.output_dir}")
        except OutputDirError as exc:
            messagebox.showerror("Output folder", str(exc))

    def _busy(self, running: bool) -> None:
        for key, btn in self.buttons.items():
            btn.configure(state=("normal" if running else "disabled") if key == "stop"
                          else ("disabled" if running and key in ("local", "network", "targets", "modules") else "normal"))

    # -- controls --------------------------------------------------------
    def start_local(self) -> None:
        demo = self.demo.get()
        selected = [m.module_id for m in self.tk.available_modules(demo=True)] if demo else sorted(self.selected)
        self._start(selected, demo)

    def start_network(self) -> None:
        modules = self.tk.network_modules()
        if not modules:
            messagebox.showinfo("Network assessment",
                                "No network assessment module is installed in this build "
                                "(Module D is delivered in Phase 4). Configured targets are kept.")
            return
        if not self.tk.scope.targets:
            messagebox.showwarning("Network assessment", "Configure at least one authorized remote target first.")
            return
        ports = parse_ports(self.tk.config.network.default_ports, self.tk.config.network.max_ports)
        p = self.tk.scope.preview(ports, self.tk.config.network.rate_limit_per_second)
        if not messagebox.askyesno("Dry-run preview", (
                f"Targets: {len(p['targets'])}   Hosts: {p['total_hosts']}\n"
                f"Ports per host: {p['ports_per_host']}   Connection attempts: {p['total_connection_attempts']}\n"
                f"Rate limit: {p['rate_limit_per_second']}/s   Minimum duration: "
                f"{p['estimated_minimum_duration_seconds']}s\n\nNo traffic has been sent yet. Proceed?")):
            return
        self._start([m.module_id for m in modules], demo=False)

    def _start(self, selected: list[str], demo: bool) -> None:
        if self.worker and self.worker.is_alive():
            return
        if self.output_dir is None:
            self.choose_output_dir()
            if self.output_dir is None:
                return
        dialog = AuthorizationDialog(self.root, self.tk.host_info(demo).hostname, demo,
                                     0 if demo else len(self.tk.scope.targets))
        if dialog.record is None:
            self._log("Assessment not started: authorization was not confirmed.")
            return
        host = self.tk.host_info(demo)
        self.info_vars["Hostname"].set(host.hostname)
        self.info_vars["Operating system"].set(f"{host.os_name} (build {host.os_build}, {host.architecture})")
        names = {m.module_id: m.name for m in self.tk.modules}
        self.info_vars["Selected modules"].set(", ".join(names[m] for m in selected))
        for var in self.sev_vars.values():
            var.set("0")
        self.progress.configure(value=0, maximum=1)
        self.info_vars["Started"].set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.info_vars["Completed"].set("-")
        self.info_vars["Status"].set("Running" + (" (demo)" if demo else ""))
        self.open_btn.configure(state="disabled")
        self.stop_token = StopToken()
        self._busy(True)
        record, out, stop = dialog.record, str(self.output_dir), self.stop_token

        def work() -> None:
            try:
                outcome = self.tk.run_assessment(record, selected, demo=demo, output_override=out, stop=stop,
                                                 progress=self.events.put)
                self.events.put({"type": "outcome", "outcome": outcome})
            except Exception as exc:  # noqa: BLE001 - shown to the operator
                self.events.put({"type": "failed", "error": f"{type(exc).__name__}: {exc}"})

        self.worker = threading.Thread(target=work, name="assessment", daemon=True)
        self.worker.start()

    def stop(self) -> None:
        if self.stop_token and not self.stop_token.stopped:
            self.stop_token.stop("Operator pressed STOP in the GUI")
            self._log("EMERGENCY STOP requested - terminating running checks...")
            self.info_vars["Status"].set("Stopping...")

    def configure_targets(self) -> None:
        RemoteTargetDialog(self.root, self.tk)
        self._log(f"Authorized remote scope: {len(self.tk.scope.targets)} target(s), "
                  f"{self.tk.scope.total_hosts} host(s).")

    def select_modules(self) -> None:
        dialog = ModuleSelectionDialog(self.root, self.tk, self.selected)
        if dialog.result is not None:
            self.selected = dialog.result
            self._update_selected_label()

    def view_reports(self) -> None:
        ReportsDialog(self.root, self.tk, self.output_dir or self.tk.paths.reports_dir, self._export_folder)

    def export_last(self) -> None:
        if not self.last_outcome or not self.last_outcome.report_folder:
            messagebox.showinfo("Export report", "No report from this session. Use 'View Previous Reports' "
                                                 "to export an earlier one.")
            return
        self._export_folder(self.last_outcome.report_folder)

    def _export_folder(self, folder: Path) -> None:
        dest = filedialog.askdirectory(title="Export report to...")
        if not dest:
            return
        target = Path(dest) / folder.name
        try:
            shutil.copytree(folder, target)
        except (OSError, shutil.Error) as exc:
            messagebox.showerror("Export report", f"Export failed: {exc}")
            return
        self._log(f"Report exported to {target}")
        messagebox.showinfo("Export report", f"Report copied to:\n{target}")

    def verify_integrity(self) -> None:
        report = self.tk.verify_integrity()
        self._log(report.summary())
        (messagebox.showinfo if report.ok else messagebox.showwarning)("Tool integrity", report.summary())

    def open_report(self) -> None:
        if self.last_outcome and self.last_outcome.report_files:
            webbrowser.open(self.last_outcome.report_files[0].as_uri())

    # -- event loop ------------------------------------------------------
    def _poll(self) -> None:
        try:
            while True:
                self._handle(self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(150, self._poll)

    def _handle(self, ev: dict[str, Any]) -> None:
        kind = ev.get("type")
        if kind == "start":
            self.info_vars["Assessment ID"].set(ev["assessment_id"])
            self.progress.configure(maximum=max(ev["total"], 1), value=0)
            self._log(f"Assessment {ev['assessment_id']} started ({ev['total']} checks).")
        elif kind == "check_start":
            self.current.configure(text=f"Running {ev['check_id']}: {ev['title']}")
        elif kind == "check_end":
            self.progress.configure(value=ev["index"])
            for sev, count in ev["severity_counts"].items():
                self.sev_vars[sev].set(str(count))
            line = f"{ev['check_id']}: {ev['status']} ({ev['findings']} finding(s))"
            self._log(line + (f" - {ev['message']}" if ev.get("message") else ""))
        elif kind == "outcome":
            outcome: SessionOutcome = ev["outcome"]
            self.last_outcome = outcome
            self.info_vars["Completed"].set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.info_vars["Status"].set(outcome.result.status.capitalize())
            self.current.configure(text="")
            for lim in outcome.result.limitations:
                self._log(f"Limitation ({lim.category}): {lim.description}")
            if outcome.report_error:
                self._log(outcome.report_error)
            for path in outcome.report_files:
                self._log(f"Report written: {path}")
                self.open_btn.configure(state="normal")
            self._busy(False)
        elif kind == "failed":
            self.info_vars["Status"].set("Failed")
            self._log(f"Assessment failed: {ev['error']}")
            self._busy(False)

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Exit", "An assessment is running. Stop it and exit?"):
                return
            self.stop()
            self.worker.join(5)
        self.root.destroy()


def run_gui(toolkit: Toolkit) -> int:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Cannot open a display ({exc}). Use the CLI instead: 'audit --help'.")
        return 1
    Dashboard(root, toolkit)
    root.mainloop()
    return 0

"""GUI smoke test. Skipped when Tkinter or a display is unavailable.

Run headless on Linux with:  xvfb-run -a python -m pytest tests/test_gui_smoke.py
"""

import os
import sys

import pytest

tk = pytest.importorskip("tkinter")
if not sys.platform.startswith("win") and not os.environ.get("DISPLAY"):
    pytest.skip("no display (use xvfb-run)", allow_module_level=True)


def test_demo_assessment_through_gui(portable_root, monkeypatch):
    from psatoolkit.core.session import Toolkit
    from psatoolkit.gui import app

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk cannot start: {exc}")
    dash = app.Dashboard(root, Toolkit(root=portable_root, elevated=False))
    dash.demo.set(True)
    observed = {}
    original = app.AuthorizationDialog.__init__

    def drive(self, parent, host, demo, n):
        def fill():
            observed["initially_disabled"] = str(self.start_btn["state"]) == "disabled"
            self.vars["operator"].set("GUI Tester")
            self.vars["reference"].set("CHG-GUI")
            observed["disabled_without_checkbox"] = str(self.start_btn["state"]) == "disabled"
            self.confirm.set(True)
            self._refresh()
            self.start_btn.invoke()
        parent.after(200, fill)
        original(self, parent, host, demo, n)

    monkeypatch.setattr(app.AuthorizationDialog, "__init__", drive)

    def wait_for_outcome(tries=[0]):
        tries[0] += 1
        if dash.last_outcome is not None or tries[0] > 100:
            root.quit()
        else:
            root.after(100, wait_for_outcome)

    root.after(100, dash.start_local)
    root.after(300, wait_for_outcome)
    root.mainloop()
    try:
        assert observed == {"initially_disabled": True, "disabled_without_checkbox": True}
        assert dash.last_outcome is not None
        assert dash.last_outcome.result.mode == "demo"
        assert dash.sev_vars["high"].get() == "3" and dash.sev_vars["critical"].get() == "1"
        assert dash.info_vars["Hostname"].get() == "demo-host.example.internal"
        assert str(dash.buttons["stop"]["state"]) == "disabled"
    finally:
        root.destroy()


def test_authorization_cancel_does_not_start(portable_root, monkeypatch):
    from psatoolkit.core.session import Toolkit
    from psatoolkit.gui import app

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk cannot start: {exc}")
    dash = app.Dashboard(root, Toolkit(root=portable_root, elevated=False))
    monkeypatch.setattr(app, "AuthorizationDialog", lambda *a, **k: type("D", (), {"record": None})())
    dash.start_local()
    assert dash.worker is None
    root.destroy()


def test_module_dialog_imports_baseline(portable_root, monkeypatch):
    from conftest import REPO_ROOT
    from psatoolkit.core.session import Toolkit
    from psatoolkit.gui import app

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk cannot start: {exc}")
    toolkit = Toolkit(root=portable_root, elevated=False)
    example = REPO_ROOT / "baselines" / "examples" / "example-ubuntu-server.json"
    messages = []
    monkeypatch.setattr(app.filedialog, "askopenfilename", lambda **k: str(example))
    monkeypatch.setattr(app.messagebox, "showinfo", lambda *a, **k: messages.append(("info", a)))
    monkeypatch.setattr(app.messagebox, "showerror", lambda *a, **k: messages.append(("error", a)))
    original = app.ModuleSelectionDialog.__init__

    def drive(self, parent, tk_, selected):
        def act():
            self._import()          # first import succeeds
            self._import()          # second import is refused (already exists)
            self.win.destroy()
        parent.after(200, act)
        original(self, parent, tk_, selected)

    monkeypatch.setattr(app.ModuleSelectionDialog, "__init__", drive)
    dash = app.Dashboard(root, toolkit)
    names = {m.module_id for m in toolkit.available_modules()}
    assert "baselines" in names and "baselines" in dash.selected
    app.ModuleSelectionDialog(root, toolkit, dash.selected)
    root.destroy()
    assert [m[0] for m in messages] == ["info", "error"]
    assert (portable_root / "baselines" / "Example_Ubuntu_Server_Baseline.json").exists()

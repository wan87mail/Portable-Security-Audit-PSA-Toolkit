import time

import pytest

from conftest import LINUX_OS, LONG_COMMAND, LONG_COMMAND_POLICY_RULES, WINDOWS_OS
from psatoolkit.core.authorization import AuthorizationError, TargetScope
from psatoolkit.core.engine import AssessmentEngine, Check, Module, SkipCheck, build_host_info
from psatoolkit.core.logging_setup import AuditLog
from psatoolkit.core.models import CheckStatus, Confidence, FindingStatus, Severity
from psatoolkit.core.safe_exec import CommandRunner, ReadOnlyPolicy
from psatoolkit.core.stop import StopToken


def make_check(check_id, run=None, **attrs):
    def default_run(self, ctx):
        return [ctx.finding(self, title="t", severity=Severity.LOW, status=FindingStatus.CONFIRMED,
                            component="c", description="d", impact="i", confidence=Confidence.HIGH,
                            remediation="r", verification="v", severity_rationale="s",
                            evidence=[ctx.evidence("e", "src", {"password": "hunter2", "line": "token=abc123"})])]
    cls = type(f"C_{check_id}", (Check,), {"check_id": check_id, "title": check_id,
                                           "supported_os": frozenset({"linux", "windows"}),
                                           "run": run or default_run, **attrs})
    return cls()


def run_engine(checks, config, authorization, os_info=LINUX_OS, elevated=True, scope=None, stop=None,
               runner=None, events=None):
    engine = AssessmentEngine([Module("m", "M", "", "local", checks)], config)
    stop = stop or StopToken()
    runner = runner or CommandRunner(stop_token=stop)
    host = build_host_info(os_info, "test-host", elevated)
    return engine.run(authorization=authorization, selected=["m"], host=host, os_info=os_info, runner=runner,
                      audit=AuditLog(None), scope=scope, stop=stop,
                      progress=(events.append if events is not None else None))


def statuses(result):
    return {c.check_id: c.status for c in result.checks}


def test_requires_authorization(config):
    engine = AssessmentEngine([Module("m", "M", "", "local", [make_check("A")])], config)
    with pytest.raises(AuthorizationError):
        engine.run(authorization=None, selected=["m"], host=build_host_info(LINUX_OS, "h", True),
                   os_info=LINUX_OS, runner=CommandRunner(), audit=AuditLog(None))


def test_findings_get_ids_and_redacted_evidence(config, authorization):
    result = run_engine([make_check("A")], config, authorization)
    f = result.findings[0]
    assert f.finding_id == "A-01" and f.check_id == "A" and f.affected_host == "test-host"
    assert f.evidence[0].data["password"] == "[REDACTED]"
    assert "abc123" not in f.evidence[0].data["line"]
    assert result.status == "completed"


def test_failing_check_does_not_stop_assessment(config, authorization):
    def boom(self, ctx):
        raise RuntimeError("kaput password=secret1")
    result = run_engine([make_check("A", boom), make_check("B")], config, authorization)
    assert statuses(result) == {"A": CheckStatus.ERROR, "B": CheckStatus.FINDINGS}
    assert "secret1" not in result.checks[0].message
    assert any(l.category == "error" and l.check_id == "A" for l in result.limitations)


def test_check_timeout(config, authorization):
    config.execution.check_timeout_seconds = 5
    slow = make_check("SLOW", lambda self, ctx: time.sleep(3) or [], timeout_seconds=0.3)
    started = time.monotonic()
    result = run_engine([slow, make_check("B")], config, authorization)
    assert time.monotonic() - started < 2.5
    assert statuses(result)["SLOW"] == CheckStatus.TIMEOUT
    assert statuses(result)["B"] == CheckStatus.FINDINGS
    assert any(l.category == "timeout" for l in result.limitations)


def test_privileged_check_skipped_with_explanation(config, authorization):
    check = make_check("ADM", requires_admin=True, admin_reason="reads sshd -T")
    result = run_engine([check], config, authorization, elevated=False)
    cr = result.checks[0]
    assert cr.status == CheckStatus.SKIPPED and "reads sshd -T" in cr.message and "sudo" in cr.message
    assert result.limitations[0].category == "privilege"
    assert run_engine([check], config, authorization, elevated=True).checks[0].status == CheckStatus.FINDINGS


def test_missing_tool_skipped(config, authorization):
    check = make_check("T", required_tools=("psa-no-such-tool",))
    result = run_engine([check], config, authorization)
    assert result.checks[0].status == CheckStatus.SKIPPED
    assert result.limitations[0].category == "dependency"


def test_os_filtering(config, authorization):
    win_only = make_check("W", supported_os=frozenset({"windows"}))
    result = run_engine([win_only], config, authorization, os_info=LINUX_OS)
    assert result.checks[0].status == CheckStatus.NOT_APPLICABLE
    assert run_engine([win_only], config, authorization, os_info=WINDOWS_OS).checks[0].status == CheckStatus.FINDINGS


def test_network_check_requires_scope(config, authorization):
    net = make_check("NET", requires_network=True)
    assert run_engine([net], config, authorization).checks[0].status == CheckStatus.SKIPPED
    scope = TargetScope()
    scope.add("10.0.0.5", "REF", True)
    assert run_engine([net], config, authorization, scope=scope).checks[0].status == CheckStatus.FINDINGS


def test_internet_check_blocked_offline(config, authorization):
    check = make_check("NET2", requires_internet=True)
    config.offline_mode = True
    assert run_engine([check], config, authorization).checks[0].status == CheckStatus.SKIPPED


def test_skipcheck_from_inside_check(config, authorization):
    def skip(self, ctx):
        raise SkipCheck("file not readable", "privilege")
    result = run_engine([make_check("S", skip)], config, authorization)
    assert result.checks[0].status == CheckStatus.SKIPPED
    assert result.limitations[0].category == "privilege"


def test_invalid_return_value_is_error(config, authorization):
    result = run_engine([make_check("BAD", lambda self, ctx: ["not a finding"])], config, authorization)
    assert result.checks[0].status == CheckStatus.ERROR


def test_emergency_stop_cancels_remaining_checks(config, authorization):
    stop = StopToken()

    def stopper(self, ctx):
        ctx.stop.stop("test stop")
        return []
    result = run_engine([make_check("A", stopper), make_check("B"), make_check("C")], config, authorization,
                        stop=stop)
    assert result.status == "stopped"
    assert statuses(result)["B"] == CheckStatus.CANCELLED and statuses(result)["C"] == CheckStatus.CANCELLED


def test_stop_interrupts_running_subprocess(config, authorization):
    stop = StopToken()
    runner = CommandRunner(stop_token=stop, policy=ReadOnlyPolicy(rules=dict(LONG_COMMAND_POLICY_RULES)))

    def long_cmd(self, ctx):
        ctx.runner.run(LONG_COMMAND)
        return []
    import threading
    threading.Timer(0.3, stop.stop).start()
    started = time.monotonic()
    result = run_engine([make_check("LONG", long_cmd)], config, authorization, stop=stop, runner=runner)
    assert time.monotonic() - started < 6
    assert result.status == "stopped"


def test_progress_events(config, authorization):
    events = []
    run_engine([make_check("A"), make_check("B")], config, authorization, events=events)
    kinds = [e["type"] for e in events]
    assert kinds[0] == "start" and kinds[-1] == "end"
    assert kinds.count("check_end") == 2


def test_duplicate_ids_rejected(config):
    with pytest.raises(ValueError):
        AssessmentEngine([Module("m", "M", "", "local", [make_check("A"), make_check("A")])], config)


def test_unknown_module_rejected(config, authorization):
    engine = AssessmentEngine([Module("m", "M", "", "local", [make_check("A")])], config)
    with pytest.raises(ValueError):
        engine.plan(["nope"], LINUX_OS, True, CommandRunner(), TargetScope())


def test_demo_and_live_modules_cannot_mix(config):
    engine = AssessmentEngine([Module("m", "M", "", "local", [make_check("A")]),
                               Module("d", "D", "", "demo", [make_check("B", demo_safe=True)])], config)
    with pytest.raises(ValueError):
        engine.plan(["m"], LINUX_OS, True, CommandRunner(), TargetScope(), demo=True)
    with pytest.raises(ValueError):
        engine.plan(["d"], LINUX_OS, True, CommandRunner(), TargetScope(), demo=False)

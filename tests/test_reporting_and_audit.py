import json

from conftest import LINUX_OS
from psatoolkit.core.engine import AssessmentEngine, build_host_info
from psatoolkit.core.logging_setup import AuditLog, verify_audit_log
from psatoolkit.core.redaction import redact, redact_text
from psatoolkit.core.safe_exec import CommandRunner
from psatoolkit.core.session import DEMO_OS
from psatoolkit.modules import demo
from psatoolkit.reporting.json_report import report_folder, verify_json_report, write_json_report


def demo_result(config, authorization):
    engine = AssessmentEngine([demo.build_module()], config)
    runner = CommandRunner(demo=True)
    return engine.run(authorization=authorization, selected=["demo"], host=build_host_info(DEMO_OS, "demo", False),
                      os_info=DEMO_OS, runner=runner, audit=AuditLog(None), demo=True)


def test_report_written_and_verifiable(tmp_path, config, authorization):
    result = demo_result(config, authorization)
    folder = report_folder(tmp_path, result)
    path = write_json_report(result, folder)
    doc = json.loads(path.read_text())
    assert doc["assessment"]["assessment_id"] == result.assessment_id
    assert doc["tool"]["version"]
    assert doc["integrity"]["algorithm"] == "sha256"
    sev = [f["severity"] for f in doc["findings"]]
    order = ["critical", "high", "medium", "low", "informational"]
    assert sev == sorted(sev, key=order.index)
    for f in doc["findings"]:
        for key in ("finding_id", "title", "severity", "affected_host", "affected_component", "description",
                    "evidence", "impact", "confidence", "references", "remediation", "verification",
                    "manual_validation_required", "severity_rationale", "status"):
            assert key in f
    assert doc["assessment"]["limitations"]
    assert verify_json_report(path).ok


def test_canonical_hash_survives_reformatting_but_detects_edits(tmp_path, config, authorization):
    result = demo_result(config, authorization)
    path = write_json_report(result, report_folder(tmp_path, result))
    doc = json.loads(path.read_text())
    path.write_text(json.dumps(doc, indent=None))     # reformat only
    v = verify_json_report(path)
    assert v.canonical_ok and v.file_hash_ok is False  # file bytes changed, content did not
    doc["findings"][0]["severity"] = "low"            # tamper with content
    path.write_text(json.dumps(doc))
    assert not verify_json_report(path).canonical_ok


def test_report_contains_no_secrets(tmp_path, config, authorization):
    result = demo_result(config, authorization)
    result.checks[0].findings[0].evidence[0].data = {"token": "ghp_" + "a" * 36, "note": "password: hunter2"}
    path = write_json_report(result, report_folder(tmp_path, result))
    text = path.read_text()
    assert "hunter2" not in text and "ghp_aaaa" not in text


def test_redaction_patterns():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIabc" not in redact_text(pem)
    assert "s3cr3t" not in redact_text("db_password = 's3cr3t'")
    assert "abcdefghijk" not in redact_text("Authorization: Bearer abcdefghijk.lmnop")
    assert "$6$" not in redact_text("root:$6$saltsalt$hashhashhashhash:19000:0:99999:7:::")
    assert "AKIAABCDEFGHIJKLMNOP" not in redact_text("key AKIAABCDEFGHIJKLMNOP")
    # configuration keywords must survive
    assert redact_text("PasswordAuthentication no") == "PasswordAuthentication no"
    assert redact({"api_key": "x1", "nested": [{"secret": "y"}], "n": 3}) == \
        {"api_key": "[REDACTED]", "nested": [{"secret": "[REDACTED]"}], "n": 3}


def test_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, "PSA-TEST")
    for i in range(5):
        log.write("event", n=i, password="hunter2")
    ok, problems = verify_audit_log(path)
    assert ok, problems
    assert "hunter2" not in path.read_text()

    lines = path.read_text().splitlines()
    edited = json.loads(lines[2])
    edited["details"]["n"] = 99
    lines[2] = json.dumps(edited)
    path.write_text("\n".join(lines) + "\n")
    ok, problems = verify_audit_log(path)
    assert not ok and any("line 3" in p for p in problems)

    lines.pop(1)  # delete an entry
    path.write_text("\n".join(lines) + "\n")
    assert not verify_audit_log(path)[0]


def test_live_engine_records_host(tmp_path, config, authorization):
    from psatoolkit.modules import system_info
    engine = AssessmentEngine([system_info.build_module()], config)
    result = engine.run(authorization=authorization, selected=["system_info"],
                        host=build_host_info(LINUX_OS, "srv01", False), os_info=LINUX_OS,
                        runner=CommandRunner(), audit=AuditLog(None))
    assert result.findings[0].affected_host == "srv01"
    assert result.status == "completed"

import json

from src.audit import record_audit_event


def test_record_audit_event_writes_jsonl_and_redacts_secrets(tmp_path):
    path = record_audit_event(
        "command_execute",
        {"command": "echo ok", "api_key": "secret-value"},
        tmp_path,
    )

    event = json.loads(path.read_text(encoding="utf-8"))

    assert event["type"] == "command_execute"
    assert event["details"]["command"] == "echo ok"
    assert event["details"]["api_key"] == "[redacted]"
    assert path.stat().st_mode & 0o777 == 0o600

from datetime import datetime, timezone

from src.findings import format_finding_entry, record_finding, summarize_result


def test_summarizes_dns_result():
    result = {
        "success": True,
        "forward_lookup": {
            "success": True,
            "hostname": "example.com",
            "ip_address": "93.184.216.34",
        },
        "reverse_lookup": None,
    }

    assert summarize_result("dns_lookup", result) == "example.com resolved to 93.184.216.34"


def test_summarizes_discovery_result():
    result = {
        "success": True,
        "network": "192.168.1.0/24",
        "total_hosts_found": 2,
    }

    assert summarize_result("discover_hosts", result) == (
        "Observed 2 active hosts on 192.168.1.0/24"
    )


def test_format_finding_entry_is_markdown():
    command = {"function": "ping", "args": {"host": "example.com"}}
    result = {"success": True, "stdout": "PING example.com\npacket details"}
    timestamp = datetime(2026, 4, 25, 12, 0, tzinfo=timezone.utc)

    entry = format_finding_entry(command, result, timestamp)

    assert "## 2026-04-25T12:00:00+00:00 - ping" in entry
    assert "- Status: success" in entry
    assert "- Target: example.com" in entry
    assert '- Args: `{"host":"example.com"}`' in entry
    assert "- Summary: PING example.com" in entry


def test_record_finding_appends_daily_markdown_file(tmp_path):
    command = {"function": "ping", "args": {"host": "example.com"}}
    result = {"success": True, "stdout": "PING example.com"}

    first_path = record_finding(command, result, tmp_path)
    second_path = record_finding(command, result, tmp_path)

    assert first_path == second_path
    content = first_path.read_text(encoding="utf-8")
    assert content.startswith("# Findings ")
    assert content.count("## ") == 2
    assert first_path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "findings").stat().st_mode & 0o777 == 0o700


def test_finding_details_are_truncated():
    command = {"function": "ping", "args": {"host": "example.com"}}
    result = {"success": True, "stdout": "x" * 2000}

    entry = format_finding_entry(command, result)

    assert "...[truncated]" in entry

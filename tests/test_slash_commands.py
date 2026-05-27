from src import agent
from src.slash_commands import handle_slash_command, is_slash_command


def test_detects_slash_command():
    assert is_slash_command("/help")
    assert is_slash_command("  /mode")
    assert not is_slash_command("help")


def test_help_lists_commands(tmp_path):
    result = handle_slash_command("/help", approval_mode="ask", context_dir=tmp_path)

    assert result.action == "handled"
    assert "/mode [safe|ask|power]" in result.output
    assert "Current mode: ask" in result.output


def test_mode_command_changes_mode(tmp_path):
    result = handle_slash_command("/mode safe", approval_mode="ask", context_dir=tmp_path)

    assert result.action == "handled"
    assert result.approval_mode == "safe"
    assert "Mode changed to: safe" in result.output


def test_mode_command_reports_current_mode(tmp_path):
    result = handle_slash_command("/mode", approval_mode="power", context_dir=tmp_path)

    assert result.approval_mode is None
    assert "Current mode: power" in result.output


def test_policy_command_creates_and_summarizes_policy(tmp_path):
    result = handle_slash_command("/policy", approval_mode="ask", context_dir=tmp_path)

    assert "Policy file:" in result.output
    assert "Default mode: ask" in result.output
    assert (tmp_path / "policy.json").exists()


def test_memory_command_reads_recent_memory(tmp_path):
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    (memory_dir / "recent.md").write_text("## turn\n\nUser: hi", encoding="utf-8")

    result = handle_slash_command("/memory", approval_mode="ask", context_dir=tmp_path)

    assert "User: hi" in result.output


def test_findings_command_reads_latest_findings(tmp_path):
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()
    (findings_dir / "2026-05-26.md").write_text("# old", encoding="utf-8")
    (findings_dir / "2026-05-27.md").write_text("# latest", encoding="utf-8")

    result = handle_slash_command("/findings", approval_mode="ask", context_dir=tmp_path)

    assert "2026-05-27.md" in result.output
    assert "# latest" in result.output


def test_inventory_command_summarizes_hosts_and_networks(tmp_path):
    hosts_dir = tmp_path / "inventory" / "hosts"
    networks_dir = tmp_path / "inventory" / "networks"
    hosts_dir.mkdir(parents=True)
    networks_dir.mkdir(parents=True)
    (hosts_dir / "router.md").write_text("# router", encoding="utf-8")
    (networks_dir / "lan.md").write_text("# lan", encoding="utf-8")

    result = handle_slash_command("/inventory", approval_mode="ask", context_dir=tmp_path)

    assert "Hosts: 1" in result.output
    assert "Networks: 1" in result.output
    assert "router.md" in result.output
    assert "lan.md" in result.output


def test_clear_command_clears_pending_request_and_session_approvals(tmp_path):
    agent._PENDING_REQUEST = {"request": "x", "question": "y", "created_at": 1}

    result = handle_slash_command("/clear", approval_mode="ask", context_dir=tmp_path)

    assert agent._PENDING_REQUEST is None
    assert result.clear_session_approvals is True
    assert "Cleared" in result.output


def test_unknown_slash_command_returns_help(tmp_path):
    result = handle_slash_command("/unknown", approval_mode="ask", context_dir=tmp_path)

    assert "Unknown slash command" in result.output
    assert "/help" in result.output

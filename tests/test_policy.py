import json

from src.policy import classify_shell_command, load_policy, policy_path


def test_load_policy_creates_default_policy(tmp_path):
    policy = load_policy(tmp_path)

    assert policy["version"] == 3
    assert policy["mode"] == "ask"
    assert "read_only_shell_auto_approve" not in policy
    assert "ssh" in policy["risky_commands"]
    assert policy_path(tmp_path).exists()


def test_load_policy_upgrades_old_ssh_block_to_approval_gate(tmp_path):
    policy_path(tmp_path).write_text(
        json.dumps(
            {
                "version": 1,
                "blocked_commands": ["ssh", "scp"],
                "risky_commands": ["sudo"],
                "read_only_shell_auto_approve": True,
            }
        ),
        encoding="utf-8",
    )

    policy = load_policy(tmp_path)

    assert policy["version"] == 3
    assert "ssh" not in policy["blocked_commands"]
    assert "scp" not in policy["blocked_commands"]
    assert "ssh" in policy["risky_commands"]
    assert "scp" in policy["risky_commands"]
    assert "read_only_shell_auto_approve" not in policy


def test_policy_approval_gates_ssh():
    decision = classify_shell_command("ssh host", mode="ask")

    assert decision.action == "ask"
    assert decision.needs_approval is True


def test_policy_marks_risky_command_for_approval():
    decision = classify_shell_command("rm old-file", mode="ask")

    assert decision.action == "ask"
    assert decision.needs_approval is True


def test_classify_shell_command_honors_policy_blocks(tmp_path):
    policy_path(tmp_path).write_text(
        json.dumps(
            {
                "version": 2,
                "mode": "ask",
                "blocked_commands": ["ls"],
                "risky_commands": [],
            }
        ),
        encoding="utf-8",
    )

    decision = classify_shell_command("ls", context_dir=tmp_path)

    assert decision.action == "deny"
    assert decision.reason == "ls is blocked by policy"


def test_classify_shell_command_auto_allows_read_only_command():
    decision = classify_shell_command("ip addr show", mode="ask")

    assert decision.action == "auto_allow"
    assert decision.needs_approval is False


def test_classify_shell_command_asks_for_sudo_in_ask_mode():
    decision = classify_shell_command("sudo apt install htop", mode="ask")

    assert decision.action == "ask"
    assert decision.needs_approval is True
    assert "sudo" in decision.reason


def test_classify_shell_command_denies_sudo_in_safe_mode():
    decision = classify_shell_command("sudo apt install htop", mode="safe")

    assert decision.action == "deny"
    assert "switch to ask or power mode" in decision.reason


def test_classify_shell_command_auto_allows_ssh_in_power_mode():
    decision = classify_shell_command("ssh fileserver df -h", mode="power")

    assert decision.action == "auto_allow"
    assert decision.require_safe is False
    assert "ssh" in decision.reason

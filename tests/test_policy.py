from src.policy import evaluate_command_policy, load_policy, policy_path


def test_load_policy_creates_default_policy(tmp_path):
    policy = load_policy(tmp_path)

    assert policy["read_only_shell_auto_approve"] is True
    assert "ssh" in policy["blocked_commands"]
    assert policy_path(tmp_path).exists()


def test_policy_blocks_ssh(tmp_path):
    decision = evaluate_command_policy("ssh host", tmp_path)

    assert decision.allowed is False
    assert decision.needs_approval is False


def test_policy_marks_risky_command_for_approval(tmp_path):
    decision = evaluate_command_policy("rm old-file", tmp_path)

    assert decision.allowed is True
    assert decision.needs_approval is True

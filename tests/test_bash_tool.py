import subprocess

from src.bash_tool import run_bash
from src.policy import validate_safe_shell_command


def test_validate_safe_shell_command_allows_simple_read_only_command():
    assert validate_safe_shell_command("ip addr show") == (True, None)


def test_validate_safe_shell_command_blocks_shell_composition():
    allowed, reason = validate_safe_shell_command("ip addr show | cat")

    assert allowed is False
    assert "composition" in reason


def test_validate_safe_shell_command_blocks_mutating_systemctl_action():
    allowed, reason = validate_safe_shell_command("systemctl restart nginx")

    assert allowed is False
    assert "State-changing" in reason


def test_validate_safe_shell_command_blocks_unlisted_command():
    allowed, reason = validate_safe_shell_command("rm file")

    assert allowed is False
    assert "not allowed" in reason


def test_validate_safe_shell_command_allows_non_catalog_read_only_command():
    assert validate_safe_shell_command("docker ps") == (True, None)


def test_run_bash_interactive_inherits_terminal_stdio(monkeypatch):
    calls = []
    terminal_calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("src.bash_tool.save_terminal_state", lambda: terminal_calls.append("save"))
    monkeypatch.setattr("src.bash_tool.restore_terminal_state", lambda: terminal_calls.append("restore"))

    result = run_bash("sudo apt install htop", require_safe=False, interactive=True)

    assert result["success"] is True
    assert calls[0][1].get("capture_output") is None
    assert calls[0][1]["check"] is False
    assert terminal_calls == ["save", "restore"]


def test_run_bash_interactive_restores_terminal_after_timeout(monkeypatch):
    terminal_calls = []

    def fake_run(_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["bash"], timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("src.bash_tool.save_terminal_state", lambda: terminal_calls.append("save"))
    monkeypatch.setattr("src.bash_tool.restore_terminal_state", lambda: terminal_calls.append("restore"))

    result = run_bash("sudo apt install htop", timeout=1, require_safe=False, interactive=True)

    assert result["success"] is False
    assert result["error_type"] == "timeout"
    assert terminal_calls == ["save", "restore"]

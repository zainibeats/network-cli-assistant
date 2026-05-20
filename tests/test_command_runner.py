import subprocess

import pytest

from src import command_runner
from src.command_runner import CommandExecutionError, run_command


def test_run_command_rejects_empty_command():
    with pytest.raises(ValueError, match="Command cannot be empty"):
        run_command([], timeout=1)


def test_run_command_rejects_unapproved_executable():
    with pytest.raises(ValueError, match="Executable is not allowed"):
        run_command(["sh", "-c", "echo nope"], timeout=1)


def test_run_command_rejects_path_execution():
    with pytest.raises(ValueError, match="Executable is not allowed"):
        run_command(["/bin/ping", "-c", "1", "127.0.0.1"], timeout=1)


def test_run_command_returns_normalized_result(monkeypatch):
    def fake_run_process(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout="ok", stderr="")

    monkeypatch.setattr(command_runner, "run_process", fake_run_process)

    result = run_command(["ping", "-c", "1", "127.0.0.1"], timeout=1)

    assert result.stdout == "ok"
    assert result.stderr == ""
    assert result.returncode == 0


def test_run_command_raises_normalized_error(monkeypatch):
    def fake_run_process(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 2, stdout="", stderr="failed")

    monkeypatch.setattr(command_runner, "run_process", fake_run_process)

    with pytest.raises(CommandExecutionError) as exc_info:
        run_command(["ping", "-c", "1", "127.0.0.1"], timeout=1)

    assert exc_info.value.result.stderr == "failed"

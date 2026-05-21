import subprocess
import sys

import pytest

from src.pty_runner import run_interactive_process


def test_run_interactive_process_returns_exit_code_and_output(capsys):
    result = run_interactive_process(
        [sys.executable, "-c", "print('pty ok')"],
        timeout=5,
    )

    captured = capsys.readouterr()
    assert result.returncode == 0
    assert "pty ok" in result.stdout
    assert "pty ok" in captured.out


def test_run_interactive_process_times_out():
    with pytest.raises(subprocess.TimeoutExpired) as exc_info:
        run_interactive_process(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=1,
        )

    assert exc_info.value.timeout == 1

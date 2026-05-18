"""Policy-checked bash execution for assistant workflows."""

from __future__ import annotations

import os
import subprocess

from .policy import command_requires_approval as _command_requires_approval
from .policy import validate_safe_shell_command


def run_bash(command: str, timeout: int = 30, require_safe: bool = True) -> dict:
    """Run a bash command after deterministic policy checks."""
    if require_safe:
        is_allowed, reason = validate_bash_command(command)
        if not is_allowed:
            return {"success": False, "error": reason, "error_type": "policy_blocked"}

    try:
        completed = subprocess.run(
            ["bash", "-lc", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=_safe_env(),
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Bash command timed out", "error_type": "timeout"}

    return {
        "success": completed.returncode == 0,
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "exit_code": completed.returncode,
        "output": completed.stdout or completed.stderr,
    }


def validate_bash_command(command: str) -> tuple[bool, str | None]:
    """Compatibility wrapper for safe shell validation."""
    return validate_safe_shell_command(command)


def command_requires_approval(command: str) -> tuple[bool, str | None]:
    """Compatibility wrapper for approval classification."""
    return _command_requires_approval(command)


def _safe_env() -> dict[str, str]:
    keep = {"HOME", "LANG", "LC_ALL", "PATH", "TERM"}
    return {key: value for key, value in os.environ.items() if key in keep}

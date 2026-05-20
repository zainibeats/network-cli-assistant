"""Policy-checked bash execution for assistant workflows."""

from __future__ import annotations

import os
import subprocess

from .policy import ApprovalMode, classify_shell_command
from .policy import validate_safe_shell_command
from .process_runner import run_process


def run_bash(
    command: str,
    timeout: int = 30,
    require_safe: bool = True,
    interactive: bool = False,
) -> dict:
    """Run a bash command after deterministic policy checks."""
    if require_safe:
        is_allowed, reason = validate_safe_shell_command(command)
        if not is_allowed:
            return {"success": False, "error": reason, "error_type": "policy_blocked"}

    try:
        if interactive:
            completed = subprocess.run(
                ["bash", "-lc", command],
                check=False,
                timeout=timeout,
                env=_safe_env(),
            )
        else:
            completed = run_process(
                ["bash", "-lc", command],
                timeout=timeout,
                env=_safe_env(),
            )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Bash command timed out", "error_type": "timeout"}

    if interactive:
        return {
            "success": completed.returncode == 0,
            "command": command,
            "stdout": "",
            "stderr": "",
            "exit_code": completed.returncode,
            "output": "Interactive command completed" if completed.returncode == 0 else "Interactive command failed",
        }

    return {
        "success": completed.returncode == 0,
        "command": command,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "exit_code": completed.returncode,
        "output": completed.stdout or completed.stderr,
    }


def classify_bash_command(command: str, mode: ApprovalMode | None = None):
    """Classify a shell command before execution."""
    return classify_shell_command(command, mode=mode)


def _safe_env() -> dict[str, str]:
    keep = {"HOME", "LANG", "LC_ALL", "PATH", "TERM"}
    return {key: value for key, value in os.environ.items() if key in keep}

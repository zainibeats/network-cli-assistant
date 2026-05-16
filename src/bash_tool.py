"""Policy-checked bash execution for assistant workflows."""

from __future__ import annotations

import os
import shlex
import subprocess

BLOCKED_TOKENS = frozenset(
    {
        "&&",
        "||",
        ";",
        ">",
        ">>",
        "<",
        "$(",
        "`",
    }
)
BLOCKED_COMMANDS = frozenset(
    {
        "apt",
        "apt-get",
        "bash",
        "chmod",
        "chown",
        "cp",
        "curl",
        "dd",
        "docker-compose",
        "git",
        "kill",
        "mkfs",
        "mv",
        "nc",
        "netcat",
        "nft",
        "pip",
        "python",
        "python3",
        "reboot",
        "rm",
        "rsync",
        "scp",
        "service",
        "shutdown",
        "ssh",
        "sudo",
        "tee",
        "touch",
        "ufw",
        "wget",
    }
)
READ_ONLY_SYSTEMCTL_ACTIONS = frozenset(
    {
        "cat",
        "is-active",
        "is-enabled",
        "is-failed",
        "list-dependencies",
        "list-unit-files",
        "list-units",
        "show",
        "status",
        "--failed",
    }
)
MUTATING_SYSTEMCTL_ACTIONS = frozenset(
    {
        "disable",
        "enable",
        "mask",
        "reload",
        "restart",
        "start",
        "stop",
        "unmask",
    }
)
MUTATING_DOCKER_ACTIONS = frozenset(
    {
        "build",
        "compose",
        "container",
        "create",
        "exec",
        "kill",
        "login",
        "logout",
        "network",
        "pause",
        "pull",
        "push",
        "restart",
        "rm",
        "rmi",
        "run",
        "start",
        "stop",
        "system",
        "unpause",
        "update",
        "volume",
    }
)


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
    """Allow read-only diagnostics and block shell composition or mutations."""
    if not command or not command.strip():
        return False, "Command cannot be empty"

    if any(token in command for token in BLOCKED_TOKENS):
        return False, "Shell composition and redirection are blocked in safe mode"

    if "|" in command:
        return False, "Shell composition and redirection are blocked in safe mode"

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return False, f"Invalid shell syntax: {exc}"

    if not parts:
        return False, "Command cannot be empty"

    executable = _base_command(parts[0])
    if "/" in parts[0] or executable in BLOCKED_COMMANDS:
        return False, f"Command is not allowed in safe mode: {executable}"

    if executable == "systemctl" and _has_mutating_systemctl_action(parts[1:]):
        return False, "State-changing systemctl actions require confirmation and are not allowed in safe mode"

    if executable == "systemctl" and not _has_read_only_systemctl_action(parts[1:]):
        return False, "Systemctl action is not clearly read-only in safe mode"

    if executable == "docker" and _has_mutating_docker_action(parts[1:]):
        return False, "State-changing docker actions require confirmation and are not allowed in safe mode"

    if _looks_like_inline_script(parts):
        return False, "Inline scripts require confirmation and are not allowed in safe mode"

    return True, None


def command_requires_approval(command: str) -> tuple[bool, str | None]:
    """Return whether a syntactically valid command needs explicit approval."""
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return False, f"Invalid shell syntax: {exc}"

    if not parts:
        return False, "Command cannot be empty"

    executable = _base_command(parts[0])
    if executable == "systemctl":
        if _has_mutating_systemctl_action(parts[1:]):
            return True, "state-changing systemctl action"
        if not _has_read_only_systemctl_action(parts[1:]):
            return True, "systemctl action is not clearly read-only"
    if executable == "docker" and _has_mutating_docker_action(parts[1:]):
        return True, "state-changing docker action"
    if executable in BLOCKED_COMMANDS:
        return True, f"{executable} is not read-only"
    if any(token in command for token in BLOCKED_TOKENS) or "|" in command:
        return True, "shell composition or redirection"
    if _looks_like_inline_script(parts):
        return True, "inline script"
    return False, None


def _base_command(value: str) -> str:
    return value.rsplit("/", 1)[-1]


def _has_mutating_systemctl_action(args: list[str]) -> bool:
    return any(arg in MUTATING_SYSTEMCTL_ACTIONS for arg in args)


def _has_read_only_systemctl_action(args: list[str]) -> bool:
    return not args or any(arg in READ_ONLY_SYSTEMCTL_ACTIONS for arg in args)


def _has_mutating_docker_action(args: list[str]) -> bool:
    return any(arg in MUTATING_DOCKER_ACTIONS for arg in args)


def _looks_like_inline_script(parts: list[str]) -> bool:
    return any(part in {"-c", "--command"} for part in parts)


def _safe_env() -> dict[str, str]:
    keep = {"HOME", "LANG", "LC_ALL", "PATH", "TERM"}
    return {key: value for key, value in os.environ.items() if key in keep}

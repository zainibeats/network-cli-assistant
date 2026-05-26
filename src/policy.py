"""Editable local policy for command approval decisions."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .runtime_context import ensure_directory, get_runtime_context_dir, set_private_permissions

DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "low_risk_shell_auto_approve": True,
    "approval": {
        "allow_session_approval": True,
        "allow_policy_edits_from_prompt": False,
    },
    "blocked_commands": ["ssh", "scp"],
    "risky_commands": [
        "apt",
        "apt-get",
        "chmod",
        "chown",
        "cp",
        "curl",
        "dd",
        "docker",
        "git",
        "kill",
        "mkfs",
        "mv",
        "nft",
        "pip",
        "python",
        "python3",
        "reboot",
        "rm",
        "rsync",
        "service",
        "shutdown",
        "sudo",
        "systemctl",
        "tee",
        "touch",
        "ufw",
        "web_search",
        "wget",
    ],
}
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
SAFE_MODE_BLOCKED_COMMANDS = frozenset(
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


@dataclass(frozen=True)
class PolicyDecision:
    """Result of checking a command against editable policy."""

    allowed: bool
    needs_approval: bool
    reason: str | None = None


def policy_path(context_dir: Path | None = None) -> Path:
    """Return the runtime policy file path."""
    return ensure_directory(context_dir or get_runtime_context_dir()) / "policy.json"


def load_policy(context_dir: Path | None = None) -> dict[str, Any]:
    """Load policy, creating a conservative default if missing or malformed."""
    path = policy_path(context_dir)
    if not path.exists():
        return write_default_policy(context_dir)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        backup = path.with_suffix(".invalid.json")
        path.replace(backup)
        return write_default_policy(context_dir)
    return _merge_defaults(loaded)


def write_default_policy(context_dir: Path | None = None) -> dict[str, Any]:
    """Write the default policy to runtime context."""
    path = policy_path(context_dir)
    path.write_text(json.dumps(DEFAULT_POLICY, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    set_private_permissions(path, 0o600)
    return DEFAULT_POLICY.copy()


def evaluate_command_policy(command: str, context_dir: Path | None = None) -> PolicyDecision:
    """Classify a shell command using the editable runtime policy."""
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return PolicyDecision(False, False, f"Invalid shell syntax: {exc}")

    if not parts:
        return PolicyDecision(False, False, "Command cannot be empty")

    executable = parts[0].rsplit("/", 1)[-1]
    policy = load_policy(context_dir)
    if executable in set(policy.get("blocked_commands", [])):
        return PolicyDecision(False, False, f"{executable} is blocked by policy")
    if executable in set(policy.get("risky_commands", [])):
        return PolicyDecision(True, True, f"{executable} is configured as risky")
    return PolicyDecision(True, False, None)


def validate_safe_shell_command(command: str) -> tuple[bool, str | None]:
    """Allow commands that can run without prompting; route the rest to approval."""
    if not command or not command.strip():
        return False, "Command cannot be empty"

    if any(token in command for token in BLOCKED_TOKENS) or "|" in command:
        return False, "Shell composition and redirection require approval"

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return False, f"Invalid shell syntax: {exc}"

    if not parts:
        return False, "Command cannot be empty"

    executable = _base_command(parts[0])
    if "/" in parts[0] or executable in SAFE_MODE_BLOCKED_COMMANDS:
        return False, f"{executable} requires approval"

    if executable == "systemctl" and _has_mutating_systemctl_action(parts[1:]):
        return False, "State-changing systemctl actions require approval"

    if executable == "systemctl" and not _has_read_only_systemctl_action(parts[1:]):
        return False, "Systemctl action requires approval"

    if executable == "docker" and _has_mutating_docker_action(parts[1:]):
        return False, "State-changing docker actions require approval"

    if _looks_like_inline_script(parts):
        return False, "Inline scripts require approval"

    return True, None


def command_requires_approval(command: str) -> tuple[bool, str | None]:
    """Return whether a syntactically valid command needs explicit approval."""
    policy_decision = evaluate_command_policy(command)
    if not policy_decision.allowed:
        return False, policy_decision.reason
    if policy_decision.needs_approval:
        return True, policy_decision.reason

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
            return True, "systemctl action requires approval"
    if executable == "docker" and _has_mutating_docker_action(parts[1:]):
        return True, "state-changing docker action"
    if executable in SAFE_MODE_BLOCKED_COMMANDS:
        return True, f"{executable} requires approval"
    if any(token in command for token in BLOCKED_TOKENS) or "|" in command:
        return True, "shell composition or redirection"
    if _looks_like_inline_script(parts):
        return True, "inline script"
    return False, None


def _merge_defaults(loaded: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(DEFAULT_POLICY))
    for key, value in loaded.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


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

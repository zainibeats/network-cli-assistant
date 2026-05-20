"""Editable local policy for command approval decisions."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .runtime_context import ensure_directory, get_runtime_context_dir, set_private_permissions

ApprovalMode = Literal["safe", "ask", "power"]
CommandPolicyAction = Literal["auto_allow", "ask", "deny"]

DEFAULT_POLICY: dict[str, Any] = {
    "version": 3,
    "mode": "ask",
    "approval": {
        "allow_session_approval": True,
        "allow_policy_edits_from_prompt": False,
    },
    "blocked_commands": [],
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
        "scp",
        "ssh",
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
class CommandPolicyDecision:
    """Normalized command execution decision."""

    action: CommandPolicyAction
    reason: str | None = None
    mode: ApprovalMode = "ask"
    require_safe: bool = True

    @property
    def allowed(self) -> bool:
        return self.action != "deny"

    @property
    def needs_approval(self) -> bool:
        return self.action == "ask"


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
    merged = _merge_defaults(loaded)
    upgraded = _upgrade_policy(merged)
    if upgraded != loaded:
        path.write_text(json.dumps(upgraded, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        set_private_permissions(path, 0o600)
    return upgraded


def write_default_policy(context_dir: Path | None = None) -> dict[str, Any]:
    """Write the default policy to runtime context."""
    path = policy_path(context_dir)
    path.write_text(json.dumps(DEFAULT_POLICY, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    set_private_permissions(path, 0o600)
    return DEFAULT_POLICY.copy()


def classify_shell_command(
    command: str,
    *,
    mode: ApprovalMode | None = None,
    context_dir: Path | None = None,
) -> CommandPolicyDecision:
    """Classify a shell command for execution in the selected assistant mode."""
    selected_mode = mode or _policy_mode(load_policy(context_dir))

    block_reason = _policy_block_reason(command, context_dir=context_dir)
    if block_reason:
        return CommandPolicyDecision("deny", block_reason, selected_mode)

    is_safe, safe_reason = validate_safe_shell_command(command)
    if is_safe:
        return CommandPolicyDecision("auto_allow", None, selected_mode, require_safe=True)

    approval_reason = _approval_reason(command, context_dir=context_dir)
    reason = approval_reason or safe_reason
    if approval_reason is None:
        return CommandPolicyDecision("deny", reason, selected_mode)

    if selected_mode == "safe":
        return CommandPolicyDecision(
            "deny",
            f"{reason}; switch to ask or power mode to approve it",
            selected_mode,
            require_safe=True,
        )
    if selected_mode == "power":
        return CommandPolicyDecision("auto_allow", reason, selected_mode, require_safe=False)

    return CommandPolicyDecision("ask", reason, selected_mode, require_safe=False)


def validate_safe_shell_command(command: str) -> tuple[bool, str | None]:
    """Allow read-only diagnostics and block shell composition or mutations."""
    if not command or not command.strip():
        return False, "Command cannot be empty"

    if any(token in command for token in BLOCKED_TOKENS) or "|" in command:
        return False, "Shell composition and redirection are blocked in safe mode"

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return False, f"Invalid shell syntax: {exc}"

    if not parts:
        return False, "Command cannot be empty"

    executable = _base_command(parts[0])
    if "/" in parts[0] or executable in SAFE_MODE_BLOCKED_COMMANDS:
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


def _approval_reason(command: str, context_dir: Path | None = None) -> str | None:
    """Return why a shell command needs approval, or None when it should be denied."""
    policy_reason = _policy_approval_reason(command, context_dir=context_dir)
    if policy_reason:
        return policy_reason

    try:
        parts = shlex.split(command)
    except ValueError:
        return None

    if not parts:
        return None

    executable = _base_command(parts[0])
    if executable == "systemctl":
        if _has_mutating_systemctl_action(parts[1:]):
            return "state-changing systemctl action"
        if not _has_read_only_systemctl_action(parts[1:]):
            return "systemctl action is not clearly read-only"
    if executable == "docker" and _has_mutating_docker_action(parts[1:]):
        return "state-changing docker action"
    if executable in SAFE_MODE_BLOCKED_COMMANDS:
        return f"{executable} is not read-only"
    if any(token in command for token in BLOCKED_TOKENS) or "|" in command:
        return "shell composition or redirection"
    if _looks_like_inline_script(parts):
        return "inline script"
    return None


def _policy_approval_reason(command: str, context_dir: Path | None = None) -> str | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts:
        return None

    executable = _base_command(parts[0])
    policy = load_policy(context_dir)
    if executable in set(policy.get("risky_commands", [])):
        return f"{executable} is configured as risky"
    return None


def _policy_block_reason(command: str, context_dir: Path | None = None) -> str | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts:
        return None

    executable = _base_command(parts[0])
    policy = load_policy(context_dir)
    if executable in set(policy.get("blocked_commands", [])):
        return f"{executable} is blocked by policy"
    return None


def _policy_mode(policy: dict[str, Any]) -> ApprovalMode:
    mode = policy.get("mode")
    return mode if mode in {"safe", "ask", "power"} else "ask"


def _merge_defaults(loaded: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(DEFAULT_POLICY))
    for key, value in loaded.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value
    return merged


def _upgrade_policy(policy: dict[str, Any]) -> dict[str, Any]:
    upgraded = json.loads(json.dumps(policy))
    upgraded.pop("read_only_shell_auto_approve", None)
    if int(upgraded.get("version") or 1) < 2:
        blocked = [item for item in upgraded.get("blocked_commands", []) if item not in {"ssh", "scp"}]
        risky = list(dict.fromkeys([*upgraded.get("risky_commands", []), "ssh", "scp"]))
        upgraded["blocked_commands"] = blocked
        upgraded["risky_commands"] = risky
        upgraded["mode"] = upgraded.get("mode") if upgraded.get("mode") in {"safe", "ask", "power"} else "ask"
        upgraded["version"] = 2
    if int(upgraded.get("version") or 1) < 3:
        upgraded["version"] = 3
    return upgraded


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

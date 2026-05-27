"""Deterministic slash commands for the interactive CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .agent import clear_pending_request
from .memory import load_chat_memory
from .policy import ApprovalMode, load_policy, policy_path
from .runtime_context import get_runtime_context_dir

SlashAction = Literal["handled", "exit"]


@dataclass(frozen=True)
class SlashCommandResult:
    """Result of a slash command handled by the CLI loop."""

    action: SlashAction
    output: str
    approval_mode: ApprovalMode | None = None
    clear_session_approvals: bool = False


def is_slash_command(user_input: str) -> bool:
    """Return whether the input should be handled as a slash command."""
    return user_input.strip().startswith("/")


def handle_slash_command(
    user_input: str,
    *,
    approval_mode: ApprovalMode,
    context_dir: Path | None = None,
) -> SlashCommandResult:
    """Handle a deterministic slash command without invoking the agent."""
    text = user_input.strip()
    command, _, argument = text.partition(" ")
    command = command.lower()
    argument = argument.strip()
    root = context_dir or get_runtime_context_dir()

    if command in {"/help", "/?"}:
        return _handled(_help_text(approval_mode, root))
    if command == "/exit":
        return SlashCommandResult("exit", "Goodbye!")
    if command == "/mode":
        return _mode_command(argument, approval_mode)
    if command == "/policy":
        return _handled(_policy_text(root))
    if command == "/memory":
        return _handled(_memory_text(root))
    if command == "/findings":
        return _handled(_latest_file_text(root / "findings", "findings"))
    if command == "/inventory":
        return _handled(_inventory_text(root))
    if command == "/clear":
        clear_pending_request()
        return SlashCommandResult(
            "handled",
            "Cleared pending clarification and session approvals.",
            clear_session_approvals=True,
        )

    return _handled(f"Unknown slash command: {command}\n\n{_available_commands()}")


def _mode_command(argument: str, current_mode: ApprovalMode) -> SlashCommandResult:
    if not argument:
        return _handled(f"Current mode: {current_mode}\nUse `/mode safe`, `/mode ask`, or `/mode power`.")
    if argument not in {"safe", "ask", "power"}:
        return _handled("Invalid mode. Use `/mode safe`, `/mode ask`, or `/mode power`.")
    return SlashCommandResult("handled", f"Mode changed to: {argument}", approval_mode=argument)


def _policy_text(context_dir: Path) -> str:
    policy = load_policy(context_dir)
    risky = ", ".join(policy.get("risky_commands", [])[:20]) or "none"
    blocked = ", ".join(policy.get("blocked_commands", [])[:20]) or "none"
    return "\n".join(
        [
            f"Policy file: {policy_path(context_dir)}",
            f"Default mode: {policy.get('mode', 'ask')}",
            f"Session approvals: {policy.get('approval', {}).get('allow_session_approval', True)}",
            f"Risky commands: {risky}",
            f"Blocked commands: {blocked}",
        ]
    )


def _memory_text(context_dir: Path) -> str:
    memory = load_chat_memory(context_dir)
    if not memory:
        return f"No recent chat memory found in {context_dir / 'memory'}."
    return _truncate(memory, 3000)


def _inventory_text(context_dir: Path) -> str:
    host_files = _markdown_files(context_dir / "inventory" / "hosts")
    network_files = _markdown_files(context_dir / "inventory" / "networks")
    lines = [
        f"Inventory root: {context_dir / 'inventory'}",
        f"Hosts: {len(host_files)}",
        f"Networks: {len(network_files)}",
    ]
    for label, paths in (("Recent hosts", host_files), ("Recent networks", network_files)):
        recent = paths[-5:]
        if recent:
            lines.append(f"{label}:")
            lines.extend(f"- {path.name}" for path in recent)
    return "\n".join(lines)


def _latest_file_text(directory: Path, label: str) -> str:
    files = _markdown_files(directory)
    if not files:
        return f"No {label} files found in {directory}."
    latest = files[-1]
    content = latest.read_text(encoding="utf-8").strip()
    if not content:
        return f"Latest {label}: {latest}\n(empty)"
    return f"Latest {label}: {latest}\n\n{_truncate(content, 3000)}"


def _markdown_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(path for path in directory.glob("*.md") if path.name != "README.md")


def _help_text(approval_mode: ApprovalMode, context_dir: Path) -> str:
    return "\n".join(
        [
            "Slash commands:",
            _available_commands(),
            "",
            f"Current mode: {approval_mode}",
            f"Runtime context: {context_dir}",
        ]
    )


def _available_commands() -> str:
    return "\n".join(
        [
            "/help - show local CLI commands",
            "/mode [safe|ask|power] - view or change execution mode",
            "/policy - show current policy summary",
            "/memory - show recent chat memory",
            "/findings - show the latest findings file",
            "/inventory - show inventory summary",
            "/clear - clear pending clarification and session approvals",
            "/exit - exit the CLI",
        ]
    )


def _truncate(value: str, limit: int) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + "\n...[truncated]"


def _handled(output: str) -> SlashCommandResult:
    return SlashCommandResult("handled", output)

"""Plan construction for local agent workflows."""

from __future__ import annotations

import ipaddress
import shlex

from .agent_prompts import shell_planner_prompt
from .command_result import needs_clarification
from .llm_providers import parse_json_with_provider
from .memory import load_chat_memory, load_runtime_memory

READ_ONLY_FUNCTIONS = frozenset(
    {
        "dns_lookup",
        "ping",
        "traceroute",
        "discover_hosts",
        "run_nmap_scan",
        "run_netstat",
    }
)
AGENT_FUNCTIONS = READ_ONLY_FUNCTIONS | {"run_bash", "web_search"}
BASH_PREFIXES = ("bash ", "run bash ", "shell ")
SCAN_COMMANDS = {"masscan", "nmap", "nikto"}


def build_agent_plan(user_input: str) -> dict | None:
    """Do not build keyword-triggered plans from free-form user input."""
    return None


def build_shell_agent_plan(user_input: str) -> dict | None:
    """Ask the local model for a bounded shell plan for local diagnostics."""
    user_prompt = "\n".join(
        [
            f"User request: {user_input.strip()}",
            "",
            "Recent memory:",
            load_chat_memory() or "(none)",
            "",
            "User-editable runtime context:",
            load_runtime_memory() or "(none)",
        ]
    )
    try:
        plan = parse_json_with_provider(shell_planner_prompt(), user_prompt)
    except Exception:
        return None

    if not isinstance(plan, dict) or plan.get("status") == "needs_clarification":
        question = plan.get("question") if isinstance(plan, dict) else None
        if question:
            return needs_clarification(question, plan.get("missing", []))
        return None

    commands = plan.get("commands")
    searches = plan.get("searches")
    if not isinstance(commands, list):
        commands = []
    if not isinstance(searches, list):
        searches = []
    if not commands and not searches:
        return None

    steps = []
    for item in searches[:2]:
        if not isinstance(item, dict):
            continue
        query = str(item.get("query", "")).strip()
        reason = str(item.get("reason") or "Research current online information")
        if query:
            steps.append(step("web_search", {"query": query, "max_results": 5}, reason))

    for item in commands[:6]:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", "")).strip()
        reason = str(item.get("reason") or "Run local diagnostic command")
        if not command:
            continue
        external_reason = external_scan_reason(command, user_input)
        if external_reason:
            return needs_clarification(external_reason, ["external_scan_confirmation"])
        steps.append(step("run_bash", {"command": command}, reason))

    if not steps:
        return None

    return {
        "status": "agent_plan",
        "mode": "power",
        "target": str(plan.get("target") or "local-machine"),
        "steps": steps,
        "source": "llm_shell_planner",
    }


def build_bash_request_plan(user_input: str) -> dict | None:
    """Build a one-step plan for explicit bash-prefixed user requests."""
    text = user_input.strip()
    lowered = text.lower()
    for prefix in BASH_PREFIXES:
        if lowered.startswith(prefix):
            command = text[len(prefix) :].strip()
            return _agent_plan(
                "safe",
                "local-machine",
                [step("run_bash", {"command": command}, "Run approved read-only bash command from user request")],
            )
    return None


def should_try_shell_planner(user_input: str, command: dict | None) -> bool:
    """Return whether the local model should try to plan shell diagnostics."""
    if command is None:
        return True
    if command.get("status") == "needs_clarification":
        return True
    return False


def as_agent_plan(command: dict) -> dict:
    """Route approved read-only parsed commands through the agent executor."""
    if command.get("status") == "agent_plan":
        return command

    function_name = command.get("function")
    if command.get("status") == "ready" and function_name in READ_ONLY_FUNCTIONS:
        return _agent_plan(
            "safe",
            _target_from_args(command.get("args", {})),
            [
                step(
                    function_name,
                    command.get("args", {}),
                    "Run approved read-only command from parsed user request",
                )
            ],
        )

    if command.get("status") == "ready" and function_name == "web_search":
        return _agent_plan(
            "power",
            "web",
            [
                step(
                    function_name,
                    command.get("args", {}),
                    "Research current online information",
                )
            ],
        )

    return command


def external_scan_reason(command: str, user_input: str) -> str | None:
    """Return why a generated scan needs explicit external-target confirmation."""
    text = user_input.lower()
    if "external" in text or "public" in text:
        return None

    try:
        parts = shlex.split(command)
    except ValueError:
        return "The generated command has invalid shell syntax. Please rephrase the request."

    if not parts or parts[0] not in SCAN_COMMANDS:
        return None

    for part in parts[1:]:
        if part.startswith("-"):
            continue
        target = part.strip()
        if not target or target.isdigit():
            continue
        if _is_private_or_local_target(target):
            continue
        return (
            "This looks like a scan against a public or external target. "
            "Please explicitly confirm the external target before I run it."
        )
    return None


def step(function: str, args: dict, reason: str) -> dict:
    """Build one executable plan step."""
    return {"function": function, "args": args, "reason": reason}


def _agent_plan(mode: str, target: str | None, steps: list[dict]) -> dict:
    return {"status": "agent_plan", "mode": mode, "target": target, "steps": steps, "source": "agent"}


def _target_from_args(args: dict) -> str | None:
    return args.get("host") or args.get("target") or args.get("network")


def _is_private_or_local_target(target: str) -> bool:
    if target in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return network.is_private or network.is_loopback or network.is_link_local
        address = ipaddress.ip_address(target)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        return target.endswith(".local") or "." not in target

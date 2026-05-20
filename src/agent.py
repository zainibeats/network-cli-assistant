"""Interactive session facade for the local terminal agent."""

from __future__ import annotations

import logging
import time
from typing import Callable

from . import core_functions
from .agent_executor import execute_agent_plan
from .agent_planner import (
    as_agent_plan,
    build_agent_plan,
    build_bash_request_plan,
    build_shell_agent_plan,
    should_try_shell_planner,
)
from .audit import record_audit_event
from .dispatcher import parse_command
from .findings import record_finding
from .knowledgebase import update_inventory
from .llm_providers import chat_with_provider
from .memory import append_chat_turn, load_chat_memory, load_runtime_memory
from .utils import format_output

ApprovalCallback = Callable[[str, str | None], bool]

CHAT_PATTERNS = (
    "hello",
    "hi",
    "hey",
    "thanks",
    "thank you",
    "what can you do",
    "help",
)
_PENDING_REQUEST: dict | None = None
PENDING_CLARIFICATION_TTL_SECONDS = 300
CLARIFICATION_CANCEL_WORDS = {"cancel", "nevermind", "never mind", "ignore that"}


def handle_agent_message(user_input: str, approval_callback: ApprovalCallback | None = None) -> str:
    """Handle every user message through the assistant agent path."""
    global _PENDING_REQUEST

    original_input = user_input
    record_audit_event("user_request", {"input_preview": original_input[:300]})
    if _PENDING_REQUEST:
        if _pending_request_expired(_PENDING_REQUEST):
            _PENDING_REQUEST = None
        elif _is_clarification_cancel(user_input):
            _PENDING_REQUEST = None
            return "Okay, I cleared the pending clarification."
        else:
            user_input = "\n".join(
                [
                    f"Original request: {_PENDING_REQUEST['request']}",
                    f"Assistant question: {_PENDING_REQUEST['question']}",
                    f"User clarification: {user_input}",
                ]
            )
            _PENDING_REQUEST = None

    if _is_chat(user_input):
        response = _chat_response(user_input)
        append_chat_turn(user_input, response)
        return response

    result = build_bash_request_plan(user_input)
    if result is None:
        command = build_agent_plan(user_input)
        if command is None or should_try_shell_planner(user_input, command):
            command = build_shell_agent_plan(user_input) or command
        command = as_agent_plan(command or parse_command(user_input))
        if command.get("status") == "needs_clarification":
            _set_pending_request(original_input, command.get("question"))
        result = _run_parsed_request(command, approval_callback=approval_callback, user_input=user_input)
    elif isinstance(result, dict) and result.get("status") == "agent_plan":
        result = _run_parsed_request(result, approval_callback=approval_callback, user_input=user_input)

    if isinstance(result, dict) and result.get("status") == "needs_clarification":
        _set_pending_request(original_input, result.get("question"))

    response = format_output(result) if isinstance(result, dict) else str(result)
    append_chat_turn(user_input, response)
    return response


def _set_pending_request(request: str, question: str | None) -> None:
    global _PENDING_REQUEST
    _PENDING_REQUEST = {
        "request": request,
        "question": question or "Please clarify the request.",
        "created_at": time.monotonic(),
    }


def _pending_request_expired(pending_request: dict) -> bool:
    created_at = pending_request.get("created_at")
    if not isinstance(created_at, int | float):
        return False
    return time.monotonic() - created_at > PENDING_CLARIFICATION_TTL_SECONDS


def _is_clarification_cancel(user_input: str) -> bool:
    return " ".join(user_input.strip().lower().split()) in CLARIFICATION_CANCEL_WORDS


def build_diagnostic_plan(user_input: str) -> dict | None:
    """Compatibility wrapper for callers that want explicit diagnostic planning."""
    return build_agent_plan(user_input)


def _run_parsed_request(
    command: dict,
    approval_callback: ApprovalCallback | None = None,
    user_input: str = "",
) -> dict:
    if command.get("status") == "needs_clarification":
        return {
            "success": True,
            "status": "needs_clarification",
            "question": command.get("question", "Please clarify the request."),
            "output": command.get("question", "Please clarify the request."),
        }

    if command.get("status") == "agent_plan":
        return execute_agent_plan(
            command,
            approval_callback=approval_callback,
            user_input=user_input,
            observe_with_model=True,
        )

    if command.get("status") == "error" or "error" in command:
        return {"success": False, "error": command.get("message", "Could not understand command")}

    if "function" not in command:
        return {"success": False, "error": "Could not understand command"}

    function_name = command["function"]
    function_args = command.get("args", {})
    result = getattr(core_functions, function_name)(**function_args)
    _persist_observation(command, result)
    return result


def _persist_observation(command: dict, result: dict) -> None:
    try:
        record_finding(command, result)
        update_inventory(command, result)
    except Exception:
        logging.getLogger("cli_assistant.agent").warning(
            "Could not persist assistant observation", exc_info=True
        )


def _is_chat(user_input: str) -> bool:
    text = " ".join(user_input.lower().split())
    return text in CHAT_PATTERNS


def _chat_response(user_input: str) -> str:
    memory = load_chat_memory()
    runtime_memory = load_runtime_memory()
    prompt = (
        "You are a concise homelab terminal assistant. "
        "Use the recent chat memory for continuity when relevant. "
        "Use user-editable runtime notes when relevant. "
        "Do not claim you executed tools in chat mode. "
        "Recommend state-changing admin actions instead of performing them.\n\n"
        f"Recent chat memory:\n{memory or '(none)'}\n\n"
        f"User-editable runtime context:\n{runtime_memory or '(none)'}"
    )
    try:
        return chat_with_provider(prompt, user_input)
    except Exception:
        return (
            "I can help with safe homelab diagnostics, approved network tools, and read-only bash. "
            "Ask me to investigate a host or run `bash <read-only command>`."
        )

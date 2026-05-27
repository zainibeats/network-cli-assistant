"""Execution and observation review for agent plans."""

from __future__ import annotations

import logging
import shlex
from typing import Callable, Iterable

from . import core_functions
from .agent_planner import AGENT_FUNCTIONS, external_scan_reason, step
from .agent_prompts import observer_prompt
from .audit import record_audit_event
from .bash_tool import classify_bash_command, run_bash
from .findings import record_finding, summarize_result
from .knowledgebase import update_inventory
from .llm_providers import parse_json_with_provider
from .policy import ApprovalMode

MAX_OBSERVATION_CHARS = 4000
MAX_DISPLAY_CHARS = 8000
MAX_AGENT_LOOPS = 3

ApprovalCallback = Callable[[str, str | None], bool]


def execute_agent_plan(
    plan: dict,
    *,
    function_resolver: Callable[[str], Callable] | None = None,
    finding_recorder: Callable[[dict, dict], object] = record_finding,
    inventory_updater: Callable[[dict, dict], object] = update_inventory,
    approval_callback: ApprovalCallback | None = None,
    user_input: str = "",
    observe_with_model: bool = False,
    approval_mode: ApprovalMode | None = None,
) -> dict:
    """Execute an agent plan, optionally letting the model inspect observations."""
    record_audit_event(
        "agent_plan",
        {
            "mode": plan.get("mode", "safe"),
            "target": plan.get("target"),
            "steps": [display_command(item) for item in plan.get("steps", [])],
        },
    )
    resolver = function_resolver or (lambda name: getattr(core_functions, name))
    results = _execute_agent_steps(
        plan.get("steps", []),
        resolver=resolver,
        finding_recorder=finding_recorder,
        inventory_updater=inventory_updater,
        approval_callback=approval_callback,
        approval_mode=approval_mode,
    )

    final_answer = ""
    follow_up_question = ""
    if observe_with_model:
        for _attempt in range(MAX_AGENT_LOOPS):
            review = _review_observations(user_input, plan, results)
            if not review:
                break
            if review.get("status") == "needs_clarification":
                follow_up_question = str(review.get("question") or "Please clarify the request.")
                break
            if review.get("answer"):
                final_answer = str(review["answer"]).strip()
                break
            next_steps = _steps_from_review(review, user_input)
            if not next_steps:
                break
            more_results = _execute_agent_steps(
                next_steps,
                resolver=resolver,
                finding_recorder=finding_recorder,
                inventory_updater=inventory_updater,
                approval_callback=approval_callback,
                approval_mode=approval_mode,
            )
            results.extend(more_results)

    output = format_agent_output(results, final_answer=final_answer)
    if follow_up_question:
        return {
            "success": True,
            "agent": True,
            "status": "needs_clarification",
            "question": follow_up_question,
            "mode": plan.get("mode", "safe"),
            "target": plan.get("target"),
            "steps": results,
            "output": follow_up_question + "\n\n" + output,
            "recommendations": recommend_next_steps(results),
        }

    return {
        "success": True,
        "agent": True,
        "mode": plan.get("mode", "safe"),
        "target": plan.get("target"),
        "steps": results,
        "output": output,
        "recommendations": recommend_next_steps(results),
    }


def display_command(plan_step: dict) -> str:
    """Return the terminal-style display string for a plan step."""
    if plan_step["function"] == "run_bash":
        return f"$ {plan_step.get('args', {}).get('command', '')}"
    if plan_step["function"] == "web_search":
        return f"web_search {plan_step.get('args', {}).get('query', '')}"
    args = plan_step.get("args", {})
    arg_text = " ".join(f"{key}={value}" for key, value in args.items())
    return f"{plan_step['function']} {arg_text}".strip()


def format_agent_output(results: Iterable[dict], *, final_answer: str = "") -> str:
    """Format executed steps and model analysis for terminal display."""
    lines = ["Agent diagnostic run completed."]
    if final_answer:
        lines.extend(["", "Assistant analysis:", final_answer])

    lines.append("")
    lines.append("Commands and output:")
    for item in results:
        plan_step = item["step"]
        result = item["result"]
        status = "OK" if result.get("success", True) else "FAILED"
        summary = summarize_result(plan_step["function"], result)
        lines.append("")
        lines.append(f"- {status} {display_command(plan_step)}")
        if summary:
            lines.append(f"  Summary: {summary}")
        output = _result_output_text(result)
        if output:
            lines.append("  Output:")
            lines.extend(f"    {line}" for line in _truncate_text(output, MAX_DISPLAY_CHARS).splitlines())

    recommendations = recommend_next_steps(results)
    if recommendations:
        lines.extend(["", "Recommendations:"])
        lines.extend(f"- {item}" for item in recommendations)
    return "\n".join(lines)


def recommend_next_steps(results: Iterable[dict]) -> list[str]:
    """Suggest next actions from executed observations."""
    recommendations = []
    for item in results:
        plan_step = item["step"]
        result = item["result"]
        if result.get("success") is False:
            recommendations.append(
                f"Review {plan_step['function']} failure before making changes: {result.get('error', 'unknown error')}"
            )
        if plan_step["function"] == "run_nmap_scan":
            ports = [port for port in result.get("ports_found", []) if port.get("state") == "open"]
            if ports:
                recommendations.append(
                    "Review exposed services and decide whether firewall or service hardening is needed."
                )
    if not recommendations:
        recommendations.append("No admin changes recommended from these read-only checks.")
    return recommendations


def _execute_agent_steps(
    steps: Iterable[dict],
    *,
    resolver: Callable[[str], Callable],
    finding_recorder: Callable[[dict, dict], object],
    inventory_updater: Callable[[dict, dict], object],
    approval_callback: ApprovalCallback | None,
    approval_mode: ApprovalMode | None,
) -> list[dict]:
    """Execute plan steps and persist each observation."""
    logger = logging.getLogger("cli_assistant.agent")
    results = []

    for plan_step in steps:
        function_name = plan_step["function"]
        if function_name not in AGENT_FUNCTIONS:
            results.append(
                {
                    "step": plan_step,
                    "success": False,
                    "error": f"Function is not available to the assistant: {function_name}",
                }
            )
            continue

        command = {"function": function_name, "args": plan_step.get("args", {})}
        try:
            if function_name == "run_bash":
                result = _run_bash_step(
                    command["args"],
                    approval_callback=approval_callback,
                    approval_mode=approval_mode,
                )
            elif function_name == "web_search":
                result = _run_web_search_step(
                    command["args"],
                    resolver=resolver,
                    approval_callback=approval_callback,
                    approval_mode=approval_mode,
                )
            else:
                result = resolver(function_name)(**command["args"])
        except Exception as exc:
            logger.exception("Agent step failed", extra={"function": function_name})
            result = {"success": False, "error": str(exc), "error_type": "agent_step_failed"}

        if function_name != "web_search":
            try:
                finding_recorder(command, result)
                inventory_updater(command, result)
            except Exception:
                logger.warning("Could not persist agent observation", exc_info=True)

        results.append({"step": plan_step, "result": result})

    return results


def _run_bash_step(
    args: dict,
    approval_callback: ApprovalCallback | None = None,
    approval_mode: ApprovalMode | None = None,
) -> dict:
    command = str(args.get("command", ""))
    timeout = int(args.get("timeout", 30))
    decision = classify_bash_command(command, mode=approval_mode)
    if decision.action == "auto_allow":
        approval = "power_mode" if not decision.require_safe else "not_required"
        record_audit_event("command_execute", {"command": command, "approval": approval})
        if not decision.require_safe:
            return run_bash(
                command=command,
                timeout=_interactive_timeout(command, timeout),
                require_safe=False,
                interactive=_needs_interactive_terminal(command),
            )
        if "timeout" in args:
            return run_bash(command=command, timeout=timeout)
        return run_bash(command=command)

    if decision.action == "deny":
        record_audit_event("command_blocked", {"command": command, "reason": decision.reason})
        return {"success": False, "error": decision.reason, "error_type": "policy_blocked"}

    if approval_callback is None:
        record_audit_event("command_approval_missing", {"command": command, "reason": decision.reason})
        return {
            "success": False,
            "error": f"Approval required before running: {command}",
            "error_type": "approval_required",
            "approval_reason": decision.reason,
        }

    approved = approval_callback(command, decision.reason)
    record_audit_event("command_approval", {"command": command, "reason": decision.reason, "approved": approved})
    if not approved:
        return {
            "success": False,
            "error": f"Command was not approved: {command}",
            "error_type": "approval_required",
        }

    interactive = _needs_interactive_terminal(command)
    record_audit_event(
        "command_execute",
        {"command": command, "approval": "user_approved", "interactive": interactive},
    )
    return run_bash(
        command=command,
        timeout=_interactive_timeout(command, timeout),
        require_safe=False,
        interactive=interactive,
    )


def _run_web_search_step(
    args: dict,
    *,
    resolver: Callable[[str], Callable],
    approval_callback: ApprovalCallback | None = None,
    approval_mode: ApprovalMode | None = None,
) -> dict:
    query = str(args.get("query", "")).strip()
    if not query:
        return {"success": False, "error": "Search query cannot be empty", "error_type": "invalid_search"}

    reason = f"Web search can reveal information outside the local machine. Query: {query}"
    if approval_mode == "power":
        record_audit_event("web_search_execute", {"query_preview": query[:120], "approval": "power_mode"})
        return resolver("web_search")(**args)

    if approval_callback is None:
        record_audit_event("web_search_blocked", {"query_preview": query[:120]})
        return {"success": False, "error": reason, "error_type": "approval_required"}

    approved = approval_callback("web_search", reason)
    record_audit_event("web_search_approval", {"query_preview": query[:120], "approved": approved})
    if not approved:
        return {
            "success": False,
            "error": "Web search was not approved",
            "error_type": "approval_required",
        }

    record_audit_event("web_search_execute", {"query_preview": query[:120]})
    return resolver("web_search")(**args)


def _needs_interactive_terminal(command: str) -> bool:
    """Return whether an approved command should inherit terminal stdio."""
    argv = _shell_words(command)
    if not argv:
        return False
    if argv[0] == "sudo" and len(argv) > 1:
        return True
    return argv[0] == "ssh"


def _interactive_timeout(command: str, timeout: int) -> int | None:
    """Return the timeout to use for approved interactive shell commands."""
    return None if _is_ssh_command(command) else timeout


def _is_ssh_command(command: str) -> bool:
    argv = _shell_words(command)
    if not argv:
        return False
    if argv[0] == "ssh":
        return True
    return len(argv) > 1 and argv[0] == "sudo" and argv[1] == "ssh"


def _shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.strip().split()


def _review_observations(user_input: str, plan: dict, results: list[dict]) -> dict | None:
    """Ask the model whether command output answers the user or needs follow-up."""
    user_prompt = "\n".join(
        [
            f"User request:\n{user_input.strip()}",
            "",
            f"Plan target: {plan.get('target') or 'unknown'}",
            "",
            "Command observations:",
            _observations_for_model(results),
        ]
    )
    try:
        review = parse_json_with_provider(observer_prompt(), user_prompt)
    except Exception:
        return None
    return review if isinstance(review, dict) else None


def _steps_from_review(review: dict, user_input: str) -> list[dict]:
    """Convert model-requested follow-up commands into executable agent steps."""
    searches = review.get("searches")
    commands = review.get("commands")

    steps = []
    if isinstance(searches, list):
        for item in searches[:2]:
            if not isinstance(item, dict):
                continue
            query = str(item.get("query", "")).strip()
            reason = str(item.get("reason") or "Research current online information")
            if query:
                steps.append(step("web_search", {"query": query, "max_results": 5}, reason))

    if not isinstance(commands, list):
        return steps

    for item in commands[:4]:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", "")).strip()
        reason = str(item.get("reason") or "Run follow-up diagnostic command")
        if not command:
            continue
        if external_scan_reason(command, user_input):
            continue
        steps.append(step("run_bash", {"command": command}, reason))
    return steps


def _observations_for_model(results: Iterable[dict]) -> str:
    chunks = []
    for index, item in enumerate(results, start=1):
        plan_step = item["step"]
        result = item["result"]
        chunks.append(
            "\n".join(
                [
                    f"Observation {index}",
                    f"Command: {display_command(plan_step)}",
                    f"Reason: {plan_step.get('reason', '')}",
                    f"Success: {result.get('success', True)}",
                    f"Exit code: {result.get('exit_code', 'n/a')}",
                    "Output:",
                    _truncate_text(_result_output_text(result), MAX_OBSERVATION_CHARS) or "(no output)",
                ]
            )
        )
    return "\n\n".join(chunks)


def _result_output_text(result: dict) -> str:
    for key in ("stdout", "stderr", "output", "network_summary"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    if result.get("results"):
        lines = []
        for index, item in enumerate(result["results"], start=1):
            lines.append(f"{index}. {item.get('title') or item.get('url')}")
            lines.append(f"   URL: {item.get('url')}")
            if item.get("snippet"):
                lines.append(f"   Snippet: {item.get('snippet')}")
        return "\n".join(lines)
    if result.get("ports_found"):
        lines = []
        for port in result["ports_found"]:
            lines.append(
                f"{port.get('port')}/{port.get('protocol', 'tcp')} "
                f"{port.get('state', '')} {port.get('service', '')}".strip()
            )
        return "\n".join(lines)
    return ""


def _truncate_text(value: str, limit: int) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + "\n...[truncated]"

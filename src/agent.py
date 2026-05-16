"""Safe multi-step assistant workflows for homelab network administration."""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
from typing import Callable, Iterable

from . import core_functions
from .bash_tool import command_requires_approval, run_bash, validate_bash_command
from .command_result import needs_clarification
from .deterministic_parser import COMMON_DOMAINS
from .dispatcher import parse_command
from .findings import record_finding, summarize_result
from .knowledgebase import update_inventory
from .llm_providers import chat_with_provider, parse_json_with_provider
from .memory import append_chat_turn, load_chat_memory
from .utils import format_output
from .validation.network import validate_network_target

AGENT_TRIGGERS = (
    "audit",
    "check",
    "diagnose",
    "investigate",
    "probe",
    "scan",
    "security check",
    "troubleshoot",
    "triage",
    "check health",
    "look into",
    "what is wrong",
    "why is",
)
LOCAL_NETWORK_TERMS = (
    "cidr",
    "default gateway",
    "ip address",
    "network am i on",
    "network is the machine on",
    "network machine is on",
    "network is this",
    "network the machine is on",
    "network this machine is on",
    "subnet",
)
LOG_REVIEW_TERMS = (
    "check logs",
    "errors in the logs",
    "look through logs",
    "parse logs",
    "parse through logs",
    "read logs",
    "review logs",
    "scan logs",
)
TARGET_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "check",
        "diagnose",
        "for",
        "health",
        "into",
        "investigate",
        "is",
        "look",
        "my",
        "network",
        "of",
        "on",
        "server",
        "the",
        "to",
        "triage",
        "troubleshoot",
        "what",
        "why",
        "wrong",
    }
)
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
AGENT_FUNCTIONS = READ_ONLY_FUNCTIONS | {"run_bash"}
TARGET_PATTERN = r"([a-zA-Z0-9][a-zA-Z0-9.-]*(?:/\d{1,2})?)"
LOCALHOST_TERMS = ("localhost", "local host", "this host", "this machine", "local machine")
SECURITY_TERMS = ("vulnerab", "security", "exposed", "open port", "listening", "attack surface")
NON_TARGET_WORDS = TARGET_STOPWORDS | {
    "attack",
    "exposed",
    "ports",
    "security",
    "services",
    "vulnerabilities",
    "vulnerability",
}
CHAT_PATTERNS = (
    "hello",
    "hi",
    "hey",
    "thanks",
    "thank you",
    "what can you do",
    "help",
)
BASH_PREFIXES = ("bash ", "run bash ", "shell ")
SHELL_PLANNER_TERMS = (
    "broken",
    "container",
    "cpu",
    "disk",
    "docker",
    "down",
    "firewall",
    "journal",
    "log",
    "memory",
    "not working",
    "nmap",
    "open port",
    "port",
    "service",
    "systemd",
    "why",
)
SCAN_COMMANDS = {"masscan", "nmap", "nikto"}
MAX_OBSERVATION_CHARS = 4000
MAX_DISPLAY_CHARS = 8000
MAX_AGENT_LOOPS = 3


ApprovalCallback = Callable[[str, str | None], bool]
_PENDING_REQUEST: dict | None = None


def handle_agent_message(user_input: str, approval_callback: ApprovalCallback | None = None) -> str:
    """Handle every user message through the assistant agent path."""
    global _PENDING_REQUEST

    original_input = user_input
    if _PENDING_REQUEST:
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

    result = _run_bash_request(user_input)
    if result is None:
        command = build_agent_plan(user_input)
        if command is None or _should_try_shell_planner(user_input, command):
            command = build_shell_agent_plan(user_input) or command
        command = _as_agent_plan(command or parse_command(user_input))
        if _should_chat(command):
            response = _chat_response(user_input)
            append_chat_turn(user_input, response)
            return response
        if command.get("status") == "needs_clarification":
            _PENDING_REQUEST = {
                "request": original_input,
                "question": command.get("question", "Please clarify the request."),
            }
        result = _run_parsed_request(
            command,
            approval_callback=approval_callback,
            user_input=user_input,
        )
    elif isinstance(result, dict) and result.get("status") == "agent_plan":
        result = _run_parsed_request(
            result,
            approval_callback=approval_callback,
            user_input=user_input,
        )

    if isinstance(result, dict) and result.get("status") == "needs_clarification":
        _PENDING_REQUEST = {
            "request": original_input,
            "question": result.get("question", "Please clarify the request."),
        }

    response = format_output(result) if isinstance(result, dict) else str(result)
    append_chat_turn(user_input, response)
    return response


def build_agent_plan(user_input: str) -> dict | None:
    """Build a bounded safe-mode diagnostic plan, or return None if not applicable."""
    text = " ".join(user_input.strip().lower().split())
    if not text:
        return None

    if _is_local_network_request(text):
        return {
            "status": "agent_plan",
            "mode": "safe",
            "target": "local-machine",
            "steps": _local_network_steps(),
            "source": "agent",
        }

    if _is_log_review_request(text):
        return {
            "status": "agent_plan",
            "mode": "safe",
            "target": "local-logs",
            "steps": _local_log_steps(),
            "source": "agent",
        }

    if not any(trigger in text for trigger in AGENT_TRIGGERS):
        return None

    if _is_localhost_security_request(text):
        return {
            "status": "agent_plan",
            "mode": "safe",
            "target": "localhost",
            "steps": _security_steps("localhost", "hostname"),
            "source": "agent",
        }

    target = _extract_target(text)
    if not target:
        return needs_clarification(
            "Which host or subnet should I investigate? For example: 192.168.1.10 or 192.168.1.0/24.",
            ["target_or_network"],
        )

    is_valid, error, target_type = validate_network_target(target)
    if not is_valid:
        return needs_clarification(error or "Please provide a valid host, IP, or CIDR target.", ["target"])

    if target_type == "cidr":
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 256:
            return needs_clarification(
                "Safe mode can investigate up to a /24 at a time. Which smaller subnet should I use?",
                ["narrower_network"],
            )
        steps = _security_steps(target, target_type) if _is_security_request(text) else _network_steps(target)
    else:
        steps = _security_steps(target, target_type) if _is_security_request(text) else _host_steps(target, target_type)

    return {
        "status": "agent_plan",
        "mode": "safe",
        "target": target,
        "steps": steps,
        "source": "agent",
    }


def build_shell_agent_plan(user_input: str) -> dict | None:
    """Ask the local model for a bounded shell plan for local diagnostics."""
    system_prompt = _shell_planner_prompt()
    memory = load_chat_memory()
    user_prompt = "\n".join(
        [
            f"User request: {user_input.strip()}",
            "",
            "Recent memory:",
            memory or "(none)",
        ]
    )
    try:
        plan = parse_json_with_provider(system_prompt, user_prompt)
    except Exception:
        return None

    if not isinstance(plan, dict) or plan.get("status") == "needs_clarification":
        question = plan.get("question") if isinstance(plan, dict) else None
        if question:
            return needs_clarification(question, plan.get("missing", []))
        return None

    commands = plan.get("commands")
    if not isinstance(commands, list) or not commands:
        return None

    steps = []
    for item in commands[:6]:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", "")).strip()
        reason = str(item.get("reason") or "Run local diagnostic command")
        if not command:
            continue
        external_reason = _external_scan_reason(command, user_input)
        if external_reason:
            return needs_clarification(external_reason, ["external_scan_confirmation"])
        steps.append(_step("run_bash", {"command": command}, reason))

    if not steps:
        return None

    return {
        "status": "agent_plan",
        "mode": "power",
        "target": str(plan.get("target") or "local-machine"),
        "steps": steps,
        "source": "llm_shell_planner",
    }


def build_diagnostic_plan(user_input: str) -> dict | None:
    """Compatibility wrapper for callers that want explicit diagnostic planning."""
    return build_agent_plan(user_input)


def execute_agent_plan(
    plan: dict,
    *,
    function_resolver: Callable[[str], Callable] | None = None,
    finding_recorder: Callable[[dict, dict], object] = record_finding,
    inventory_updater: Callable[[dict, dict], object] = update_inventory,
    approval_callback: ApprovalCallback | None = None,
    user_input: str = "",
    observe_with_model: bool = False,
) -> dict:
    """Execute an agent plan, optionally letting the model inspect observations."""
    resolver = function_resolver or (lambda name: getattr(core_functions, name))
    results = _execute_agent_steps(
        plan.get("steps", []),
        resolver=resolver,
        finding_recorder=finding_recorder,
        inventory_updater=inventory_updater,
        approval_callback=approval_callback,
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
            )
            results.extend(more_results)

    output = _format_agent_output(results, final_answer=final_answer)
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
            "recommendations": _recommend_next_steps(results),
        }

    return {
        "success": True,
        "agent": True,
        "mode": plan.get("mode", "safe"),
        "target": plan.get("target"),
        "steps": results,
        "output": output,
        "recommendations": _recommend_next_steps(results),
    }


def _execute_agent_steps(
    steps: Iterable[dict],
    *,
    resolver: Callable[[str], Callable],
    finding_recorder: Callable[[dict, dict], object],
    inventory_updater: Callable[[dict, dict], object],
    approval_callback: ApprovalCallback | None,
) -> list[dict]:
    """Execute plan steps and persist each observation."""
    logger = logging.getLogger("network_cli.agent")
    results = []

    for step in steps:
        function_name = step["function"]
        if function_name not in AGENT_FUNCTIONS:
            results.append(
                {
                    "step": step,
                    "success": False,
                    "error": f"Function is not allowed in safe mode: {function_name}",
                }
            )
            continue

        command = {"function": function_name, "args": step.get("args", {})}
        try:
            if function_name == "run_bash":
                result = _run_bash_step(
                    command["args"],
                    approval_callback=approval_callback,
                )
            else:
                result = resolver(function_name)(**command["args"])
        except Exception as exc:
            logger.exception("Agent step failed", extra={"function": function_name})
            result = {"success": False, "error": str(exc), "error_type": "agent_step_failed"}

        try:
            finding_recorder(command, result)
            inventory_updater(command, result)
        except Exception:
            logger.warning("Could not persist agent observation", exc_info=True)

        results.append({"step": step, "result": result})

    return results


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


def _as_agent_plan(command: dict) -> dict:
    """Route approved read-only commands through the agent executor."""
    if command.get("status") == "agent_plan":
        return command

    function_name = command.get("function")
    if command.get("status") == "ready" and function_name in READ_ONLY_FUNCTIONS:
        return {
            "status": "agent_plan",
            "mode": "safe",
            "target": _target_from_args(command.get("args", {})),
            "steps": [
                _step(
                    function_name,
                    command.get("args", {}),
                    "Run approved read-only command from parsed user request",
                )
            ],
            "source": "agent",
        }

    return command


def _target_from_args(args: dict) -> str | None:
    return args.get("host") or args.get("target") or args.get("network")


def _run_bash_request(user_input: str) -> dict | None:
    text = user_input.strip()
    lowered = text.lower()
    for prefix in BASH_PREFIXES:
        if lowered.startswith(prefix):
            command = text[len(prefix) :].strip()
            return {
                "status": "agent_plan",
                "mode": "safe",
                "target": "local-machine",
                "steps": [
                    _step(
                        "run_bash",
                        {"command": command},
                        "Run approved read-only bash command from user request",
                    )
                ],
                "source": "agent",
            }
    return None


def _run_bash_step(args: dict, approval_callback: ApprovalCallback | None = None) -> dict:
    command = str(args.get("command", ""))
    timeout = int(args.get("timeout", 30))
    is_allowed, reason = validate_bash_command(command)
    if is_allowed:
        return run_bash(command=command, timeout=timeout)

    requires_approval, approval_reason = command_requires_approval(command)
    if not requires_approval or approval_callback is None:
        return {"success": False, "error": reason, "error_type": "policy_blocked"}

    if not approval_callback(command, approval_reason):
        return {
            "success": False,
            "error": f"Command was not approved: {command}",
            "error_type": "approval_required",
        }

    return run_bash(command=command, timeout=timeout, require_safe=False)


def _persist_observation(command: dict, result: dict) -> None:
    try:
        record_finding(command, result)
        update_inventory(command, result)
    except Exception:
        logging.getLogger("network_cli.agent").warning(
            "Could not persist assistant observation", exc_info=True
        )


def _is_chat(user_input: str) -> bool:
    text = " ".join(user_input.lower().split())
    return text in CHAT_PATTERNS


def _chat_response(user_input: str) -> str:
    memory = load_chat_memory()
    prompt = (
        "You are a concise homelab network and server admin assistant. "
        "Use the recent chat memory for continuity when relevant. "
        "Do not claim you executed tools in chat mode. "
        "Recommend state-changing admin actions instead of performing them.\n\n"
        f"Recent chat memory:\n{memory or '(none)'}"
    )
    try:
        return chat_with_provider(prompt, user_input)
    except Exception:
        return (
            "I can help with safe homelab diagnostics, approved network tools, and read-only bash. "
            "Ask me to investigate a host or run `bash <read-only command>`."
        )


def _should_chat(command: dict) -> bool:
    return False


def _should_try_shell_planner(user_input: str, command: dict | None) -> bool:
    text = " ".join(user_input.lower().split())
    if command is None:
        return any(term in text for term in SHELL_PLANNER_TERMS)
    if command.get("status") == "needs_clarification":
        return any(term in text for term in SHELL_PLANNER_TERMS)
    return False


def _review_observations(user_input: str, plan: dict, results: list[dict]) -> dict | None:
    """Ask the model whether command output answers the user or needs follow-up."""
    prompt = _observer_prompt()
    observations = _observations_for_model(results)
    user_prompt = "\n".join(
        [
            f"User request:\n{user_input.strip()}",
            "",
            f"Plan target: {plan.get('target') or 'unknown'}",
            "",
            "Command observations:",
            observations,
        ]
    )
    try:
        review = parse_json_with_provider(prompt, user_prompt)
    except Exception:
        return None
    return review if isinstance(review, dict) else None


def _steps_from_review(review: dict, user_input: str) -> list[dict]:
    """Convert model-requested follow-up commands into executable agent steps."""
    commands = review.get("commands")
    if not isinstance(commands, list):
        return []

    steps = []
    for item in commands[:4]:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", "")).strip()
        reason = str(item.get("reason") or "Run follow-up diagnostic command")
        if not command:
            continue
        external_reason = _external_scan_reason(command, user_input)
        if external_reason:
            continue
        steps.append(_step("run_bash", {"command": command}, reason))
    return steps


def _observer_prompt() -> str:
    return """
You are a helpful local homelab assistant reviewing command output after executing diagnostics.

Return only JSON. Do not use Markdown.

Choose one response shape:
{"answer":"concise answer for the user, including relevant command findings"}
{"commands":[{"command":"single read-only follow-up command","reason":"why it is needed"}]}
{"status":"needs_clarification","question":"one specific question for the user","missing":["field_name"]}

Rules:
- Use the command observations directly. Do not pretend a command ran if it is not listed.
- If the observations answer the user, provide the answer.
- If key information is missing and a safe local read-only command can get it, request up to 4 follow-up commands.
- If a human detail is required, ask exactly one clear question.
- Follow-up commands must be local only, no SSH, no sudo, no mutation, no shell chains, no redirection, no inline scripts.
- For scan output, call out open ports/services explicitly.
""".strip()


def _shell_planner_prompt() -> str:
    return """
You are a local-first homelab terminal agent. Convert the user's natural language request into a short JSON command plan for the local machine only.

Return only JSON. Do not use Markdown.

Schema:
{
  "target": "local-machine",
  "commands": [
    {"command": "single command", "reason": "why this observation is useful"}
  ]
}

Rules:
- Prefer read-only diagnostic commands that inspect state: systemctl status/show/is-active, journalctl reads, docker ps/logs/inspect, ss, ip, df, free, uptime, ps, top batch snapshots, ls, find, grep, awk, sed reads, cat/head/tail.
- No SSH.
- Do not install packages, change services, edit files, remove files, restart services, stop containers, or alter firewall rules.
- Do not use sudo.
- Use one command per plan item. Avoid shell chains, pipes, redirection, command substitution, and inline scripts.
- Keep plans to 3-6 commands.
- Preserve explicit user-requested safe flags such as nmap -Pn.
- For vulnerability or port scans, only use private/local targets unless the user explicitly confirms an external target.
- If the request cannot be investigated from the local machine, return {"status":"needs_clarification","question":"...","missing":["..."]}.
""".strip()


def _host_steps(target: str, target_type: str | None) -> list[dict]:
    steps = []
    if target_type == "hostname":
        steps.append(_step("dns_lookup", {"host": target}, "Resolve the hostname"))
    steps.extend(
        [
            _step("ping", {"host": target}, "Check basic reachability"),
            _step("traceroute", {"host": target}, "Inspect the path to the host"),
            _step("run_nmap_scan", {"target": target, "top_ports": 10}, "Check common exposed services"),
        ]
    )
    return steps


def _network_steps(target: str) -> list[dict]:
    return [
        _step("discover_hosts", {"network": target, "scan_method": "arp"}, "Find active hosts"),
        _step("run_nmap_scan", {"target": target, "top_ports": 10}, "Check common exposed services"),
    ]


def _security_steps(target: str, target_type: str | None) -> list[dict]:
    if target_type == "cidr":
        return [
            _step("discover_hosts", {"network": target, "scan_method": "arp"}, "Find active hosts"),
            _step(
                "run_nmap_scan",
                {"target": target, "top_ports": 100},
                "Scan common ports for exposed services",
            ),
        ]

    steps = []
    if target == "localhost":
        steps.extend(_local_context_steps())
    elif target_type == "hostname":
        steps.append(_step("dns_lookup", {"host": target}, "Resolve the hostname"))

    steps.extend(
        [
            _step("ping", {"host": target}, "Check basic reachability"),
            _step("traceroute", {"host": target}, "Inspect the path to the host"),
            _step(
                "run_nmap_scan",
                {"target": target, "top_ports": 100},
                "Scan common ports for exposed services",
            ),
        ]
    )
    return steps


def _local_context_steps() -> list[dict]:
    return [
        _step(
            "run_bash",
            {"command": "ss -tulpen"},
            "List local TCP and UDP listening sockets with process context",
        ),
        _step("run_bash", {"command": "ip addr show"}, "Review local interface exposure"),
    ]


def _local_network_steps() -> list[dict]:
    return [
        _step(
            "run_bash",
            {"command": "ip -brief -4 addr show scope global"},
            "Find local IPv4 addresses and CIDR prefixes",
        ),
        _step(
            "run_bash",
            {"command": "ip route show"},
            "Find default gateway and connected routes",
        ),
        _step("run_bash", {"command": "hostname -I"}, "List host IP addresses"),
    ]


def _local_log_steps() -> list[dict]:
    return [
        _step(
            "run_bash",
            {"command": "journalctl -n 200 -p warning"},
            "Review recent warning and error logs",
        ),
        _step(
            "run_bash",
            {"command": "systemctl --failed"},
            "Check failed systemd units",
        ),
    ]


def _external_scan_reason(command: str, user_input: str) -> str | None:
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


def _is_local_network_request(text: str) -> bool:
    asks_local_host = any(term in text for term in LOCALHOST_TERMS) or "machine" in text
    asks_network = any(term in text for term in LOCAL_NETWORK_TERMS)
    return asks_network and (asks_local_host or "am i on" in text or "this" in text)


def _is_log_review_request(text: str) -> bool:
    return any(term in text for term in LOG_REVIEW_TERMS)


def _is_localhost_security_request(text: str) -> bool:
    return any(term in text for term in LOCALHOST_TERMS) and any(
        term in text for term in SECURITY_TERMS
    )


def _is_security_request(text: str) -> bool:
    return any(term in text for term in SECURITY_TERMS)


def _step(function: str, args: dict, reason: str) -> dict:
    return {"function": function, "args": args, "reason": reason}


def _extract_target(text: str) -> str | None:
    for pattern in (
        rf"\b(?:host|server|device|target|subnet|network) {TARGET_PATTERN}\b",
        rf"\b(?:on|for|to|into) {TARGET_PATTERN}\b",
    ):
        match = re.search(pattern, text)
        if match:
            target = _normalize_target(match.group(1))
            if _is_named_target(target):
                return target

    for token in re.findall(TARGET_PATTERN, text):
        target = _normalize_target(token)
        if target not in NON_TARGET_WORDS and _is_valid_fallback_target(target):
            return target
    return None


def _normalize_target(target: str) -> str:
    return COMMON_DOMAINS.get(target.strip(".").lower(), target.strip())


def _is_valid_fallback_target(target: str) -> bool:
    if target in COMMON_DOMAINS.values() or "." in target or "/" in target:
        return validate_network_target(target)[0]
    return False


def _is_named_target(target: str) -> bool:
    return target not in NON_TARGET_WORDS and validate_network_target(target)[0]


def _summarize_agent_results(results: Iterable[dict]) -> str:
    lines = ["Safe diagnostic plan completed."]
    for item in results:
        step = item["step"]
        result = item["result"]
        status = "OK" if result.get("success", True) else "FAILED"
        summary = summarize_result(step["function"], result)
        lines.append(f"- {status} {step['function']}: {summary}")
    return "\n".join(lines)


def _format_agent_output(results: Iterable[dict], *, final_answer: str = "") -> str:
    lines = ["Agent diagnostic run completed."]
    if final_answer:
        lines.extend(["", "Assistant analysis:", final_answer])

    lines.append("")
    lines.append("Commands and output:")
    for item in results:
        step = item["step"]
        result = item["result"]
        status = "OK" if result.get("success", True) else "FAILED"
        function_name = step["function"]
        command_text = _display_command(step)
        summary = summarize_result(function_name, result)
        lines.append("")
        lines.append(f"- {status} {command_text}")
        if summary:
            lines.append(f"  Summary: {summary}")
        output = _result_output_text(result)
        if output:
            lines.append("  Output:")
            lines.extend(f"    {line}" for line in _truncate_text(output, MAX_DISPLAY_CHARS).splitlines())

    recommendations = _recommend_next_steps(results)
    if recommendations:
        lines.extend(["", "Recommendations:"])
        lines.extend(f"- {item}" for item in recommendations)
    return "\n".join(lines)


def _observations_for_model(results: Iterable[dict]) -> str:
    chunks = []
    for index, item in enumerate(results, start=1):
        step = item["step"]
        result = item["result"]
        chunks.append(
            "\n".join(
                [
                    f"Observation {index}",
                    f"Command: {_display_command(step)}",
                    f"Reason: {step.get('reason', '')}",
                    f"Success: {result.get('success', True)}",
                    f"Exit code: {result.get('exit_code', 'n/a')}",
                    "Output:",
                    _truncate_text(_result_output_text(result), MAX_OBSERVATION_CHARS) or "(no output)",
                ]
            )
        )
    return "\n\n".join(chunks)


def _display_command(step: dict) -> str:
    if step["function"] == "run_bash":
        return f"$ {step.get('args', {}).get('command', '')}"
    args = step.get("args", {})
    arg_text = " ".join(f"{key}={value}" for key, value in args.items())
    return f"{step['function']} {arg_text}".strip()


def _result_output_text(result: dict) -> str:
    for key in ("stdout", "stderr", "output", "network_summary"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
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


def _recommend_next_steps(results: Iterable[dict]) -> list[str]:
    recommendations = []
    for item in results:
        step = item["step"]
        result = item["result"]
        if result.get("success") is False:
            recommendations.append(
                f"Review {step['function']} failure before making changes: {result.get('error', 'unknown error')}"
            )
        if step["function"] == "run_nmap_scan":
            ports = [p for p in result.get("ports_found", []) if p.get("state") == "open"]
            if ports:
                recommendations.append(
                    "Review exposed services and decide whether firewall or service hardening is needed."
                )
    if not recommendations:
        recommendations.append("No admin changes recommended from these read-only checks.")
    return recommendations

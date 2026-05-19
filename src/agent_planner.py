"""Plan construction for local agent workflows."""

from __future__ import annotations

import ipaddress
import re
import shlex

from .agent_prompts import shell_planner_prompt
from .command_result import needs_clarification
from .deterministic_parser import COMMON_DOMAINS
from .llm_providers import parse_json_with_provider
from .memory import load_chat_memory, load_runtime_memory
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
AGENT_FUNCTIONS = READ_ONLY_FUNCTIONS | {"run_bash", "web_search"}
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
    "package",
    "packages",
    "install",
    "update",
    "upgrade",
    "remove",
    "not working",
    "nmap",
    "open port",
    "port",
    "service",
    "systemd",
    "why",
)
SCAN_COMMANDS = {"masscan", "nmap", "nikto"}
WEB_RESEARCH_TERMS = (
    "documentation",
    "docs",
    "latest",
    "most recent",
    "online",
    "search",
    "web",
)


def build_agent_plan(user_input: str) -> dict | None:
    """Build a bounded safe-mode diagnostic plan, or return None if not applicable."""
    text = " ".join(user_input.strip().lower().split())
    if not text:
        return None

    if _is_local_network_request(text):
        return _agent_plan("safe", "local-machine", _local_network_steps())

    if _is_log_review_request(text):
        return _agent_plan("safe", "local-logs", _local_log_steps())

    if _is_web_research_request(text):
        return _agent_plan(
            "power",
            "web",
            [step("web_search", {"query": user_input.strip(), "max_results": 5}, "Research current online information")],
        )

    if not any(trigger in text for trigger in AGENT_TRIGGERS):
        return None

    if _is_localhost_security_request(text):
        return _agent_plan("safe", "localhost", _security_steps("localhost", "hostname"))

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

    return _agent_plan("safe", target, steps)


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
    text = " ".join(user_input.lower().split())
    if command is None:
        return any(term in text for term in SHELL_PLANNER_TERMS)
    if command.get("status") == "needs_clarification":
        return any(term in text for term in SHELL_PLANNER_TERMS)
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


def _is_web_research_request(text: str) -> bool:
    if not any(term in text for term in WEB_RESEARCH_TERMS):
        return False
    return any(
        term in text
        for term in (
            "compose",
            "docker",
            "install",
            "setup",
            "set up",
            "configure",
            "documentation",
            "docs",
            "search",
            "online",
        )
    )


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


def _host_steps(target: str, target_type: str | None) -> list[dict]:
    steps = []
    if target_type == "hostname":
        steps.append(step("dns_lookup", {"host": target}, "Resolve the hostname"))
    steps.extend(
        [
            step("ping", {"host": target}, "Check basic reachability"),
            step("traceroute", {"host": target}, "Inspect the path to the host"),
            step("run_nmap_scan", {"target": target, "top_ports": 10}, "Check common exposed services"),
        ]
    )
    return steps


def _network_steps(target: str) -> list[dict]:
    return [
        step("discover_hosts", {"network": target, "scan_method": "arp"}, "Find active hosts"),
        step("run_nmap_scan", {"target": target, "top_ports": 10}, "Check common exposed services"),
    ]


def _security_steps(target: str, target_type: str | None) -> list[dict]:
    if target_type == "cidr":
        return [
            step("discover_hosts", {"network": target, "scan_method": "arp"}, "Find active hosts"),
            step("run_nmap_scan", {"target": target, "top_ports": 100}, "Scan common ports for exposed services"),
        ]

    steps = []
    if target == "localhost":
        steps.extend(_local_context_steps())
        steps.append(step("run_nmap_scan", {"target": target, "top_ports": 100}, "Scan common ports for exposed services"))
        return steps
    if target_type == "hostname":
        steps.append(step("dns_lookup", {"host": target}, "Resolve the hostname"))

    steps.extend(
        [
            step("ping", {"host": target}, "Check basic reachability"),
            step("traceroute", {"host": target}, "Inspect the path to the host"),
            step("run_nmap_scan", {"target": target, "top_ports": 100}, "Scan common ports for exposed services"),
        ]
    )
    return steps


def _local_context_steps() -> list[dict]:
    return [
        step("run_bash", {"command": "ss -tulpen"}, "List local TCP and UDP listening sockets with process context"),
        step("run_bash", {"command": "ip addr show"}, "Review local interface exposure"),
    ]


def _local_network_steps() -> list[dict]:
    return [
        step("run_bash", {"command": "ip -brief -4 addr show scope global"}, "Find local IPv4 addresses and CIDR prefixes"),
        step("run_bash", {"command": "ip route show"}, "Find default gateway and connected routes"),
        step("run_bash", {"command": "hostname -I"}, "List host IP addresses"),
    ]


def _local_log_steps() -> list[dict]:
    return [
        step("run_bash", {"command": "journalctl -n 200 -p warning"}, "Review recent warning and error logs"),
        step("run_bash", {"command": "systemctl --failed"}, "Check failed systemd units"),
    ]


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
    return any(term in text for term in LOCALHOST_TERMS) and any(term in text for term in SECURITY_TERMS)


def _is_security_request(text: str) -> bool:
    return any(term in text for term in SECURITY_TERMS)


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

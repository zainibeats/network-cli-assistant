"""Rules-first parser for obvious network requests."""

import re

from .command_result import command_call, needs_clarification
from .validation.network import validate_network_target, validate_target

COMMON_DOMAINS = {
    "archive": "archive.org",
    "github": "github.com",
    "google": "google.com",
    "mullvad": "mullvad.net",
    "reddit": "reddit.com",
    "stackoverflow": "stackoverflow.com",
    "wikipedia": "wikipedia.org",
}

BROAD_NETWORK_TERMS = {"lan", "local network", "my network", "network", "subnet"}
TARGET_PATTERN = r"([a-zA-Z0-9][a-zA-Z0-9.-]*(?:/\d{1,2})?)"


def parse_deterministic(user_input: str) -> dict | None:
    """
    Parse common network requests without using a model.

    Returns:
        Command result dict, clarification dict, or None when the LLM should try.
    """
    text = _normalize_text(user_input)
    if not text:
        return None

    broad_result = _parse_broad_request(text)
    if broad_result:
        return broad_result

    for parser in (
        _parse_netstat,
        _parse_ping,
        _parse_traceroute,
        _parse_dns_lookup,
        _parse_discovery,
        _parse_nmap_scan,
    ):
        result = parser(text)
        if result:
            return result

    return None


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _normalize_target(target: str) -> str:
    return COMMON_DOMAINS.get(target.strip(".").lower(), target.strip())


def _valid_target(target: str) -> str | None:
    normalized = _normalize_target(target)
    is_valid, _, _ = validate_target(normalized)
    return normalized if is_valid else None


def _valid_network_target(target: str) -> str | None:
    normalized = _normalize_target(target)
    is_valid, _, _ = validate_network_target(normalized)
    return normalized if is_valid else None


def _parse_broad_request(text: str) -> dict | None:
    broad_scan = any(term in text for term in BROAD_NETWORK_TERMS)
    has_cidr = bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", text))

    if (
        broad_scan
        and not has_cidr
        and any(word in text for word in ("scan", "discover", "hosts", "ips"))
    ):
        return needs_clarification(
            "Which subnet or target should I use? For example: 192.168.1.0/24.",
            ["target_or_network"],
        )

    return None


def _parse_netstat(text: str) -> dict | None:
    if text in {"netstat", "run netstat"}:
        return command_call("run_netstat")
    if "listening ports" in text or "network connections" in text:
        return command_call("run_netstat")
    if "open locally" in text or "ports are open locally" in text:
        return command_call("run_netstat")
    return None


def _parse_ping(text: str) -> dict | None:
    patterns = (
        rf"^ping {TARGET_PATTERN}$",
        rf"^test connectivity to {TARGET_PATTERN}$",
        rf"^check if {TARGET_PATTERN} is reachable$",
    )
    target = _first_valid_target(text, patterns)
    if target:
        return command_call("ping", {"host": target})
    return None


def _parse_traceroute(text: str) -> dict | None:
    patterns = (
        rf"^traceroute (?:to )?{TARGET_PATTERN}$",
        rf"^trace route to {TARGET_PATTERN}$",
        rf"^show (?:me )?(?:the )?path to {TARGET_PATTERN}$",
    )
    target = _first_valid_target(text, patterns)
    if target:
        return command_call("traceroute", {"host": target})
    return None


def _parse_dns_lookup(text: str) -> dict | None:
    patterns = (
        rf"^dns lookup (?:for )?{TARGET_PATTERN}$",
        rf"^lookup dns (?:for )?{TARGET_PATTERN}$",
        rf"^reverse lookup {TARGET_PATTERN}$",
        rf"^what(?:'s| is) the ip (?:of|for) {TARGET_PATTERN}$",
    )
    target = _first_valid_target(text, patterns)
    if target:
        return command_call("dns_lookup", {"host": target})
    return None


def _parse_discovery(text: str) -> dict | None:
    if not any(
        phrase in text for phrase in ("discover", "hosts are up", "machines are up", "ips are")
    ):
        return None

    network = _extract_network(text)
    if not network:
        return None

    return command_call("discover_hosts", {"network": network})


def _parse_nmap_scan(text: str) -> dict | None:
    if not any(phrase in text for phrase in ("scan", "open ports", "nmap", "check ports")):
        return None

    target = _extract_scan_target(text)
    if not target:
        return None

    args: dict[str, int | str] = {"target": target}

    top_ports = re.search(r"\btop (\d{1,5}) ports?\b", text)
    if top_ports:
        args["top_ports"] = int(top_ports.group(1))

    specific_ports = re.search(r"\bports? ([0-9,\s]+)(?: on| for|$)", text)
    if specific_ports and "," in specific_ports.group(1):
        args["specific_ports"] = re.sub(r"\s+", "", specific_ports.group(1))

    port_range = re.search(r"\bport range (\d{1,5}-\d{1,5})\b", text)
    if port_range:
        args["port_range"] = port_range.group(1)

    return command_call("run_nmap_scan", args)


def _first_valid_target(text: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return _valid_target(match.group(1))
    return None


def _extract_network(text: str) -> str | None:
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b", text)
    if not match:
        return None
    target = match.group(1)
    is_valid, _, target_type = validate_network_target(target)
    return target if is_valid and target_type == "cidr" else None


def _extract_scan_target(text: str) -> str | None:
    patterns = (
        rf"\bon (?:network )?{TARGET_PATTERN}\b",
        rf"\bof (?:network )?{TARGET_PATTERN}\b",
        rf"\bfor (?:network )?{TARGET_PATTERN}\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return _valid_network_target(match.group(1))
    return None

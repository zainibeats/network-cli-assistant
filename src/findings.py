"""Markdown findings writer for runtime observations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .runtime_context import ensure_directory, get_runtime_context_dir, set_private_permissions

MAX_DETAIL_CHARS = 1600


def record_finding(
    command: dict[str, Any], result: dict[str, Any], context_dir: Path | None = None
) -> Path:
    """
    Append a compact command observation to today's findings file.

    Findings are observations only. They do not promote data into inventory.
    """
    root = context_dir or get_runtime_context_dir()
    findings_dir = ensure_directory(root / "findings")
    now = datetime.now(timezone.utc)
    findings_file = findings_dir / f"{now.date().isoformat()}.md"

    if not findings_file.exists():
        findings_file.write_text(f"# Findings {now.date().isoformat()}\n\n", encoding="utf-8")

    entry = format_finding_entry(command, result, now)
    with findings_file.open("a", encoding="utf-8") as handle:
        handle.write(entry)

    set_private_permissions(findings_file, 0o600)
    return findings_file


def format_finding_entry(
    command: dict[str, Any],
    result: dict[str, Any],
    timestamp: datetime | None = None,
) -> str:
    """Build one markdown finding entry."""
    timestamp = timestamp or datetime.now(timezone.utc)
    function_name = command.get("function", "unknown")
    args = command.get("args", {})
    status = "success" if result.get("success", True) else "failed"
    target = _target_from_command(command)
    summary = summarize_result(function_name, result)

    lines = [
        f"## {timestamp.isoformat(timespec='seconds')} - {function_name}",
        "",
        f"- Status: {status}",
        f"- Target: {target or 'n/a'}",
        f"- Args: `{_compact_json(args)}`",
        f"- Summary: {summary}",
    ]

    details = _details(result)
    if details:
        lines.extend(["", "```text", details, "```"])

    lines.append("")
    return "\n".join(lines)


def summarize_result(function_name: str, result: dict[str, Any]) -> str:
    """Return a compact human-readable observation summary."""
    if result.get("success") is False:
        return result.get("error", "Operation failed")

    if function_name == "dns_lookup":
        return _summarize_dns(result)
    if function_name in {"ping", "traceroute", "run_netstat"}:
        return _first_line(result.get("stdout") or result.get("output") or "Operation completed")
    if function_name == "discover_hosts":
        count = result.get("total_hosts_found", 0)
        network = result.get("network", "network")
        return f"Observed {count} active host{'s' if count != 1 else ''} on {network}"
    if function_name == "run_nmap_scan":
        open_ports = [p for p in result.get("ports_found", []) if p.get("state") == "open"]
        target = result.get("target", "target")
        return (
            f"Observed {len(open_ports)} open port{'s' if len(open_ports) != 1 else ''} on {target}"
        )

    return _first_line(str(result.get("output") or "Operation completed"))


def _summarize_dns(result: dict[str, Any]) -> str:
    forward = result.get("forward_lookup") or {}
    reverse = result.get("reverse_lookup") or {}
    parts = []
    if forward.get("success"):
        parts.append(f"{forward.get('hostname')} resolved to {forward.get('ip_address')}")
    if reverse.get("success"):
        parts.append(f"{reverse.get('ip_address')} reversed to {reverse.get('hostname')}")
    return "; ".join(parts) if parts else "DNS lookup completed"


def _target_from_command(command: dict[str, Any]) -> str | None:
    args = command.get("args", {})
    return args.get("host") or args.get("target") or args.get("network")


def _details(result: dict[str, Any]) -> str:
    text = result.get("stdout") or result.get("network_summary") or result.get("output")
    if not isinstance(text, str):
        return ""
    text = text.strip()
    if len(text) > MAX_DETAIL_CHARS:
        return text[:MAX_DETAIL_CHARS].rstrip() + "\n...[truncated]"
    return text


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _first_line(value: str) -> str:
    return value.strip().splitlines()[0] if value.strip() else "Operation completed"

"""File-backed runtime knowledgebase for network observations."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .findings import summarize_result
from .runtime_context import ensure_directory, get_runtime_context_dir, set_private_permissions

KB_DIRECTORIES = (
    "audit",
    "inventory/hosts",
    "inventory/networks",
    "findings",
    "incidents",
    "memory",
    "notes",
    "skills",
)
MAX_RECENT_OBSERVATIONS = 20


def ensure_knowledgebase(context_dir: Path | None = None) -> Path:
    """Create the editable knowledgebase directory structure."""
    root = ensure_directory(context_dir or get_runtime_context_dir())
    for relative_path in KB_DIRECTORIES:
        try:
            directory = ensure_directory(root / relative_path)
        except PermissionError:
            continue
        readme = directory / "README.md"
        try:
            if not readme.exists():
                readme.write_text(_readme_text(relative_path), encoding="utf-8")
                set_private_permissions(readme, 0o600)
        except PermissionError:
            continue
    return root


def update_inventory(
    command: dict[str, Any], result: dict[str, Any], context_dir: Path | None = None
) -> Path | None:
    """Update a bounded per-target inventory note from a command observation."""
    target = _target_from_command(command)
    if not target:
        return None

    root = ensure_knowledgebase(context_dir)
    target_kind = "networks" if "/" in target else "hosts"
    inventory_file = root / "inventory" / target_kind / f"{_slugify(target)}.md"

    admin_notes, recent_observations = _load_inventory_sections(inventory_file)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    recent_observations.insert(0, _format_observation(command, result, now))
    recent_observations = recent_observations[:MAX_RECENT_OBSERVATIONS]

    inventory_file.write_text(
        _render_inventory_document(target, now, admin_notes, recent_observations),
        encoding="utf-8",
    )
    set_private_permissions(inventory_file, 0o600)
    return inventory_file


def _load_inventory_sections(path: Path) -> tuple[str, list[str]]:
    if not path.exists():
        return "", []

    content = path.read_text(encoding="utf-8")
    return _extract_admin_notes(content), _extract_observations(content)


def _render_inventory_document(
    target: str, last_observed: str, admin_notes: str, observations: list[str]
) -> str:
    lines = [
        f"# {target}",
        "",
        f"- Last observed: {last_observed}",
        "- Type: network" if "/" in target else "- Type: host",
        "",
        "## Admin Notes",
        "",
        admin_notes or "_Add durable human-maintained knowledge here._",
        "",
        "## Recent Observations",
        "",
    ]

    if observations:
        lines.extend(observations)
    else:
        lines.append("- No observations yet.")

    lines.append("")
    return "\n".join(lines)


def _extract_admin_notes(content: str) -> str:
    match = re.search(r"## Admin Notes\n\n(.*?)(?:\n## |\n<!-- nca:metadata)", content, re.DOTALL)
    if not match:
        return ""
    notes = match.group(1).strip()
    if notes == "_Add durable human-maintained knowledge here._":
        return ""
    return notes


def _extract_observations(content: str) -> list[str]:
    match = re.search(r"## Recent Observations\n\n(.*)", content, re.DOTALL)
    if not match:
        return []
    return [
        line.strip()
        for line in match.group(1).splitlines()
        if line.startswith("- ") and line != "- No observations yet."
    ][:MAX_RECENT_OBSERVATIONS]


def _format_observation(command: dict[str, Any], result: dict[str, Any], timestamp: str) -> str:
    function_name = command.get("function", "unknown")
    args = json.dumps(command.get("args", {}), sort_keys=True, separators=(",", ":"))
    status = "success" if result.get("success", True) else "failed"
    summary = summarize_result(function_name, result)
    return f"- {timestamp} `{function_name}` {status}: {summary} Args: `{args}`"


def _target_from_command(command: dict[str, Any]) -> str | None:
    args = command.get("args", {})
    return args.get("host") or args.get("target") or args.get("network")


def _slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_") or "unknown"


def _readme_text(relative_path: str) -> str:
    descriptions = {
        "inventory/hosts": "One bounded Markdown profile per known host.",
        "inventory/networks": "One bounded Markdown profile per known subnet or CIDR.",
        "audit": "Append-only JSONL audit events for commands, approvals, and agent decisions.",
        "findings": "Daily command observations written automatically by the assistant.",
        "incidents": "Human-maintained incident notes and timelines.",
        "memory": "Bounded recent chat memory for conversational continuity.",
        "notes": "General human-maintained network notes.",
        "skills": "Reusable operator procedures and troubleshooting playbooks.",
    }
    return f"# {relative_path}\n\n{descriptions.get(relative_path, 'Knowledgebase files.')}\n"

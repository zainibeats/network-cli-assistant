"""Append-only Markdown/JSONL audit log for agent decisions and actions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .runtime_context import ensure_directory, get_runtime_context_dir, set_private_permissions


def record_audit_event(
    event_type: str,
    details: dict[str, Any],
    context_dir: Path | None = None,
) -> Path:
    """Append one structured audit event to today's JSONL log."""
    root = context_dir or get_runtime_context_dir()
    try:
        audit_dir = ensure_directory(root / "audit")
    except PermissionError:
        return root / "audit"
    now = datetime.now(timezone.utc)
    audit_file = audit_dir / f"{now.date().isoformat()}.jsonl"
    event = {
        "timestamp": now.isoformat(timespec="seconds"),
        "type": event_type,
        "details": _redact(details),
    }
    try:
        with audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    except PermissionError:
        return audit_file
    set_private_permissions(audit_file, 0o600)
    return audit_file


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_field(key, item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _redact_field(key: str, value: Any) -> Any:
    lowered = key.lower()
    if any(term in lowered for term in ("secret", "token", "password", "api_key", "apikey")):
        return "[redacted]"
    return _redact(value)

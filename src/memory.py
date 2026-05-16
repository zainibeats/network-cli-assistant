"""Small editable chat memory for the runtime assistant."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .runtime_context import ensure_directory, get_runtime_context_dir

MAX_TURNS = 12


def memory_dir(context_dir: Path | None = None) -> Path:
    """Return the chat memory directory."""
    return ensure_directory((context_dir or get_runtime_context_dir()) / "memory")


def load_chat_memory(context_dir: Path | None = None) -> str:
    """Load the bounded recent chat transcript."""
    path = memory_dir(context_dir) / "recent.md"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def append_chat_turn(
    user_input: str, assistant_output: str, context_dir: Path | None = None
) -> Path:
    """Append a chat turn and keep only the most recent bounded turns."""
    path = memory_dir(context_dir) / "recent.md"
    turns = _split_turns(path.read_text(encoding="utf-8") if path.exists() else "")
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    turns.append(
        "\n".join(
            [
                f"## {timestamp}",
                "",
                f"User: {user_input.strip()}",
                "",
                f"Assistant: {assistant_output.strip()}",
                "",
            ]
        )
    )
    path.write_text("\n".join(turns[-MAX_TURNS:]), encoding="utf-8")
    path.chmod(0o600)
    return path


def _split_turns(content: str) -> list[str]:
    return [f"## {turn.strip()}" for turn in content.split("## ") if turn.strip()]

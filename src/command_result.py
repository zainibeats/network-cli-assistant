"""Structured parser result helpers."""

from typing import Any


def command_call(
    function: str, args: dict[str, Any] | None = None, source: str = "deterministic"
) -> dict:
    """Build a structured command call result."""
    return {
        "status": "ready",
        "function": function,
        "args": args or {},
        "source": source,
    }


def needs_clarification(question: str, missing: list[str] | None = None) -> dict:
    """Build a structured clarification result."""
    return {
        "status": "needs_clarification",
        "question": question,
        "missing": missing or [],
    }


def parser_error(error: str, message: str) -> dict:
    """Build a structured parser error result."""
    return {
        "status": "error",
        "error": error,
        "message": message,
    }

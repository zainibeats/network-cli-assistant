"""Terminal input helpers for the interactive CLI."""

from __future__ import annotations

import sys

_PROMPT_SESSION = None


def discard_pending_input(stream=None) -> bool:
    """
    Drop unread terminal input so stale keystrokes cannot become a later command.

    Returns True when input was flushed. Non-interactive streams and platforms
    without POSIX terminal controls are left untouched.
    """
    stream = stream or sys.stdin
    try:
        if not stream.isatty():
            return False
        fd = stream.fileno()
    except (AttributeError, OSError):
        return False

    try:
        import termios
    except ImportError:
        return False

    try:
        termios.tcflush(fd, termios.TCIFLUSH)
    except (OSError, termios.error):
        return False

    return True


def read_prompt(prompt: str) -> str:
    """Read one terminal input line, using prompt_toolkit when available."""
    if not sys.stdin.isatty():
        return input(prompt)

    session = _get_prompt_session()
    if session is None:
        return input(prompt)

    return session.prompt(prompt)


def _get_prompt_session():
    global _PROMPT_SESSION
    if _PROMPT_SESSION is not None:
        return _PROMPT_SESSION

    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import InMemoryHistory
    except ImportError:
        return None

    _PROMPT_SESSION = PromptSession(history=InMemoryHistory())
    return _PROMPT_SESSION

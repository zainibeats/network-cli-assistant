"""Terminal input helpers for the interactive CLI."""

from __future__ import annotations

import sys

_PROMPT_SESSION = None
_ORIGINAL_TERMINAL_ATTRS = None


def save_terminal_state(stream=None) -> bool:
    """Capture the terminal attributes that should be restored after raw/no-echo modes."""
    global _ORIGINAL_TERMINAL_ATTRS
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
        _ORIGINAL_TERMINAL_ATTRS = termios.tcgetattr(fd)
    except (OSError, termios.error):
        return False
    return True


def restore_terminal_state(stream=None) -> bool:
    """Restore the saved terminal attributes after prompt or subprocess failures."""
    stream = stream or sys.stdin
    if _ORIGINAL_TERMINAL_ATTRS is None:
        return False

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
        termios.tcsetattr(fd, termios.TCSADRAIN, _ORIGINAL_TERMINAL_ATTRS)
    except (OSError, termios.error):
        return False
    return True


def ensure_terminal_ready(stream=None) -> bool:
    """
    Make the terminal suitable for line input.

    If a child process or prompt implementation leaves ECHO/ICANON disabled, typed
    input is still delivered to stdin but is not displayed. Restoring the saved
    startup state fixes that without discarding the session.
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
        current_attrs = termios.tcgetattr(fd)
    except (OSError, termios.error):
        return False

    if _ORIGINAL_TERMINAL_ATTRS is None:
        return save_terminal_state(stream)

    local_flags = current_attrs[3]
    if local_flags & termios.ECHO and local_flags & termios.ICANON:
        return True

    return restore_terminal_state(stream)


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

    ensure_terminal_ready()
    session = _get_prompt_session()
    if session is None:
        return input(prompt)

    save_terminal_state()
    try:
        return session.prompt(prompt)
    finally:
        restore_terminal_state()


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

import sys
from types import SimpleNamespace

from src import terminal_io
from src.terminal_io import discard_pending_input, ensure_terminal_ready, read_prompt, restore_terminal_state, save_terminal_state


class FakeStream:
    def __init__(self, *, tty=True, fd=7):
        self.tty = tty
        self.fd = fd

    def isatty(self):
        return self.tty

    def fileno(self):
        return self.fd


def test_discard_pending_input_flushes_tty(monkeypatch):
    calls = []
    fake_termios = SimpleNamespace(
        TCIFLUSH=0,
        error=OSError,
        tcflush=lambda fd, queue: calls.append((fd, queue)),
    )
    monkeypatch.setitem(sys.modules, "termios", fake_termios)

    assert discard_pending_input(FakeStream()) is True
    assert calls == [(7, 0)]


def test_discard_pending_input_ignores_non_tty(monkeypatch):
    fake_termios = SimpleNamespace(
        TCIFLUSH=0,
        error=OSError,
        tcflush=lambda _fd, _queue: (_ for _ in ()).throw(AssertionError("should not flush")),
    )
    monkeypatch.setitem(sys.modules, "termios", fake_termios)

    assert discard_pending_input(FakeStream(tty=False)) is False


def test_read_prompt_uses_builtin_input_for_non_tty(monkeypatch):
    monkeypatch.setattr(terminal_io.sys, "stdin", FakeStream(tty=False))
    monkeypatch.setattr("builtins.input", lambda prompt: f"read from {prompt}")

    assert read_prompt(">> ") == "read from >> "


def test_read_prompt_uses_prompt_session_for_tty(monkeypatch):
    class FakeSession:
        def prompt(self, prompt):
            return f"session read from {prompt}"

    monkeypatch.setattr(terminal_io.sys, "stdin", FakeStream(tty=True))
    monkeypatch.setattr(terminal_io, "_PROMPT_SESSION", FakeSession())

    assert read_prompt(">> ") == "session read from >> "


def test_terminal_state_restores_saved_attrs(monkeypatch):
    calls = []
    saved_attrs = [1, 2, 3, 0b10]
    fake_termios = SimpleNamespace(
        TCSADRAIN=1,
        ECHO=0b10,
        ICANON=0b100,
        error=OSError,
        tcgetattr=lambda fd: saved_attrs,
        tcsetattr=lambda fd, action, attrs: calls.append((fd, action, attrs)),
    )
    monkeypatch.setitem(sys.modules, "termios", fake_termios)
    monkeypatch.setattr(terminal_io, "_ORIGINAL_TERMINAL_ATTRS", None)

    assert save_terminal_state(FakeStream()) is True
    assert restore_terminal_state(FakeStream()) is True
    assert calls == [(7, 1, saved_attrs)]


def test_ensure_terminal_ready_restores_when_echo_is_disabled(monkeypatch):
    calls = []
    saved_attrs = [1, 2, 3, 0b110]
    current_attrs = [1, 2, 3, 0]
    fake_termios = SimpleNamespace(
        TCSADRAIN=1,
        ECHO=0b10,
        ICANON=0b100,
        error=OSError,
        tcgetattr=lambda fd: current_attrs,
        tcsetattr=lambda fd, action, attrs: calls.append((fd, action, attrs)),
    )
    monkeypatch.setitem(sys.modules, "termios", fake_termios)
    monkeypatch.setattr(terminal_io, "_ORIGINAL_TERMINAL_ATTRS", saved_attrs)

    assert ensure_terminal_ready(FakeStream()) is True
    assert calls == [(7, 1, saved_attrs)]

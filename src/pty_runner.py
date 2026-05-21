"""Small PTY runner for commands that need an interactive terminal."""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import time
from collections.abc import Sequence

from .terminal_io import restore_terminal_state, save_terminal_state

READ_SIZE = 4096
TERMINATE_GRACE_SECONDS = 0.5


def run_interactive_process(
    args: Sequence[str],
    *,
    timeout: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """
    Run a process behind a pseudo-terminal while forwarding local terminal I/O.

    The child process gets the PTY slave as its terminal, so terminal mutations
    from programs like sudo are scoped away from the parent terminal. The parent
    still temporarily switches stdin to raw mode for byte forwarding and restores
    it before returning.
    """
    pid, master_fd = os.forkpty()
    if pid == 0:
        try:
            os.execvpe(args[0], list(args), env or os.environ)
        except Exception:
            os._exit(127)

    output = bytearray()
    deadline = time.monotonic() + timeout
    timed_out = False
    stdin_fd = _fileno_if_tty(sys.stdin)
    stdout_fd = _fileno_if_available(sys.stdout)

    save_terminal_state()
    try:
        _set_raw_if_tty(stdin_fd)
        while True:
            status = _poll_child(pid)
            if status is not None:
                exit_code = _exit_code_from_status(status)
                _drain_master(master_fd, output, stdout_fd)
                return subprocess.CompletedProcess(
                    list(args),
                    exit_code,
                    stdout=output.decode(errors="replace"),
                    stderr="",
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_child(pid)
                _drain_master(master_fd, output, stdout_fd)
                raise subprocess.TimeoutExpired(
                    cmd=list(args),
                    timeout=timeout,
                    output=output.decode(errors="replace"),
                    stderr="",
                )

            read_fds = [master_fd]
            if stdin_fd is not None:
                read_fds.append(stdin_fd)
            readable, _, _ = select.select(read_fds, [], [], min(0.1, remaining))
            if master_fd in readable:
                _copy_from_master(master_fd, output, stdout_fd)
            if stdin_fd is not None and stdin_fd in readable:
                _copy_to_master(stdin_fd, master_fd)
    finally:
        restore_terminal_state()
        try:
            os.close(master_fd)
        except OSError:
            pass
        if timed_out:
            _reap_child(pid)


def _fileno_if_available(stream) -> int | None:
    try:
        return stream.fileno()
    except (AttributeError, OSError):
        return None


def _fileno_if_tty(stream) -> int | None:
    try:
        if not stream.isatty():
            return None
        return stream.fileno()
    except (AttributeError, OSError):
        return None


def _set_raw_if_tty(fd: int | None) -> None:
    if fd is None:
        return
    try:
        import tty

        tty.setraw(fd)
    except (ImportError, OSError):
        return


def _poll_child(pid: int) -> int | None:
    try:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return 0
    if waited_pid == 0:
        return None
    return status


def _exit_code_from_status(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return 1


def _copy_from_master(master_fd: int, output: bytearray, stdout_fd: int | None) -> None:
    try:
        data = os.read(master_fd, READ_SIZE)
    except OSError:
        return
    if not data:
        return
    output.extend(data)
    if stdout_fd is not None:
        try:
            os.write(stdout_fd, data)
            return
        except OSError:
            pass
    try:
        sys.stdout.write(data.decode(errors="replace"))
        sys.stdout.flush()
    except OSError:
        pass


def _copy_to_master(stdin_fd: int, master_fd: int) -> None:
    try:
        data = os.read(stdin_fd, READ_SIZE)
    except OSError:
        return
    if not data:
        return
    try:
        os.write(master_fd, data)
    except OSError:
        pass


def _drain_master(master_fd: int, output: bytearray, stdout_fd: int | None) -> None:
    while True:
        readable, _, _ = select.select([master_fd], [], [], 0)
        if not readable:
            return
        before = len(output)
        _copy_from_master(master_fd, output, stdout_fd)
        if len(output) == before:
            return


def _terminate_child(pid: int) -> None:
    _signal_child(pid, signal.SIGTERM)
    deadline = time.monotonic() + TERMINATE_GRACE_SECONDS
    while time.monotonic() < deadline:
        status = _poll_child(pid)
        if status is not None:
            return
        time.sleep(0.05)
    _signal_child(pid, signal.SIGKILL)


def _signal_child(pid: int, sig: signal.Signals) -> None:
    try:
        os.killpg(os.getpgid(pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, OSError):
            pass


def _reap_child(pid: int) -> None:
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass

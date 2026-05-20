"""
Safe subprocess boundary for approved network commands.

Network functions should call this module instead of subprocess directly so
execution policy and tests have one stable seam.
"""

import subprocess
from dataclasses import dataclass
from typing import Iterable, Sequence

from .process_runner import run_process

ALLOWED_EXECUTABLES = frozenset(
    {
        "ip",
        "netstat",
        "nmap",
        "ping",
        "traceroute",
    }
)


@dataclass(frozen=True)
class CommandResult:
    """Normalized command execution result."""

    args: Sequence[str]
    stdout: str
    stderr: str
    returncode: int


class CommandExecutionError(RuntimeError):
    """Raised when an approved command exits unsuccessfully."""

    def __init__(self, result: CommandResult):
        self.result = result
        super().__init__(result.stderr or f"Command failed: {result.args[0]}")


def run_command(
    args: Sequence[str],
    *,
    timeout: int,
    allowed_executables: Iterable[str] = ALLOWED_EXECUTABLES,
) -> CommandResult:
    """
    Run an approved command and return normalized output.

    Args:
        args: Command and arguments as separate list items.
        timeout: Maximum runtime in seconds.
        allowed_executables: Executable names allowed by this runner.

    Returns:
        CommandResult with stdout, stderr, and return code.

    Raises:
        ValueError: If command input is invalid or not allowed.
        subprocess.TimeoutExpired: If the command times out.
        FileNotFoundError: If the executable is missing.
        CommandExecutionError: If the command returns a non-zero exit code.
    """
    if not args:
        raise ValueError("Command cannot be empty")

    executable = args[0]
    if "/" in executable or executable not in set(allowed_executables):
        raise ValueError(f"Executable is not allowed: {executable}")

    completed = run_process(
        list(args),
        timeout=timeout,
    )
    result = CommandResult(
        args=tuple(args),
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )
    if completed.returncode != 0:
        raise CommandExecutionError(result)

    return result

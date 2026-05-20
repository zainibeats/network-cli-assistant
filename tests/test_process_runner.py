import subprocess
from types import SimpleNamespace

import pytest

from src import process_runner
from src.process_runner import run_process


class FakeProcess:
    pid = 123
    returncode = 0

    def __init__(self, *_args, **_kwargs):
        self.calls = 0
        self.killed = False

    def communicate(self, timeout=None):
        self.calls += 1
        if timeout is not None:
            raise subprocess.TimeoutExpired(cmd=["sleep", "10"], timeout=1)
        return "partial stdout", "partial stderr"

    def kill(self):
        self.killed = True


def test_run_process_raises_timeout_after_killing_process_group(monkeypatch):
    fake_process = FakeProcess()
    kill_calls = []

    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: fake_process)
    monkeypatch.setattr(process_runner.os, "killpg", lambda pid, sig: kill_calls.append((pid, sig)))

    with pytest.raises(subprocess.TimeoutExpired) as exc_info:
        run_process(["sleep", "10"], timeout=1)

    assert kill_calls == [(123, process_runner.signal.SIGKILL)]
    assert fake_process.calls == 2
    assert exc_info.value.output == "partial stdout"
    assert exc_info.value.stderr == "partial stderr"


def test_run_process_falls_back_to_kill_when_process_group_missing(monkeypatch):
    fake_process = FakeProcess()

    def raise_missing_group(_pid, _sig):
        raise ProcessLookupError

    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: fake_process)
    monkeypatch.setattr(process_runner.os, "killpg", raise_missing_group)

    with pytest.raises(subprocess.TimeoutExpired):
        run_process(["sleep", "10"], timeout=1)

    assert fake_process.killed is True


def test_run_process_returns_completed_process(monkeypatch):
    fake_process = SimpleNamespace(
        returncode=0,
        communicate=lambda timeout=None: ("stdout", "stderr"),
    )
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: fake_process)

    result = run_process(["echo", "ok"], timeout=1)

    assert result.args == ["echo", "ok"]
    assert result.stdout == "stdout"
    assert result.stderr == "stderr"
    assert result.returncode == 0

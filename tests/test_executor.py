"""Unit tests for the async command executor."""

from __future__ import annotations

import os

import pytest

from tools.executor import get_running_processes, kill_process, run_command_collect, run_interactive


pytestmark = pytest.mark.skipif(os.name == "nt", reason="executor is designed for Kali/Linux subprocess semantics")


@pytest.mark.asyncio
async def test_run_command_collect_success() -> None:
    result = await run_command_collect("printf 'hello\\nworld\\n'", timeout=5)
    assert result.exit_code == 0
    assert result.timed_out is False
    assert "hello" in result.output
    assert "world" in result.output


@pytest.mark.asyncio
async def test_run_command_collect_timeout() -> None:
    result = await run_command_collect("sleep 2", timeout=1)
    assert result.timed_out is True
    assert result.exit_code is not None


@pytest.mark.asyncio
async def test_run_interactive_feeds_inputs() -> None:
    output = await run_interactive("cat", ["alpha", "beta"])
    assert "alpha" in output
    assert "beta" in output


def test_get_running_processes_returns_list() -> None:
    assert isinstance(get_running_processes(), list)


@pytest.mark.asyncio
async def test_kill_unknown_process_returns_false() -> None:
    assert await kill_process(99999999) is False


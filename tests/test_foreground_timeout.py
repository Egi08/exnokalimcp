"""Foreground MCP timeout cap tests."""

from __future__ import annotations

import asyncio
import sys

from server import ExnoKaliMCPServices, load_config


def _test_config(tmp_path):
    config = load_config()
    config["server"]["auth"]["enabled"] = False
    config["paths"]["workspace_dir"] = str(tmp_path / "workspaces")
    config["paths"]["results_db"] = str(tmp_path / "results.db")
    config["paths"]["logs_dir"] = str(tmp_path / "logs")
    config["security"]["scope_file"] = str(tmp_path / "scope.txt")
    config["security"]["rate_limits"]["default_seconds"] = 0
    return config


def _python_command(code: str) -> str:
    return f'"{sys.executable}" -c "{code}"'


def test_run_command_tool_caps_foreground_timeout(tmp_path) -> None:
    config = _test_config(tmp_path)
    config["tools"]["foreground_timeout"] = 1
    services = ExnoKaliMCPServices(config)

    result = asyncio.run(
        services.run_command_tool(
            "test_sleep",
            _python_command("import time; time.sleep(3); print('done')"),
            {},
            timeout=30,
            check_binary=False,
        )
    )

    assert result["ok"] is False
    assert result["timed_out"] is True
    assert result["requested_timeout"] == 30
    assert result["effective_timeout"] == 1
    assert result["foreground_timeout_capped"] is True
    assert "start_background_process" in result["timeout_hint"]
    assert " -c " in result["background_example"]["arguments"]["command"]


def test_run_command_tool_does_not_cap_short_timeout(tmp_path) -> None:
    config = _test_config(tmp_path)
    config["tools"]["foreground_timeout"] = 30
    services = ExnoKaliMCPServices(config)

    result = asyncio.run(
        services.run_command_tool(
            "test_echo",
            _python_command("print('ok')"),
            {},
            timeout=5,
            check_binary=False,
        )
    )

    assert result["ok"] is True
    assert result["requested_timeout"] == 5
    assert result["effective_timeout"] == 5
    assert result["foreground_timeout_capped"] is False

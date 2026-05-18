"""MCP registration smoke tests."""

from __future__ import annotations

import asyncio

from server import create_server, load_config


def test_mcp_registers_terminal_file_and_doctor_tools(tmp_path) -> None:
    config = load_config()
    config["paths"]["workspace_dir"] = str(tmp_path / "workspaces")
    config["paths"]["results_db"] = str(tmp_path / "results.db")
    config["paths"]["logs_dir"] = str(tmp_path / "logs")
    config["security"]["scope_file"] = str(tmp_path / "scope.txt")

    async def _list_tool_names() -> set[str]:
        mcp = create_server(config)
        return {tool.name for tool in await mcp.list_tools()}

    names = asyncio.run(_list_tool_names())
    expected = {
        "terminal_start",
        "terminal_send",
        "terminal_read",
        "terminal_stop",
        "send_background_process_input",
        "file_download_chunk",
        "file_upload_chunk",
        "file_checksum",
        "file_diff",
        "file_backup",
        "file_patch",
        "file_restore",
        "workspace_tree",
        "workspace_file_read",
        "workspace_export_zip",
        "wsl_path_convert",
        "doctor_check",
        "doctor_fix",
        "command_history",
        "rerun_command",
        "save_command_as_script",
        "export_audit_log",
        "apt_update",
        "which_tool",
        "resolve_tool",
        "tool_inventory",
        "suggest_tool_for_task",
        "service_status",
        "network_interfaces",
        "open_port_listeners",
        "disk_usage",
        "process_list",
    }
    assert expected <= names

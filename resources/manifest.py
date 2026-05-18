"""Manifest and health MCP resources."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any


def register(mcp: Any, services: Any) -> None:
    """Register ExnoKaliMCP manifest resources."""

    @mcp.resource("exnokalimcp://manifest")
    async def get_manifest() -> dict[str, Any]:
        """Get registered tool and resource metadata."""

        tools = await mcp.list_tools()
        return {
            "server": services.config.get("server", {}),
            "tool_count": len(tools),
            "tools": [{"name": tool.name, "description": tool.description} for tool in tools],
            "resources": [
                "kali://wordlists",
                "kali://wordlists/{name}",
                "kali://tools/installed",
                "kali://targets/scope",
                "kali://workspaces/{name}/results",
                "kali://templates/nuclei",
                "kali://exploits/recent",
                "exnokalimcp://manifest",
                "exnokalimcp://health",
            ],
        }

    @mcp.resource("exnokalimcp://health")
    def get_health() -> dict[str, Any]:
        """Get lightweight server health details."""

        core_tools = ["nmap", "ffuf", "nuclei", "sqlmap", "subfinder", "httpx", "dnsx"]
        return {
            "server": services.config.get("server", {}),
            "workspace_dir": str(services.sessions.workspace_dir),
            "scope_file": str(services.sessions.scope_file),
            "results_db": str(services.store.db_path),
            "audit_log": str(Path(services.audit_file).expanduser()),
            "scope_rules": services.sessions.list_scope(),
            "core_tools": {tool: bool(shutil.which(tool)) for tool in core_tools},
        }


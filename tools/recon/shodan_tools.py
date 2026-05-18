"""Shodan MCP tools."""

from __future__ import annotations

import ipaddress
from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register Shodan tools."""

    @mcp.tool()
    async def shodan_query(
        query: str,
        api_key: str = "",
        options: str = "--fields ip_str,port,org,hostnames --limit 100",
        workspace: str = "default",
        timeout: int = 600,
    ) -> dict[str, Any]:
        """Search Shodan or fetch host data using the shodan CLI."""

        key = api_key or services.config.get("api_keys", {}).get("shodan", "")
        env = {"SHODAN_API_KEY": key} if key else None
        try:
            ipaddress.ip_address(query)
            command = join_flags(["shodan", "host", quote(query), option_string(options)])
            target = query
        except ValueError:
            command = join_flags(["shodan", "search", option_string(options), quote(query)])
            target = ""
        return await services.run_command_tool(
            "shodan_query",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            env=env,
        )


"""Nikto, WhatWeb, Wapiti, and Joomla scanner MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register web fingerprinting and vulnerability scanner tools."""

    @mcp.tool()
    async def nikto_scan(
        target: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run Nikto web server checks against an authorized target."""

        command = join_flags(["nikto", "-host", quote(target), option_string(options)])
        return await services.run_command_tool(
            "nikto_scan",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def whatweb(
        url: str,
        aggression: int = 1,
        workspace: str = "default",
        timeout: int = 900,
    ) -> dict[str, Any]:
        """Fingerprint web technology for an authorized URL using WhatWeb."""

        command = join_flags(["whatweb", "-a", quote(max(1, min(int(aggression), 4))), quote(url)])
        return await services.run_command_tool(
            "whatweb",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def wapiti_scan(
        url: str,
        options: str = "-f json -o -",
        workspace: str = "default",
        timeout: int = 7200,
    ) -> dict[str, Any]:
        """Run Wapiti web application vulnerability scanner against an authorized URL."""

        command = join_flags(["wapiti", "-u", quote(url), option_string(options)])
        return await services.run_command_tool(
            "wapiti_scan",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def joomscan(
        url: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run Joomla security checks against an authorized Joomla site."""

        command = join_flags(["joomscan", "-u", quote(url), option_string(options)])
        return await services.run_command_tool(
            "joomscan",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )


"""Hydra and Medusa MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register network authentication testing tools."""

    @mcp.tool()
    async def hydra_brute(
        target: str,
        service: str,
        username: str,
        wordlist: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Run Hydra password testing against an explicitly authorized service."""

        command = join_flags(
            ["hydra", "-l", quote(username), "-P", quote(wordlist), quote(target), quote(service), option_string(options)]
        )
        return await services.run_command_tool(
            "hydra_brute",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def medusa_brute(
        target: str,
        service: str,
        options: str,
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Run Medusa authentication testing against an explicitly authorized service."""

        command = join_flags(["medusa", "-h", quote(target), "-M", quote(service), option_string(options)])
        return await services.run_command_tool(
            "medusa_brute",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )


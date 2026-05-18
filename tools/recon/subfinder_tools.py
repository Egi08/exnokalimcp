"""Subfinder MCP tools."""

from __future__ import annotations

from typing import Any

from tools import csv, join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register subfinder tools."""

    @mcp.tool()
    async def subfinder(
        domain: str,
        sources: list[str] | None = None,
        recursive: bool = False,
        options: str = "",
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Enumerate subdomains for an authorized domain using subfinder."""

        source_arg = f"-sources {quote(csv(sources))}" if sources else ""
        recursive_arg = "-recursive" if recursive else ""
        command = join_flags(
            ["subfinder", "-silent", "-d", quote(domain), source_arg, recursive_arg, option_string(options)]
        )
        return await services.run_command_tool(
            "subfinder",
            command,
            locals(),
            target=domain,
            workspace=workspace,
            timeout=timeout,
            parser=lambda output: {"subdomains": sorted(set(line.strip() for line in output.splitlines() if line.strip()))},
        )


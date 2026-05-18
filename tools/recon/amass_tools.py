"""Amass MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register amass tools."""

    @mcp.tool()
    async def amass_enum(
        domain: str,
        mode: str = "passive",
        timeout: int = 3600,
        options: str = "",
        workspace: str = "default",
    ) -> dict[str, Any]:
        """Run OWASP Amass enumeration for an authorized domain."""

        mode_arg = "-passive" if mode.lower() == "passive" else "-active"
        command = join_flags(["amass", "enum", mode_arg, "-d", quote(domain), option_string(options)])
        return await services.run_command_tool(
            "amass_enum",
            command,
            locals(),
            target=domain,
            workspace=workspace,
            timeout=timeout,
            parser=lambda output: {"subdomains": sorted(set(line.strip() for line in output.splitlines() if line.strip()))},
        )


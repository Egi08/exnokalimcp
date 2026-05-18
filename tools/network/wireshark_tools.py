"""Wireshark/tshark MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, quote


def register(mcp: Any, services: Any) -> None:
    """Register Wireshark CLI tools."""

    @mcp.tool()
    async def tshark_capture(
        interface: str,
        duration: int = 30,
        display_filter: str = "",
        workspace: str = "default",
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Capture and summarize packets using tshark on a local interface."""

        filter_arg = f"-Y {quote(display_filter)}" if display_filter else ""
        command = join_flags(
            ["timeout", quote(max(1, int(duration))), "tshark", "-i", quote(interface), filter_arg]
        )
        return await services.run_command_tool(
            "tshark_capture",
            command,
            locals(),
            workspace=workspace,
            timeout=max(timeout, duration + 15),
        )

    @mcp.tool()
    async def tshark_interfaces() -> dict[str, Any]:
        """List packet capture interfaces visible to tshark."""

        return await services.run_command_tool(
            "tshark_interfaces",
            "tshark -D",
            locals(),
            workspace="default",
            timeout=30,
        )


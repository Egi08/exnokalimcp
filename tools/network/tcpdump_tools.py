"""tcpdump MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, quote


def register(mcp: Any, services: Any) -> None:
    """Register packet capture tools."""

    @mcp.tool()
    async def tcpdump_capture(
        interface: str,
        filter: str = "",
        duration: int = 60,
        output: str = "",
        workspace: str = "default",
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Capture packets on a local interface with tcpdump for authorized analysis."""

        pcap_path = output or str(services.sessions.output_path(workspace, "tcpdump_capture", ".pcap"))
        filter_arg = quote(filter) if filter else ""
        command = join_flags(
            [
                "timeout",
                quote(max(1, int(duration))),
                "tcpdump",
                "-i",
                quote(interface),
                "-w",
                quote(pcap_path),
                filter_arg,
            ]
        )
        result = await services.run_command_tool(
            "tcpdump_capture",
            command,
            locals(),
            workspace=workspace,
            timeout=max(timeout, duration + 15),
        )
        result["pcap_path"] = pcap_path
        return result


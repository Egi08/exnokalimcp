"""Aircrack-ng suite MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register wireless assessment tools."""

    @mcp.tool()
    async def airmon_start(
        interface: str,
        workspace: str = "default",
        timeout: int = 120,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Enable monitor mode on a local wireless interface for authorized testing."""

        command = join_flags(["airmon-ng", "start", quote(interface)])
        return await services.run_command_tool(
            "airmon_start",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def airodump_capture(
        interface: str,
        bssid: str = "",
        channel: str = "",
        output: str = "",
        duration: int = 120,
        workspace: str = "default",
        timeout: int = 300,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Capture WiFi packets with airodump-ng for authorized wireless testing."""

        prefix = output or str(services.sessions.output_path(workspace, "airodump_capture", "", folder="raw"))
        bssid_arg = f"--bssid {quote(bssid)}" if bssid else ""
        channel_arg = f"--channel {quote(channel)}" if channel else ""
        command = join_flags(
            [
                "timeout",
                quote(max(1, int(duration))),
                "airodump-ng",
                quote(interface),
                bssid_arg,
                channel_arg,
                "-w",
                quote(prefix),
                "--output-format",
                "pcap,csv",
            ]
        )
        result = await services.run_command_tool(
            "airodump_capture",
            command,
            locals(),
            workspace=workspace,
            timeout=max(timeout, duration + 30),
            confirm_authorized=confirm_authorized,
        )
        result["capture_prefix"] = prefix
        return result

    @mcp.tool()
    async def aireplay_deauth(
        interface: str,
        bssid: str,
        client: str = "",
        count: int = 5,
        workspace: str = "default",
        timeout: int = 120,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Run a bounded aireplay-ng deauthentication test with explicit authorization."""

        client_arg = f"-c {quote(client)}" if client else ""
        command = join_flags(
            ["aireplay-ng", "--deauth", quote(max(1, int(count))), "-a", quote(bssid), client_arg, quote(interface)]
        )
        return await services.run_command_tool(
            "aireplay_deauth",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def aircrack_crack(
        capture_file: str,
        wordlist: str,
        bssid: str = "",
        workspace: str = "default",
        timeout: int = 7200,
    ) -> dict[str, Any]:
        """Run aircrack-ng against a captured WPA/WEP handshake."""

        bssid_arg = f"-b {quote(bssid)}" if bssid else ""
        command = join_flags(["aircrack-ng", quote(capture_file), "-w", quote(wordlist), bssid_arg])
        return await services.run_command_tool(
            "aircrack_crack",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def wifite_auto(
        options: str = "",
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Run Wifite automation for an explicitly authorized wireless assessment."""

        command = join_flags(["wifite", option_string(options)])
        return await services.run_command_tool(
            "wifite_auto",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )


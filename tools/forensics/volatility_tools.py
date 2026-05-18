"""Forensics and binary analysis MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register forensics and analysis tools."""

    @mcp.tool()
    async def strings_analysis(
        file_path: str,
        options: str = "-a -n 6",
        workspace: str = "default",
        timeout: int = 600,
    ) -> dict[str, Any]:
        """Extract printable strings from a local file."""

        command = join_flags(["strings", option_string(options), quote(file_path)])
        return await services.run_command_tool(
            "strings_analysis",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def binwalk_analyze(
        file_path: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Analyze or extract firmware content with binwalk."""

        command = join_flags(["binwalk", option_string(options), quote(file_path)])
        return await services.run_command_tool(
            "binwalk_analyze",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def exiftool_analyze(
        file_path: str,
        options: str = "-json",
        workspace: str = "default",
        timeout: int = 600,
    ) -> dict[str, Any]:
        """Extract metadata from a local file using exiftool."""

        command = join_flags(["exiftool", option_string(options), quote(file_path)])
        return await services.run_command_tool(
            "exiftool_analyze",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def file_identify(
        file_path: str,
        workspace: str = "default",
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Identify a local file type."""

        command = f"file {quote(file_path)}"
        return await services.run_command_tool(
            "file_identify",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def hexdump_view(
        file_path: str,
        length: int = 512,
        offset: int = 0,
        workspace: str = "default",
        timeout: int = 120,
    ) -> dict[str, Any]:
        """View a bounded hex dump of a local file."""

        command = join_flags(["xxd", "-l", quote(max(1, int(length))), "-s", quote(max(0, int(offset))), quote(file_path)])
        return await services.run_command_tool(
            "hexdump_view",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def steghide_extract(
        file_path: str,
        passphrase: str = "",
        workspace: str = "default",
        timeout: int = 600,
    ) -> dict[str, Any]:
        """Extract hidden content from a steghide-supported file."""

        output = services.sessions.output_path(workspace, "steghide_extract", ".bin")
        pass_file = services.write_input_file(workspace, "steghide_passphrase", passphrase, ".secret")
        command = join_flags(
            ["steghide", "extract", "-sf", quote(file_path), "-xf", quote(output), "-p", f'"$(cat {quote(pass_file)})"', "-f"]
        )
        result = await services.run_command_tool(
            "steghide_extract",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )
        result["extracted_path"] = str(output)
        return result

    @mcp.tool()
    async def volatility_analyze(
        memory_dump: str,
        profile: str = "",
        plugin: str = "windows.info",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run Volatility memory forensics analysis."""

        if profile:
            command = join_flags(["volatility", "-f", quote(memory_dump), "--profile", quote(profile), quote(plugin)])
        else:
            command = join_flags(["volatility3", "-f", quote(memory_dump), quote(plugin)])
        return await services.run_command_tool(
            "volatility_analyze",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def foremost_recover(
        file_path: str,
        output_dir: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Recover carved files from raw data using foremost."""

        out = output_dir or str(services.sessions.output_path(workspace, "foremost_recover", "", folder="raw"))
        command = join_flags(["foremost", "-i", quote(file_path), "-o", quote(out)])
        result = await services.run_command_tool(
            "foremost_recover",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )
        result["recover_dir"] = out
        return result


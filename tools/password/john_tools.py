"""John the Ripper MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register John the Ripper tools."""

    @mcp.tool()
    async def john_crack(
        hash_file: str,
        wordlist: str = "",
        format: str = "",
        options: str = "",
        workspace: str = "default",
        timeout: int = 7200,
    ) -> dict[str, Any]:
        """Run John the Ripper against an authorized hash file."""

        wordlist_arg = f"--wordlist={quote(wordlist)}" if wordlist else ""
        format_arg = f"--format={quote(format)}" if format else ""
        command = join_flags(["john", wordlist_arg, format_arg, option_string(options), quote(hash_file)])
        return await services.run_command_tool(
            "john_crack",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )


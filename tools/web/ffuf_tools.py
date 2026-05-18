"""ffuf, feroxbuster, and dirsearch MCP tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import Context

from tools import join_flags, option_string, quote
from tools.parsers import parse_feroxbuster, parse_ffuf, parse_json


def register(mcp: Any, services: Any) -> None:
    """Register content discovery tools."""

    @mcp.tool()
    async def ffuf_fuzz(
        url: str,
        wordlist: str = "",
        filter_options: str = "",
        extensions: str = "",
        options: str = "-mc all",
        workspace: str = "default",
        timeout: int = 3600,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Run ffuf directory/file/content fuzzing against an authorized URL."""

        wordlist = wordlist or services.config.get("tools", {}).get("ffuf", {}).get(
            "default_wordlist", "/usr/share/wordlists/dirb/common.txt"
        )
        ext_arg = f"-e {quote(extensions)}" if extensions else ""
        command = join_flags(
            [
                "ffuf",
                "-u",
                quote(url),
                "-w",
                quote(wordlist),
                "-of",
                "json",
                ext_arg,
                option_string(filter_options),
                option_string(options),
            ]
        )
        return await services.run_command_tool(
            "ffuf_fuzz",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
            parser=parse_ffuf,
            ctx=ctx,
        )

    @mcp.tool()
    async def feroxbuster(
        url: str,
        wordlist: str = "",
        options: str = "--json",
        workspace: str = "default",
        timeout: int = 3600,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Run recursive web content discovery with feroxbuster."""

        wordlist = wordlist or services.config.get("tools", {}).get("ffuf", {}).get(
            "default_wordlist", "/usr/share/wordlists/dirb/common.txt"
        )
        command = join_flags(
            ["feroxbuster", "-u", quote(url), "-w", quote(wordlist), option_string(options)]
        )
        return await services.run_command_tool(
            "feroxbuster",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
            parser=parse_feroxbuster,
            ctx=ctx,
        )

    @mcp.tool()
    async def dirsearch(
        url: str,
        wordlist: str = "",
        extensions: str = "php,asp,aspx,jsp,html,js,txt",
        options: str = "--json-report=-",
        workspace: str = "default",
        timeout: int = 3600,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Run dirsearch path discovery against an authorized URL."""

        wordlist_arg = f"-w {quote(wordlist)}" if wordlist else ""
        ext_arg = f"-e {quote(extensions)}" if extensions else ""
        command = join_flags(
            ["dirsearch", "-u", quote(url), wordlist_arg, ext_arg, option_string(options)]
        )
        return await services.run_command_tool(
            "dirsearch",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
            parser=parse_json,
            ctx=ctx,
        )

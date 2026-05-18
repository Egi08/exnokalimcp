"""sqlmap, XSS scanner, and parameter discovery MCP tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import Context

from tools import join_flags, option_string, parse_headers, quote


def _header_args(headers: dict[str, str] | str | None) -> str:
    return " ".join(f"-H {quote(header)}" for header in parse_headers(headers))


def register(mcp: Any, services: Any) -> None:
    """Register SQL injection, XSS, and parameter discovery tools."""

    @mcp.tool()
    async def sqlmap_scan(
        url: str,
        options: str = "",
        data: str = "",
        cookies: str = "",
        headers: dict[str, str] | str | None = None,
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Run sqlmap testing against an authorized URL after explicit confirmation."""

        defaults = services.config.get("tools", {}).get("sqlmap", {})
        data_arg = f"--data {quote(data)}" if data else ""
        cookie_arg = f"--cookie {quote(cookies)}" if cookies else ""
        command = join_flags(
            [
                "sqlmap",
                "-u",
                quote(url),
                "--batch",
                f"--level={int(defaults.get('default_level', 3))}",
                f"--risk={int(defaults.get('default_risk', 2))}",
                data_arg,
                cookie_arg,
                _header_args(headers),
                option_string(options),
            ]
        )
        return await services.run_command_tool(
            "sqlmap_scan",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            ctx=ctx,
        )

    @mcp.tool()
    async def sqlmap_dump(
        url: str,
        db: str,
        table: str = "",
        options: str = "",
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Dump data with sqlmap for an explicitly authorized target and database."""

        table_arg = f"-T {quote(table)}" if table else ""
        command = join_flags(
            ["sqlmap", "-u", quote(url), "--batch", "-D", quote(db), table_arg, "--dump", option_string(options)]
        )
        return await services.run_command_tool(
            "sqlmap_dump",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            ctx=ctx,
        )

    @mcp.tool()
    async def xsstrike(
        url: str,
        data: str = "",
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run XSStrike XSS checks against an authorized URL."""

        data_arg = f"--data {quote(data)}" if data else ""
        command = join_flags(["xsstrike", "-u", quote(url), data_arg, option_string(options)])
        return await services.run_command_tool(
            "xsstrike",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def dalfox(
        url: str,
        options: str = "--silence",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run Dalfox XSS scanner and parameter analysis against an authorized URL."""

        command = join_flags(["dalfox", "url", quote(url), option_string(options)])
        return await services.run_command_tool(
            "dalfox",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def arjun(
        url: str,
        method: str = "GET",
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Discover HTTP parameters for an authorized URL using Arjun."""

        command = join_flags(["arjun", "-u", quote(url), "-m", quote(method.upper()), option_string(options)])
        return await services.run_command_tool(
            "arjun",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def paramspider(
        domain: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Mine parameters from web archives for an authorized domain using ParamSpider."""

        command = join_flags(["paramspider", "-d", quote(domain), option_string(options)])
        return await services.run_command_tool(
            "paramspider",
            command,
            locals(),
            target=domain,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def jwt_tool(
        token: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 900,
    ) -> dict[str, Any]:
        """Analyze a JWT locally using jwt_tool."""

        command = join_flags(["jwt_tool", quote(token), option_string(options)])
        return await services.run_command_tool(
            "jwt_tool",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

"""Miscellaneous web security MCP tools."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register specialized web security tools."""

    @mcp.tool()
    async def ssrfmap(
        url: str,
        data: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Run SSRFmap against an authorized request template."""

        parsed = urlparse(url)
        request = (
            f"POST {parsed.path or '/'} HTTP/1.1\n"
            f"Host: {parsed.netloc}\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            f"Content-Length: {len(data)}\n\n"
            f"{data}\n"
        )
        request_file = services.write_input_file(workspace, "ssrfmap_request", request, ".req")
        command = join_flags(["ssrfmap", "-r", quote(request_file), "-p", "url", option_string(options)])
        return await services.run_command_tool(
            "ssrfmap",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def corscanner(
        url: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Check CORS misconfiguration for an authorized URL."""

        command = join_flags(["corscanner", "-u", quote(url), option_string(options)])
        return await services.run_command_tool(
            "corscanner",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def testssl(
        host: str,
        options: str = "--fast",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run SSL/TLS checks against an authorized host using testssl.sh."""

        command = join_flags(["testssl.sh", option_string(options), quote(host)])
        return await services.run_command_tool(
            "testssl",
            command,
            locals(),
            target=host,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def wafw00f(
        url: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 900,
    ) -> dict[str, Any]:
        """Detect web application firewalls for an authorized URL."""

        command = join_flags(["wafw00f", quote(url), option_string(options)])
        return await services.run_command_tool(
            "wafw00f",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )


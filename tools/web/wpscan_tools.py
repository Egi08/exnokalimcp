"""WPScan MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register CMS scanner tools."""

    @mcp.tool()
    async def wpscan(
        url: str,
        options: str = "--format json",
        api_token: str = "",
        workspace: str = "default",
        timeout: int = 7200,
    ) -> dict[str, Any]:
        """Run WPScan against an authorized WordPress site."""

        token = api_token or services.config.get("api_keys", {}).get("wpscan", "")
        token_arg = f"--api-token {quote(token)}" if token else ""
        command = join_flags(["wpscan", "--url", quote(url), token_arg, option_string(options)])
        return await services.run_command_tool(
            "wpscan",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )


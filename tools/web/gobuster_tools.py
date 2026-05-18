"""Gobuster MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, quote


def register(mcp: Any, services: Any) -> None:
    """Register gobuster mode tools."""

    @mcp.tool()
    async def gobuster_dir(
        url: str,
        wordlist: str = "",
        extensions: str = "",
        threads: int = 50,
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run gobuster directory brute force against an authorized URL."""

        wordlist = wordlist or services.config.get("tools", {}).get("ffuf", {}).get(
            "default_wordlist", "/usr/share/wordlists/dirb/common.txt"
        )
        ext_arg = f"-x {quote(extensions)}" if extensions else ""
        command = join_flags(
            ["gobuster", "dir", "-u", quote(url), "-w", quote(wordlist), "-t", quote(threads), ext_arg]
        )
        return await services.run_command_tool(
            "gobuster_dir",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def gobuster_dns(
        domain: str,
        wordlist: str,
        threads: int = 50,
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run gobuster DNS subdomain discovery against an authorized domain."""

        command = join_flags(
            ["gobuster", "dns", "-d", quote(domain), "-w", quote(wordlist), "-t", quote(threads)]
        )
        return await services.run_command_tool(
            "gobuster_dns",
            command,
            locals(),
            target=domain,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def gobuster_vhost(
        url: str,
        wordlist: str,
        domain: str = "",
        threads: int = 50,
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run gobuster virtual host discovery against an authorized URL."""

        domain_arg = f"--append-domain --domain {quote(domain)}" if domain else ""
        command = join_flags(
            [
                "gobuster",
                "vhost",
                "-u",
                quote(url),
                "-w",
                quote(wordlist),
                "-t",
                quote(threads),
                domain_arg,
            ]
        )
        return await services.run_command_tool(
            "gobuster_vhost",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )


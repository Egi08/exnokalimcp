"""WHOIS, OSINT, archive URL, and recon-ng MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote


def register(mcp: Any, services: Any) -> None:
    """Register general reconnaissance tools."""

    @mcp.tool()
    async def whois_lookup(
        domain_or_ip: str,
        workspace: str = "default",
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Run a WHOIS lookup for an authorized domain or IP."""

        command = f"whois {quote(domain_or_ip)}"
        return await services.run_command_tool(
            "whois_lookup",
            command,
            locals(),
            target=domain_or_ip,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def theHarvester(
        domain: str,
        sources: str = "bing,duckduckgo,crtsh",
        limit: int = 500,
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Collect emails, subdomains, and IPs for an authorized domain."""

        command = join_flags(["theHarvester", "-d", quote(domain), "-b", quote(sources), "-l", quote(limit)])
        return await services.run_command_tool(
            "theHarvester",
            command,
            locals(),
            target=domain,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def recon_ng(
        workspace_name: str,
        modules: list[str],
        target: str,
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Run a recon-ng workspace workflow against an authorized target."""

        script_lines = [
            f"workspaces create {workspace_name}",
            f"db insert domains {target}",
        ]
        for module in modules:
            script_lines.extend([f"modules load {module}", f"options set SOURCE {target}", "run", "back"])
        script_file = services.write_input_file(workspace_name, "recon_ng_script", "\n".join(script_lines) + "\n", ".rc")
        command = join_flags(["recon-ng", "-w", quote(workspace_name), "-r", quote(script_file)])
        return await services.run_command_tool(
            "recon_ng",
            command,
            locals(),
            target=target,
            workspace=workspace_name,
            timeout=timeout,
        )

    @mcp.tool()
    async def osint_username(
        username: str,
        platforms: list[str] | None = None,
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Search for a username across OSINT platforms using sherlock."""

        site_args = " ".join(f"--site {quote(site)}" for site in (platforms or []))
        command = join_flags(["sherlock", quote(username), site_args, "--print-found"])
        return await services.run_command_tool(
            "osint_username",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def google_dork(
        dork_query: str,
        target: str,
        workspace: str = "default",
    ) -> dict[str, Any]:
        """
        Build safe Google/Bing dork URLs for manual authorized review.

        This tool does not scrape search engines; it stores reproducible search
        URLs so the operator can review results within provider terms.
        """

        from urllib.parse import quote_plus

        services.ensure_allowed("google_dork", locals(), target=target)
        query = f"site:{target} {dork_query}".strip()
        urls = {
            "google": f"https://www.google.com/search?q={quote_plus(query)}",
            "bing": f"https://www.bing.com/search?q={quote_plus(query)}",
        }
        output_path = services.sessions.output_path(workspace, "google_dork", ".json")
        output_path.write_text(__import__("json").dumps(urls, indent=2), encoding="utf-8")
        result_id = services.store.add_result(
            workspace,
            "google_dork",
            target,
            "manual-search-url-generation",
            0,
            str(output_path),
            {"query": query, "urls": urls},
            {"params": locals()},
        )
        return {"ok": True, "result_id": result_id, "query": query, "urls": urls}

    @mcp.tool()
    async def waybackurls(
        domain: str,
        workspace: str = "default",
        timeout: int = 1200,
    ) -> dict[str, Any]:
        """Fetch archived URLs for an authorized domain using waybackurls."""

        command = f"waybackurls {quote(domain)}"
        return await services.run_command_tool(
            "waybackurls",
            command,
            locals(),
            target=domain,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def gau(
        domain: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 1200,
    ) -> dict[str, Any]:
        """Get archived URLs from multiple sources for an authorized domain using gau."""

        command = join_flags(["gau", option_string(options), quote(domain)])
        return await services.run_command_tool(
            "gau",
            command,
            locals(),
            target=domain,
            workspace=workspace,
            timeout=timeout,
        )


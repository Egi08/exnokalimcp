"""DNS and HTTP probing MCP tools."""

from __future__ import annotations

from typing import Any

from tools import join_flags, option_string, quote
from tools.parsers import parse_dnsx, parse_httpx


def register(mcp: Any, services: Any) -> None:
    """Register DNS and HTTP probe tools."""

    @mcp.tool()
    async def dnsx(
        domains_list: list[str],
        record_types: list[str] | None = None,
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Resolve and enumerate DNS records for authorized domains using dnsx."""

        services.ensure_targets_allowed("dnsx", locals(), domains_list)
        record_types = record_types or ["a", "aaaa", "cname", "mx", "ns", "txt"]
        flags = []
        for record in record_types:
            clean = record.lower().strip()
            if clean in {"a", "aaaa", "cname", "mx", "ns", "txt", "soa", "ptr"}:
                flags.append(f"-{clean}")
        input_file = services.write_input_file(workspace, "dnsx_domains", "\n".join(domains_list) + "\n")
        target = domains_list[0] if domains_list else ""
        command = join_flags(["dnsx", "-silent", "-json", "-l", quote(input_file), " ".join(flags)])
        return await services.run_command_tool(
            "dnsx",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            parser=parse_dnsx,
        )

    @mcp.tool()
    async def httpx_probe(
        hosts_list: list[str],
        options: str = "-status-code -title -tech-detect -follow-redirects",
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Probe authorized hosts with httpx for HTTP metadata and technology detection."""

        services.ensure_targets_allowed("httpx_probe", locals(), hosts_list)
        input_file = services.write_input_file(workspace, "httpx_hosts", "\n".join(hosts_list) + "\n")
        target = hosts_list[0] if hosts_list else ""
        command = join_flags(["httpx", "-silent", "-json", "-l", quote(input_file), option_string(options)])
        return await services.run_command_tool(
            "httpx_probe",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            parser=parse_httpx,
        )

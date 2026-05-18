"""Nmap and masscan MCP tools."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context

from tools import csv, join_flags, option_string, quote


def _parse_nmap_xml(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {"hosts": [], "summary": "no XML output found"}
    root = ET.parse(path).getroot()
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addresses = [addr.attrib for addr in host.findall("address")]
        hostnames = [
            name.attrib.get("name", "")
            for name in host.findall("./hostnames/hostname")
            if name.attrib.get("name")
        ]
        ports: list[dict[str, Any]] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            scripts = [
                {"id": script.attrib.get("id"), "output": script.attrib.get("output", "")}
                for script in port.findall("script")
            ]
            ports.append(
                {
                    "protocol": port.attrib.get("protocol"),
                    "port": int(port.attrib.get("portid", "0")),
                    "state": state.attrib.get("state") if state is not None else "",
                    "service": service.attrib if service is not None else {},
                    "scripts": scripts,
                }
            )
        hosts.append({"addresses": addresses, "hostnames": hostnames, "ports": ports})
    return {
        "hosts": hosts,
        "host_count": len(hosts),
        "open_ports": sum(1 for host in hosts for port in host["ports"] if port["state"] == "open"),
    }


def register(mcp: Any, services: Any) -> None:
    """Register nmap-related MCP tools."""

    @mcp.tool()
    async def nmap_scan(
        target: str,
        ports: str = "",
        scan_type: str = "default",
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """
        Run an authorized nmap scan and return parsed XML plus a saved raw result.

        scan_type may be default, stealth, tcp, udp, ping, aggressive, or vuln.
        """

        xml_path = services.sessions.output_path(workspace, "nmap_scan", ".xml")
        scan_map = {
            "default": services.config.get("tools", {}).get("nmap", {}).get("default_args", "-sV -sC"),
            "stealth": "-sS -sV",
            "tcp": "-sT -sV",
            "udp": "-sU -sV",
            "ping": "-sn",
            "aggressive": "-A",
            "vuln": "-sV --script vuln",
        }
        scan_args = scan_map.get(scan_type, scan_map["default"])
        port_args = f"-p {quote(ports)}" if ports else ""
        command = join_flags(
            [
                "nmap",
                scan_args,
                port_args,
                option_string(options),
                "-oX",
                quote(xml_path),
                quote(target),
            ]
        )
        return await services.run_command_tool(
            "nmap_scan",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            parser=lambda _: _parse_nmap_xml(xml_path),
            ctx=ctx,
        )

    @mcp.tool()
    async def nmap_vuln_scan(
        target: str,
        ports: str = "",
        workspace: str = "default",
        timeout: int = 7200,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Run nmap service/version detection with the vuln NSE script category."""

        xml_path = services.sessions.output_path(workspace, "nmap_vuln_scan", ".xml")
        port_args = f"-p {quote(ports)}" if ports else ""
        command = join_flags(["nmap", "-sV", "--script", "vuln", port_args, "-oX", quote(xml_path), quote(target)])
        return await services.run_command_tool(
            "nmap_vuln_scan",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            parser=lambda _: _parse_nmap_xml(xml_path),
            ctx=ctx,
        )

    @mcp.tool()
    async def masscan(
        target_range: str,
        ports: str,
        rate: int = 1000,
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Run masscan for fast authorized port discovery."""

        command = join_flags(
            [
                "masscan",
                quote(target_range),
                f"-p{quote(ports)}",
                "--rate",
                quote(max(1, int(rate))),
                option_string(options),
            ]
        )
        return await services.run_command_tool(
            "masscan",
            command,
            locals(),
            target=target_range,
            workspace=workspace,
            timeout=timeout,
            ctx=ctx,
        )

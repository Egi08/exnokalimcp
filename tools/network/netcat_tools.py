"""Network utility MCP tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools import join_flags, option_string, parse_headers, quote


def _headers(headers: dict[str, str] | str | None) -> str:
    return " ".join(f"-H {quote(header)}" for header in parse_headers(headers))


def register(mcp: Any, services: Any) -> None:
    """Register network utility tools."""

    @mcp.tool()
    async def netdiscover(
        range: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 900,
    ) -> dict[str, Any]:
        """Run netdiscover for authorized local network host discovery."""

        command = join_flags(["netdiscover", "-r", quote(range), option_string(options)])
        return await services.run_command_tool(
            "netdiscover",
            command,
            locals(),
            target=range,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def arp_scan(
        range: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 900,
    ) -> dict[str, Any]:
        """Run arp-scan for authorized local network host discovery."""

        command = join_flags(["arp-scan", quote(range), option_string(options)])
        return await services.run_command_tool(
            "arp_scan",
            command,
            locals(),
            target=range,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def netcat_connect(
        host: str,
        port: int,
        data: str = "",
        workspace: str = "default",
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Open a netcat client connection to an authorized host and port."""

        if data:
            input_file = services.write_input_file(workspace, "netcat_connect", data, ".txt")
            command = join_flags(["nc", "-nv", quote(host), quote(port), "<", quote(input_file)])
        else:
            command = join_flags(["nc", "-nvz", quote(host), quote(port)])
        return await services.run_command_tool(
            "netcat_connect",
            command,
            locals(),
            target=host,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def netcat_listen(
        port: int,
        timeout: int = 300,
        workspace: str = "default",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Start a temporary netcat listener for an explicitly authorized engagement."""

        command = join_flags(["timeout", quote(timeout), "nc", "-nvlp", quote(port)])
        return await services.run_command_tool(
            "netcat_listen",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout + 10,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def socat_relay(
        options: str,
        workspace: str = "default",
        timeout: int = 3600,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Run a socat tunnel or relay for an explicitly authorized engagement."""

        command = join_flags(["socat", option_string(options)])
        return await services.run_command_tool(
            "socat_relay",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def ssh_connect(
        host: str,
        user: str,
        key_or_pass: str = "",
        command_to_run: str = "id",
        options: str = "",
        workspace: str = "default",
        timeout: int = 900,
    ) -> dict[str, Any]:
        """Run a command over SSH to an authorized host using a key or SSHPASS."""

        key_path = Path(key_or_pass).expanduser() if key_or_pass else None
        env = None
        if key_path and key_path.exists():
            auth_arg = f"-i {quote(key_path)}"
        elif key_or_pass:
            auth_arg = ""
            env = {"SSHPASS": key_or_pass}
            command_prefix = "sshpass -e ssh"
            command = join_flags(
                [
                    command_prefix,
                    option_string(options),
                    auth_arg,
                    f"{quote(user)}@{quote(host)}",
                    quote(command_to_run),
                ]
            )
            return await services.run_command_tool(
                "ssh_connect",
                command,
                locals(),
                target=host,
                workspace=workspace,
                timeout=timeout,
                env=env,
            )
        else:
            auth_arg = ""
        command = join_flags(
            ["ssh", option_string(options), auth_arg, f"{quote(user)}@{quote(host)}", quote(command_to_run)]
        )
        return await services.run_command_tool(
            "ssh_connect",
            command,
            locals(),
            target=host,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def proxychains_run(
        command: str,
        proxy_list: list[str],
        workspace: str = "default",
        timeout: int = 3600,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Run a command through a temporary proxychains configuration."""

        config = "strict_chain\nproxy_dns\n[ProxyList]\n" + "\n".join(proxy_list) + "\n"
        config_file = services.write_input_file(workspace, "proxychains", config, ".conf")
        wrapped = join_flags(["proxychains4", "-f", quote(config_file), command])
        return await services.run_command_tool(
            "proxychains_run",
            wrapped,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def curl_request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | str | None = None,
        data: str = "",
        options: str = "-i -sS",
        workspace: str = "default",
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Send an HTTP request to an authorized URL using curl."""

        data_arg = f"--data-raw {quote(data)}" if data else ""
        command = join_flags(
            ["curl", "-X", quote(method.upper()), _headers(headers), data_arg, option_string(options), quote(url)]
        )
        return await services.run_command_tool(
            "curl_request",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def wget_download(
        url: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 1800,
    ) -> dict[str, Any]:
        """Download a file from an authorized URL into the workspace."""

        output_dir = services.sessions.workspace_path(workspace) / "raw"
        command = join_flags(["wget", "-P", quote(output_dir), option_string(options), quote(url)])
        return await services.run_command_tool(
            "wget_download",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def packet_crafter(
        options: dict[str, Any],
        workspace: str = "default",
        timeout: int = 300,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Craft and optionally send a simple TCP/UDP/ICMP packet with Scapy."""

        dst = str(options.get("dst", ""))
        script = f"""
from scapy.all import IP, TCP, UDP, ICMP, Raw, send
opts = {json.dumps(options)}
proto = str(opts.get('protocol', 'tcp')).lower()
packet = IP(dst=opts['dst'])
if proto == 'udp':
    packet = packet / UDP(dport=int(opts.get('dport', 53)), sport=int(opts.get('sport', 44444)))
elif proto == 'icmp':
    packet = packet / ICMP()
else:
    packet = packet / TCP(dport=int(opts.get('dport', 80)), sport=int(opts.get('sport', 44444)), flags=str(opts.get('flags', 'S')))
payload = str(opts.get('payload', ''))
if payload:
    packet = packet / Raw(load=payload.encode())
print(packet.summary())
if bool(opts.get('send', False)):
    send(packet, count=int(opts.get('count', 1)), verbose=False)
    print('sent')
"""
        script_file = services.write_input_file(workspace, "packet_crafter", script, ".py")
        return await services.run_command_tool(
            "packet_crafter",
            f"python3 {quote(script_file)}",
            locals(),
            target=dst,
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
        )

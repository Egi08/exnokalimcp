#!/usr/bin/env python3
"""Kali Linux MCP server for authorized WSL penetration testing workflows."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import re
import shutil
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml
from mcp.server.fastmcp import Context, FastMCP

from tools import DISCLAIMER, command_preview, quote
from tools.executor import configure_executor, run_command_collect, start_background_command
from tools.result_store import ResultStore
from tools.session_manager import SessionManager


TOOL_MODULES = [
    "tools.recon.nmap_tools",
    "tools.recon.whois_tools",
    "tools.recon.dns_tools",
    "tools.recon.subfinder_tools",
    "tools.recon.amass_tools",
    "tools.recon.shodan_tools",
    "tools.web.ffuf_tools",
    "tools.web.gobuster_tools",
    "tools.web.nikto_tools",
    "tools.web.sqlmap_tools",
    "tools.web.wpscan_tools",
    "tools.web.nuclei_tools",
    "tools.web.burp_tools",
    "tools.exploit.metasploit_tools",
    "tools.exploit.searchsploit_tools",
    "tools.exploit.msfvenom_tools",
    "tools.network.wireshark_tools",
    "tools.network.netcat_tools",
    "tools.network.tcpdump_tools",
    "tools.password.hashcat_tools",
    "tools.password.john_tools",
    "tools.password.hydra_tools",
    "tools.wireless.aircrack_tools",
    "tools.forensics.volatility_tools",
    "tools.shell.terminal_tools",
]

RESOURCE_MODULES = [
    "resources.wordlists",
    "resources.targets",
    "resources.reports",
    "resources.manifest",
]


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load YAML configuration with environment override support."""

    default_path = Path(__file__).with_name("config.yaml")
    env_path = os.environ.get("EXNOKALIMCP_CONFIG") or os.environ.get("KALI_MCP_CONFIG")
    config_path = Path(path or env_path or default_path).expanduser()
    defaults = yaml.safe_load(default_path.read_text(encoding="utf-8"))
    if config_path.exists() and config_path != default_path:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        config = _deep_merge(defaults, loaded)
    else:
        config = defaults
    return config


class ExnoKaliMCPServices:
    """Shared services exposed to all MCP tool modules."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        configure_executor(config)
        self.sessions = SessionManager(config)
        db_path = config.get("paths", {}).get("results_db", "~/.exnokalimcp/results.db")
        self.store = ResultStore(db_path)
        logs_dir = Path(config.get("paths", {}).get("logs_dir", "~/.exnokalimcp/logs")).expanduser()
        logs_dir.mkdir(parents=True, exist_ok=True)
        self.audit_file = logs_dir / "audit.log"
        self._last_call: dict[tuple[str, str], float] = {}

    def authorize(self) -> None:
        """Enforce simple API-key authorization for stdio and local SSE use."""

        auth = self.config.get("server", {}).get("auth", {})
        if not auth.get("enabled", True):
            return
        configured = {str(key) for key in auth.get("api_keys", []) if str(key)}
        supplied = os.environ.get("EXNOKALIMCP_AUTH_KEY") or os.environ.get("KALI_MCP_AUTH_KEY", "")
        if configured and supplied not in configured:
            raise PermissionError(
                "EXNOKALIMCP_AUTH_KEY is missing or invalid. Set it to an api_keys entry in config.yaml."
            )

    def ensure_allowed(
        self,
        tool: str,
        params: dict[str, Any],
        target: str | None = None,
        confirm_authorized: bool = False,
    ) -> None:
        """Run authorization, confirmation, scope, and rate-limit checks."""

        self.authorize()
        required = set(self.config.get("security", {}).get("require_confirmation", []))
        if tool in required and not confirm_authorized:
            raise PermissionError(
                f"{tool} requires confirm_authorized=True and written authorization for the target."
            )
        if self.permission_mode == "read_only" and self._is_write_or_exec_tool(tool):
            raise PermissionError(f"{tool} is blocked because security.permission_mode is read_only")
        if target:
            match = self.sessions.check_scope(target)
            if not match.allowed:
                raise PermissionError(f"Scope check failed for {target}: {match.reason}")
        self._rate_limit(tool, target or "local")
        self.audit_log(tool, params, status="allowed")

    @property
    def permission_mode(self) -> str:
        """Return the configured local-control permission mode."""

        mode = str(self.config.get("security", {}).get("permission_mode", "full_control")).lower()
        return mode if mode in {"read_only", "workspace_only", "pentest_safe", "full_control"} else "full_control"

    def ensure_command_policy(self, tool: str, command: str, confirm_authorized: bool = False) -> None:
        """Require explicit confirmation for commands matching dangerous patterns."""

        for pattern in self.config.get("security", {}).get("dangerous_command_patterns", []):
            if re.search(str(pattern), command, flags=re.IGNORECASE) and not confirm_authorized:
                raise PermissionError(
                    f"{tool} command matches dangerous pattern {pattern!r}; confirm_authorized=True is required."
                )
        if self.permission_mode == "read_only":
            raise PermissionError(f"{tool} is blocked because security.permission_mode is read_only")

    def ensure_path_policy(self, tool: str, path: str | Path, write: bool = False) -> None:
        """Enforce filesystem permission modes and protected write paths."""

        resolved = Path(path).expanduser().resolve()
        security = self.config.get("security", {})
        if write and self.permission_mode == "read_only":
            raise PermissionError(f"{tool} cannot write because security.permission_mode is read_only")
        if write and self.permission_mode == "workspace_only":
            workspace_root = self.sessions.workspace_dir.resolve()
            if resolved != workspace_root and workspace_root not in resolved.parents:
                raise PermissionError(f"{tool} can only write under {workspace_root} in workspace_only mode")
        if write and self.permission_mode == "pentest_safe":
            for item in security.get("protected_paths", []):
                protected = Path(str(item)).expanduser().resolve()
                if resolved == protected or protected in resolved.parents:
                    raise PermissionError(f"{tool} refuses to write protected path: {resolved}")

    def _is_write_or_exec_tool(self, tool: str) -> bool:
        prefixes = (
            "shell_",
            "terminal_",
            "start_background",
            "send_background",
            "stop_background",
            "file_write",
            "file_upload",
            "file_mkdir",
            "file_copy",
            "file_move",
            "file_delete",
            "file_replace",
            "file_chmod",
            "file_backup",
            "file_patch",
            "file_restore",
            "workspace_export",
            "doctor_fix",
            "install_tool",
            "update_tools",
            "apt_update",
            "rerun_command",
            "save_command",
        )
        return any(tool.startswith(prefix) for prefix in prefixes)

    def ensure_targets_allowed(self, tool: str, params: dict[str, Any], targets: list[str]) -> None:
        """Verify that every target in a list is in scope."""

        self.authorize()
        result = self.sessions.check_targets([target for target in targets if target])
        if not result["allowed"]:
            blocked = ", ".join(item["target"] for item in result["blocked"][:10])
            raise PermissionError(f"Scope check failed for {tool}; blocked targets: {blocked}")
        self.audit_log(tool, params, status="allowed")

    def audit_log(
        self,
        tool: str,
        params: dict[str, Any],
        user: str = "local",
        status: str = "called",
        message: str = "",
    ) -> None:
        """Write immutable JSONL audit records for every operation."""

        sanitized = self._sanitize_params(params)
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "user": user,
            "status": status,
            "params": sanitized,
            "message": message,
        }
        with self.audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        self.store.add_tool_call(tool, sanitized, user, status, message)

    async def run_command_tool(
        self,
        tool: str,
        command: str,
        params: dict[str, Any],
        target: str | None = None,
        workspace: str = "default",
        timeout: int | None = None,
        confirm_authorized: bool = False,
        parser: Callable[[str], dict[str, Any] | list[Any]] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        check_binary: bool = True,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Check policy, run a command, persist output, and return JSON."""

        started = time.monotonic()
        timeout = timeout or int(self.config.get("tools", {}).get("default_timeout", 3600))
        self.ensure_allowed(tool, params, target=target, confirm_authorized=confirm_authorized)
        self.ensure_command_policy(tool, command, confirm_authorized=confirm_authorized)
        missing = self._missing_tool(command) if check_binary else None
        if missing:
            result = {
                "ok": False,
                "status": "missing_tool",
                "tool": tool,
                "missing": missing,
                "install_hint": f"Run install_tool(tool_name='{missing}', method='apt') or install.sh.",
                "disclaimer": DISCLAIMER,
            }
            self.audit_log(tool, params, status="missing_tool", message=missing)
            return result

        output_path = self.sessions.output_path(workspace, tool)
        self.audit_log(tool, params, status="started", message=command_preview(command))
        line_count = 0

        async def _progress(line: str) -> None:
            nonlocal line_count
            line_count += 1
            if ctx is None:
                return
            if line_count == 1 or line_count % 25 == 0:
                await ctx.report_progress(float(line_count), None, f"{tool}: {line_count} output lines")
            if line_count <= 10 or line_count % 50 == 0:
                await ctx.info(f"{tool}: {line[:500]}")

        try:
            command_result = await run_command_collect(
                command,
                timeout=timeout,
                cwd=cwd,
                env=env,
                on_line=_progress if ctx is not None else None,
            )
        except Exception as exc:
            self.audit_log(tool, params, status="error", message=str(exc))
            raise

        output_path.write_text(command_result.output, encoding="utf-8", errors="replace")
        parsed: dict[str, Any] | list[Any] = {}
        parse_error = ""
        if parser:
            try:
                parsed = parser(command_result.output)
            except Exception as exc:
                parse_error = str(exc)

        max_chars = int(self.config.get("security", {}).get("max_output_chars", 20000))
        summary = {
            "parsed": parsed,
            "parse_error": parse_error,
            "line_count": len(command_result.output.splitlines()),
            "duration_seconds": command_result.duration_seconds,
            "timed_out": command_result.timed_out,
        }
        result_id = self.store.add_result(
            workspace=workspace,
            tool=tool,
            target=target,
            command=command,
            exit_code=command_result.exit_code,
            output_path=str(output_path),
            summary=summary,
            metadata={"params": self._sanitize_params(params)},
        )
        self.audit_log(
            tool,
            params,
            status="completed",
            message=f"result_id={result_id} exit_code={command_result.exit_code}",
        )
        return {
            "ok": command_result.exit_code == 0 and not command_result.timed_out,
            "tool": tool,
            "result_id": result_id,
            "workspace": workspace,
            "target": target,
            "command": command,
            "exit_code": command_result.exit_code,
            "timed_out": command_result.timed_out,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output_path": str(output_path),
            "output_preview": command_result.output[:max_chars],
            "summary": summary,
            "disclaimer": DISCLAIMER,
        }

    async def start_background_tool(
        self,
        tool: str,
        command: str,
        params: dict[str, Any],
        target: str | None = None,
        workspace: str = "default",
        confirm_authorized: bool = False,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Start a checked long-running command and return a pollable job id."""

        self.ensure_allowed(tool, params, target=target, confirm_authorized=confirm_authorized)
        self.ensure_command_policy(tool, command, confirm_authorized=confirm_authorized)
        missing = self._missing_tool(command)
        if missing:
            return {
                "ok": False,
                "status": "missing_tool",
                "tool": tool,
                "missing": missing,
                "install_hint": f"Run install_tool(tool_name='{missing}', method='apt') or install.sh.",
                "disclaimer": DISCLAIMER,
            }
        output_path = self.sessions.output_path(workspace, tool)
        self.audit_log(tool, params, status="background_started", message=command_preview(command))
        job = await start_background_command(command, str(output_path), cwd=cwd, env=env)
        result_id = self.store.add_result(
            workspace=workspace,
            tool=tool,
            target=target,
            command=command,
            exit_code=None,
            output_path=str(output_path),
            summary={"background": True, "job_id": job["job_id"]},
            metadata={"params": self._sanitize_params(params)},
        )
        return {
            "ok": True,
            "tool": tool,
            "result_id": result_id,
            "workspace": workspace,
            "target": target,
            "command": command,
            "job": job,
            "output_path": str(output_path),
            "disclaimer": DISCLAIMER,
        }

    def write_input_file(self, workspace: str, tool: str, content: str, suffix: str = ".txt") -> Path:
        """Write command input material inside the current workspace."""

        return self.sessions.write_input_file(workspace, tool, content, suffix=suffix)

    def check_tool(self, tool_name: str) -> dict[str, Any]:
        """Return availability information for an executable."""

        path = shutil.which(tool_name)
        version = ""
        if path:
            try:
                proc = subprocess.run(
                    [tool_name, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                version = (proc.stdout or proc.stderr).splitlines()[0:1]
                version = version[0] if version else ""
            except Exception:
                version = ""
        return {"tool": tool_name, "installed": bool(path), "path": path, "version": version}

    def _missing_tool(self, command: str) -> str | None:
        try:
            head = command.split("|", 1)[0].split("&&", 1)[0].strip()
            tokens = shlex.split(head)
            if not tokens:
                return None
            executable = tokens[0]
            if executable in {"sudo", "timeout"} and len(tokens) > 1:
                if executable == "sudo":
                    executable = tokens[1]
                elif len(tokens) > 2:
                    executable = tokens[2]
            if executable.startswith(("python", "bash", "sh")):
                return None if shutil.which(executable) else executable
            if "/" in executable:
                return None if Path(executable).exists() else executable
            return None if shutil.which(executable) else executable
        except Exception:
            return None

    def _rate_limit(self, tool: str, target: str) -> None:
        limits = self.config.get("security", {}).get("rate_limits", {})
        if target == "local" and tool not in limits:
            return
        seconds = int(limits.get(tool, limits.get("default_seconds", 2)))
        key = (tool, target)
        now = time.monotonic()
        previous = self._last_call.get(key, 0.0)
        if now - previous < seconds:
            wait = round(seconds - (now - previous), 2)
            raise PermissionError(f"Rate limit active for {tool} against {target}; wait {wait}s.")
        self._last_call[key] = now

    def _sanitize_params(self, params: dict[str, Any]) -> dict[str, Any]:
        redacted = {}
        sensitive = {"password", "passphrase", "api_key", "api_token", "key_or_pass", "token"}
        for key, value in params.items():
            redacted[key] = "***REDACTED***" if key.lower() in sensitive else value
        return redacted


def create_server(config: dict[str, Any]) -> FastMCP:
    """Create and fully register the FastMCP server."""

    name = config.get("server", {}).get("name", "exnokalimcp")
    try:
        mcp = FastMCP(name, instructions=DISCLAIMER)
    except TypeError:
        mcp = FastMCP(name)
    try:
        mcp.settings.host = config.get("server", {}).get("host", "127.0.0.1")
        mcp.settings.port = int(config.get("server", {}).get("port", 8080))
    except Exception:
        pass
    services = ExnoKaliMCPServices(config)

    for module_name in TOOL_MODULES:
        module = importlib.import_module(module_name)
        module.register(mcp, services)

    for module_name in RESOURCE_MODULES:
        module = importlib.import_module(module_name)
        module.register(mcp, services)

    register_workflows(mcp, services)
    return mcp


def register_workflows(mcp: FastMCP, services: ExnoKaliMCPServices) -> None:
    """Register high-level bug bounty workflow tools."""

    @mcp.tool()
    async def bugbounty_recon(
        domain: str,
        scope: list[str],
        workspace: str = "bugbounty",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """
        Run a chained authorized bug bounty recon workflow.

        The workflow adds the supplied scope rules, enumerates subdomains, probes
        HTTP services, performs conservative scanning, gathers archived URLs,
        fingerprints web tech, and runs nuclei against discovered assets.
        """

        params = locals()
        for item in scope:
            services.sessions.add_scope(item)
        services.ensure_allowed("bugbounty_recon", params, target=domain, confirm_authorized=confirm_authorized)
        services.sessions.create_workspace(workspace, domain, "Bug bounty recon workflow")
        commands = [
            ("subfinder", f"subfinder -silent -d {quote(domain)}"),
            ("amass_passive", f"amass enum -passive -d {quote(domain)}"),
            ("waybackurls", f"waybackurls {quote(domain)}"),
            ("gau", f"gau {quote(domain)}"),
            ("whatweb", f"whatweb --no-errors {quote('https://' + domain)}"),
        ]
        results: list[dict[str, Any]] = []
        subdomain_outputs: list[str] = []
        for name, command in commands:
            result = await services.run_command_tool(
                name,
                command,
                {"domain": domain, "workspace": workspace},
                target=domain,
                workspace=workspace,
                confirm_authorized=True,
            )
            results.append(result)
            if name in {"subfinder", "amass_passive"} and result.get("ok"):
                subdomain_outputs.append(result.get("output_preview", ""))

        hosts = sorted({line.strip() for output in subdomain_outputs for line in output.splitlines() if line.strip()})
        if hosts:
            host_file = services.write_input_file(workspace, "bugbounty_recon_hosts", "\n".join(hosts) + "\n")
            results.append(
                await services.run_command_tool(
                    "httpx_probe",
                    f"httpx -silent -json -l {quote(host_file)}",
                    {"hosts_file": str(host_file)},
                    target=domain,
                    workspace=workspace,
                    confirm_authorized=True,
                )
            )
            results.append(
                await services.run_command_tool(
                    "nuclei_scan",
                    f"nuclei -silent -l {quote(host_file)}",
                    {"hosts_file": str(host_file)},
                    target=domain,
                    workspace=workspace,
                    confirm_authorized=True,
                )
            )
        return {"ok": True, "workspace": workspace, "steps": results, "disclaimer": DISCLAIMER}

    @mcp.tool()
    async def web_app_assessment(
        url: str,
        options: dict[str, Any] | None = None,
        workspace: str = "web-assessment",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """
        Run a full authorized web application assessment chain.

        The workflow fingerprints technology, performs content discovery,
        parameter discovery, vulnerability checks, TLS checks, CORS checks, WAF
        detection, and optional sqlmap testing when explicitly confirmed.
        """

        options = options or {}
        services.ensure_allowed("web_app_assessment", locals(), target=url, confirm_authorized=confirm_authorized)
        services.sessions.create_workspace(workspace, url, "Web application assessment")
        wordlist = options.get("wordlist", services.config.get("tools", {}).get("ffuf", {}).get("default_wordlist"))
        commands = [
            ("whatweb", f"whatweb --no-errors {quote(url)}"),
            ("nikto_scan", f"nikto -host {quote(url)}"),
            ("ffuf_fuzz", f"ffuf -u {quote(url.rstrip('/') + '/FUZZ')} -w {quote(wordlist)} -of json"),
            ("nuclei_scan", f"nuclei -silent -u {quote(url)}"),
            ("dalfox", f"dalfox url {quote(url)} --silence"),
            ("testssl", f"testssl.sh --fast {quote(url)}"),
            ("wafw00f", f"wafw00f {quote(url)}"),
        ]
        if confirm_authorized:
            commands.append(("sqlmap_scan", f"sqlmap -u {quote(url)} --batch --level=1 --risk=1"))
        results = []
        for name, command in commands:
            results.append(
                await services.run_command_tool(
                    name,
                    command,
                    {"url": url, "options": options},
                    target=url,
                    workspace=workspace,
                    confirm_authorized=True,
                )
            )
        return {"ok": True, "workspace": workspace, "steps": results, "disclaimer": DISCLAIMER}

    @mcp.tool()
    async def network_pentest(
        target_range: str,
        options: dict[str, Any] | None = None,
        workspace: str = "network-pentest",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """
        Run an authorized network assessment chain.

        Performs host discovery, fast port discovery, service enumeration,
        vulnerability scripts, and exploit-db lookup against discovered banners.
        """

        options = options or {}
        services.ensure_allowed("network_pentest", locals(), target=target_range, confirm_authorized=confirm_authorized)
        services.sessions.create_workspace(workspace, target_range, "Network pentest workflow")
        ports = options.get("ports", "1-1000")
        commands = [
            ("nmap_ping_sweep", f"nmap -sn {quote(target_range)}"),
            ("masscan", f"masscan {quote(target_range)} -p{quote(ports)} --rate {int(options.get('rate', 1000))}"),
            ("nmap_service_enum", f"nmap -sV -sC -p {quote(ports)} {quote(target_range)}"),
            ("nmap_vuln_scan", f"nmap -sV --script vuln -p {quote(ports)} {quote(target_range)}"),
        ]
        results = []
        for name, command in commands:
            results.append(
                await services.run_command_tool(
                    name,
                    command,
                    {"target_range": target_range, "options": options},
                    target=target_range,
                    workspace=workspace,
                    confirm_authorized=True,
                )
            )
        return {"ok": True, "workspace": workspace, "steps": results, "disclaimer": DISCLAIMER}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kali Linux MCP server for WSL")
    parser.add_argument("--config", help="Path to config.yaml")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], help="MCP transport")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    config = load_config(args.config)
    if args.transport:
        config.setdefault("server", {})["transport"] = args.transport

    stop_event = asyncio.Event()

    def _signal_handler(*_: Any) -> None:
        if not stop_event.is_set():
            stop_event.set()

    try:
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
    except ValueError:
        pass

    mcp = create_server(config)
    transport = config.get("server", {}).get("transport", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()

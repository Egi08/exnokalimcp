"""Nuclei MCP tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context

from tools import csv, join_flags, option_string, quote
from tools.parsers import parse_nuclei


def register(mcp: Any, services: Any) -> None:
    """Register nuclei tools."""

    @mcp.tool()
    async def nuclei_scan(
        target: str,
        templates: str = "",
        severity: list[str] | None = None,
        options: str = "",
        workspace: str = "default",
        timeout: int = 7200,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Run nuclei vulnerability templates against an authorized target."""

        default_severity = services.config.get("tools", {}).get("nuclei", {}).get(
            "default_severity", ["critical", "high", "medium"]
        )
        sev = csv(severity or default_severity)
        template_arg = f"-t {quote(Path(templates).expanduser())}" if templates else ""
        command = join_flags(
            ["nuclei", "-silent", "-jsonl", "-u", quote(target), "-severity", quote(sev), template_arg, option_string(options)]
        )
        return await services.run_command_tool(
            "nuclei_scan",
            command,
            locals(),
            target=target,
            workspace=workspace,
            timeout=timeout,
            parser=parse_nuclei,
            ctx=ctx,
        )

    @mcp.tool()
    async def nuclei_template_list(
        tags: list[str] | None = None,
        severity: list[str] | None = None,
    ) -> dict[str, Any]:
        """List locally available nuclei templates by optional tags or severity text."""

        services.ensure_allowed("nuclei_template_list", locals())
        templates_dir = Path(
            services.config.get("tools", {}).get("nuclei", {}).get("templates_dir", "~/nuclei-templates")
        ).expanduser()
        items: list[dict[str, str]] = []
        if templates_dir.exists():
            for path in templates_dir.rglob("*.yaml"):
                text = path.read_text(encoding="utf-8", errors="ignore")
                if tags and not all(f"- {tag}" in text or f"tags: {tag}" in text for tag in tags):
                    continue
                if severity and not any(f"severity: {sev}" in text for sev in severity):
                    continue
                items.append({"path": str(path), "name": path.stem})
        return {"ok": True, "templates_dir": str(templates_dir), "count": len(items), "templates": items[:500]}

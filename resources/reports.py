"""Workspace result MCP resources."""

from __future__ import annotations

from typing import Any


def register(mcp: Any, services: Any) -> None:
    """Register workspace result resources."""

    @mcp.resource("kali://workspaces/{name}/results")
    def get_workspace_results(name: str) -> dict[str, Any]:
        """Get all results for a workspace."""

        return services.store.get_workspace_results(name)


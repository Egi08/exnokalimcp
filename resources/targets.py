"""Target scope MCP resources."""

from __future__ import annotations

from typing import Any


def register(mcp: Any, services: Any) -> None:
    """Register target resources."""

    @mcp.resource("kali://targets/scope")
    def get_scope() -> dict[str, Any]:
        """Get current engagement scope."""

        return {
            "scope_enforcement": services.sessions.scope_enforcement,
            "scope_file": str(services.sessions.scope_file),
            "targets": services.sessions.list_scope(),
        }


"""Shared helpers for ExnoKaliMCP tool modules."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

DISCLAIMER = """WARNING: This MCP server is for AUTHORIZED penetration testing only.
Unauthorized access to systems is illegal.
Ensure you have written permission before proceeding."""


def quote(value: Any) -> str:
    """Return a shell-quoted representation of a value."""

    return shlex.quote(str(value))


def option_string(options: str | None) -> str:
    """Convert a free-form option string into quoted shell tokens."""

    if not options:
        return ""
    return " ".join(quote(part) for part in shlex.split(options))


def join_flags(parts: Iterable[str | None]) -> str:
    """Join non-empty command fragments with single spaces."""

    return " ".join(part for part in parts if part)


def csv(values: Sequence[str] | str | None) -> str:
    """Return comma-separated CLI value text from a list or scalar."""

    if values is None:
        return ""
    if isinstance(values, str):
        return values
    return ",".join(str(item) for item in values)


def json_dumps(data: Any) -> str:
    """Serialize a value deterministically for storage or output."""

    return json.dumps(data, sort_keys=True, ensure_ascii=False)


def parse_headers(headers: Mapping[str, str] | str | None) -> list[str]:
    """Normalize HTTP headers into command-line header values."""

    if headers is None:
        return []
    if isinstance(headers, str):
        return [line.strip() for line in headers.splitlines() if line.strip()]
    return [f"{key}: {value}" for key, value in headers.items()]


def expand_path(path: str | Path) -> Path:
    """Expand user and environment variables in a filesystem path."""

    return Path(str(path)).expanduser().resolve()


def command_preview(command: str, limit: int = 300) -> str:
    """Return a compact command preview for audit output."""

    return command if len(command) <= limit else command[: limit - 3] + "..."


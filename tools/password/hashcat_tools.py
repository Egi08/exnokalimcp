"""Hashcat and hash utility MCP tools."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

from tools import join_flags, option_string, quote


def _identify_hash(hash_string: str) -> dict[str, Any]:
    length = len(hash_string.strip())
    candidates: list[str] = []
    hex_only = all(ch in "0123456789abcdefABCDEF" for ch in hash_string.strip())
    if hex_only:
        if length == 32:
            candidates.extend(["MD5", "NTLM"])
        elif length == 40:
            candidates.append("SHA1")
        elif length == 64:
            candidates.extend(["SHA256", "SHA3-256"])
        elif length == 96:
            candidates.append("SHA384")
        elif length == 128:
            candidates.extend(["SHA512", "SHA3-512"])
    if hash_string.startswith("$2"):
        candidates.append("bcrypt")
    if hash_string.startswith("$6$"):
        candidates.append("sha512crypt")
    if hash_string.startswith("$y$"):
        candidates.append("yescrypt")
    return {"length": length, "hex": hex_only, "candidates": candidates or ["unknown"]}


def register(mcp: Any, services: Any) -> None:
    """Register hashcat and hash helper tools."""

    @mcp.tool()
    async def hashcat_crack(
        hash: str,
        hash_type: int,
        wordlist: str,
        rules: str = "",
        options: str = "",
        workspace: str = "default",
        timeout: int = 7200,
    ) -> dict[str, Any]:
        """Run hashcat against a provided hash and wordlist for authorized recovery."""

        hash_file = services.write_input_file(workspace, "hashcat_hash", hash.strip() + "\n", ".hash")
        rule_arg = f"-r {quote(rules)}" if rules else ""
        command = join_flags(
            ["hashcat", "-m", quote(hash_type), quote(hash_file), quote(wordlist), rule_arg, option_string(options)]
        )
        return await services.run_command_tool(
            "hashcat_crack",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def hash_identify(hash_string: str) -> dict[str, Any]:
        """Identify likely hash formats from the string shape."""

        services.ensure_allowed("hash_identify", locals())
        info = _identify_hash(hash_string)
        return {"ok": True, "hash": hash_string[:12] + "..." if len(hash_string) > 12 else hash_string, **info}

    @mcp.tool()
    async def hash_decode(hash: str, hash_type: str = "auto") -> dict[str, Any]:
        """Try common safe local decodings such as hex and base64."""

        services.ensure_allowed("hash_decode", locals())
        attempts: dict[str, str] = {}
        value = hash.strip()
        for name, func in {
            "hex": lambda v: bytes.fromhex(v),
            "base64": lambda v: base64.b64decode(v, validate=True),
            "urlsafe_base64": lambda v: base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)),
        }.items():
            try:
                decoded = func(value)
                attempts[name] = decoded.decode("utf-8", errors="replace")
            except (ValueError, binascii.Error):
                pass
        if hash_type.lower() in {"md5", "sha1", "sha256", "sha512"}:
            attempts["note"] = f"{hash_type} is one-way; use hashcat_crack or john_crack with authorization."
        return {"ok": True, "identify": _identify_hash(value), "decodings": attempts}

    @mcp.tool()
    async def crunch_wordlist(
        min_len: int,
        max_len: int,
        charset: str,
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Generate a custom wordlist with crunch and save it in the workspace."""

        output = services.sessions.output_path(workspace, "crunch_wordlist", ".txt", folder="raw")
        command = join_flags(
            ["crunch", quote(min_len), quote(max_len), quote(charset), "-o", quote(output), option_string(options)]
        )
        result = await services.run_command_tool(
            "crunch_wordlist",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
        )
        result["wordlist_path"] = str(output)
        return result

    @mcp.tool()
    async def cewl_wordlist(
        url: str,
        depth: int = 2,
        min_length: int = 5,
        options: str = "",
        workspace: str = "default",
        timeout: int = 3600,
    ) -> dict[str, Any]:
        """Generate a wordlist from an authorized website using CeWL."""

        output = services.sessions.output_path(workspace, "cewl_wordlist", ".txt", folder="raw")
        command = join_flags(
            [
                "cewl",
                quote(url),
                "-d",
                quote(depth),
                "-m",
                quote(min_length),
                "-w",
                quote(output),
                option_string(options),
            ]
        )
        result = await services.run_command_tool(
            "cewl_wordlist",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )
        result["wordlist_path"] = str(output)
        return result


"""Wordlist, tool inventory, template, and exploit-db MCP resources."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


KALI_TOOL_BINARIES = [
    "nmap",
    "masscan",
    "naabu",
    "subfinder",
    "amass",
    "dnsx",
    "httpx",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "nikto",
    "sqlmap",
    "xsstrike",
    "dalfox",
    "nuclei",
    "wpscan",
    "joomscan",
    "whatweb",
    "wapiti",
    "dirsearch",
    "arjun",
    "paramspider",
    "jwt_tool",
    "ssrfmap",
    "corscanner",
    "testssl.sh",
    "wafw00f",
    "searchsploit",
    "msfconsole",
    "msfvenom",
    "hashcat",
    "john",
    "hydra",
    "medusa",
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "wifite",
    "tcpdump",
    "tshark",
    "nc",
    "socat",
    "ssh",
    "proxychains4",
    "curl",
    "wget",
    "strings",
    "binwalk",
    "exiftool",
    "steghide",
    "volatility3",
    "foremost",
]


def register(mcp: Any, services: Any) -> None:
    """Register inventory resources."""

    @mcp.resource("kali://wordlists")
    def list_wordlists() -> dict[str, Any]:
        """List all available wordlists on the system."""

        base = Path(services.config.get("paths", {}).get("wordlists_dir", "/usr/share/wordlists")).expanduser()
        items = []
        if base.exists():
            for path in base.rglob("*"):
                if path.is_file():
                    items.append({"name": path.name, "path": str(path), "size": path.stat().st_size})
                    if len(items) >= 1000:
                        break
        return {"wordlists_dir": str(base), "count": len(items), "items": items}

    @mcp.resource("kali://wordlists/{name}")
    def get_wordlist_info(name: str) -> dict[str, Any]:
        """Get info about a specific wordlist."""

        base = Path(services.config.get("paths", {}).get("wordlists_dir", "/usr/share/wordlists")).expanduser()
        matches = [path for path in base.rglob(name) if path.is_file()] if base.exists() else []
        if not matches:
            return {"found": False, "name": name, "wordlists_dir": str(base)}
        path = matches[0]
        sample = path.read_text(encoding="utf-8", errors="replace").splitlines()[:20]
        return {"found": True, "name": name, "path": str(path), "size": path.stat().st_size, "sample": sample}

    @mcp.resource("kali://tools/installed")
    def list_installed_tools() -> list[dict[str, Any]]:
        """List all installed Kali tools."""

        return [services.check_tool(tool) for tool in KALI_TOOL_BINARIES]

    @mcp.resource("kali://templates/nuclei")
    def list_nuclei_templates() -> dict[str, Any]:
        """List all nuclei templates by category."""

        templates_dir = Path(
            services.config.get("tools", {}).get("nuclei", {}).get("templates_dir", "~/nuclei-templates")
        ).expanduser()
        categories: dict[str, int] = {}
        examples: list[str] = []
        if templates_dir.exists():
            for path in templates_dir.rglob("*.yaml"):
                rel = path.relative_to(templates_dir)
                category = rel.parts[0] if rel.parts else "root"
                categories[category] = categories.get(category, 0) + 1
                if len(examples) < 100:
                    examples.append(str(rel))
        return {"templates_dir": str(templates_dir), "categories": categories, "examples": examples}

    @mcp.resource("kali://exploits/recent")
    def recent_exploits() -> list[dict[str, Any]]:
        """Recent entries from exploit-db."""

        csv_path = Path("/usr/share/exploitdb/files_exploits.csv")
        if not csv_path.exists():
            return [{"error": "exploit-db CSV not found", "install_hint": "sudo apt-get install exploitdb"}]
        rows = []
        with csv_path.open(newline="", encoding="utf-8", errors="replace") as handle:
            reader = list(csv.DictReader(handle))
        for row in reader[-50:]:
            rows.append(row)
        return rows

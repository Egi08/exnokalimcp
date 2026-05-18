"""Tool availability, package mapping, and on-demand install planning."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    """Package metadata for a Kali CLI tool."""

    binary: str
    category: str = "misc"
    apt: str | None = None
    go: str | None = None
    pipx: str | None = None
    pip: str | None = None
    aliases: tuple[str, ...] = ()
    notes: str = ""


DEFAULT_TOOL_SPECS: dict[str, ToolSpec] = {
    "python3": ToolSpec("python3", "runtime", apt="python3"),
    "pipx": ToolSpec("pipx", "runtime", apt="pipx", pip="pipx"),
    "go": ToolSpec("go", "runtime", apt="golang-go"),
    "git": ToolSpec("git", "runtime", apt="git"),
    "curl": ToolSpec("curl", "runtime", apt="curl"),
    "wget": ToolSpec("wget", "runtime", apt="wget"),
    "jq": ToolSpec("jq", "runtime", apt="jq"),
    "unzip": ToolSpec("unzip", "runtime", apt="unzip"),
    "nmap": ToolSpec("nmap", "recon", apt="nmap"),
    "masscan": ToolSpec("masscan", "recon", apt="masscan"),
    "naabu": ToolSpec("naabu", "recon", go="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "subfinder": ToolSpec(
        "subfinder", "recon", go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ),
    "amass": ToolSpec("amass", "recon", apt="amass"),
    "dnsx": ToolSpec("dnsx", "recon", go="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "httpx": ToolSpec("httpx", "recon", go="github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "whois": ToolSpec("whois", "recon", apt="whois"),
    "dig": ToolSpec("dig", "recon", apt="dnsutils"),
    "theHarvester": ToolSpec("theHarvester", "recon", apt="theharvester", aliases=("theharvester",)),
    "recon-ng": ToolSpec("recon-ng", "recon", apt="recon-ng"),
    "sherlock": ToolSpec("sherlock", "recon", apt="sherlock"),
    "shodan": ToolSpec("shodan", "recon", pipx="shodan"),
    "waybackurls": ToolSpec("waybackurls", "recon", go="github.com/tomnomnom/waybackurls@latest"),
    "gau": ToolSpec("gau", "recon", go="github.com/lc/gau/v2/cmd/gau@latest"),
    "ffuf": ToolSpec("ffuf", "web", apt="ffuf"),
    "gobuster": ToolSpec("gobuster", "web", apt="gobuster"),
    "feroxbuster": ToolSpec("feroxbuster", "web", apt="feroxbuster"),
    "dirsearch": ToolSpec("dirsearch", "web", apt="dirsearch"),
    "nikto": ToolSpec("nikto", "web", apt="nikto"),
    "sqlmap": ToolSpec("sqlmap", "web", apt="sqlmap"),
    "xsstrike": ToolSpec("xsstrike", "web", pipx="xsstrike"),
    "dalfox": ToolSpec("dalfox", "web", go="github.com/hahwul/dalfox/v2@latest"),
    "nuclei": ToolSpec("nuclei", "web", apt="nuclei", go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "wpscan": ToolSpec("wpscan", "web", apt="wpscan"),
    "joomscan": ToolSpec("joomscan", "web", apt="joomscan"),
    "whatweb": ToolSpec("whatweb", "web", apt="whatweb"),
    "wapiti": ToolSpec("wapiti", "web", apt="wapiti"),
    "arjun": ToolSpec("arjun", "web", pipx="arjun"),
    "paramspider": ToolSpec("paramspider", "web", pipx="paramspider"),
    "jwt_tool": ToolSpec("jwt_tool", "web", pipx="jwt-tool", aliases=("jwt-tool",)),
    "ssrfmap": ToolSpec("ssrfmap", "web", pipx="ssrfmap"),
    "corscanner": ToolSpec("corscanner", "web", pipx="corscanner"),
    "testssl.sh": ToolSpec("testssl.sh", "web", apt="testssl.sh", aliases=("testssl",)),
    "wafw00f": ToolSpec("wafw00f", "web", apt="wafw00f"),
    "gowitness": ToolSpec("gowitness", "web", go="github.com/sensepost/gowitness@latest"),
    "searchsploit": ToolSpec("searchsploit", "exploit", apt="exploitdb"),
    "msfconsole": ToolSpec("msfconsole", "exploit", apt="metasploit-framework"),
    "msfvenom": ToolSpec("msfvenom", "exploit", apt="metasploit-framework"),
    "pwncat-cs": ToolSpec("pwncat-cs", "exploit", pipx="pwncat-cs", aliases=("pwncat",)),
    "tcpdump": ToolSpec("tcpdump", "network", apt="tcpdump"),
    "tshark": ToolSpec("tshark", "network", apt="tshark"),
    "wireshark": ToolSpec("wireshark", "network", apt="wireshark"),
    "nc": ToolSpec("nc", "network", apt="netcat-openbsd", aliases=("netcat",)),
    "socat": ToolSpec("socat", "network", apt="socat"),
    "ssh": ToolSpec("ssh", "network", apt="openssh-client"),
    "sshpass": ToolSpec("sshpass", "network", apt="sshpass"),
    "proxychains4": ToolSpec("proxychains4", "network", apt="proxychains4", aliases=("proxychains",)),
    "netdiscover": ToolSpec("netdiscover", "network", apt="netdiscover"),
    "arp-scan": ToolSpec("arp-scan", "network", apt="arp-scan"),
    "hashcat": ToolSpec("hashcat", "password", apt="hashcat"),
    "john": ToolSpec("john", "password", apt="john"),
    "hydra": ToolSpec("hydra", "password", apt="hydra"),
    "medusa": ToolSpec("medusa", "password", apt="medusa"),
    "hashid": ToolSpec("hashid", "password", apt="hashid"),
    "crunch": ToolSpec("crunch", "password", apt="crunch"),
    "cewl": ToolSpec("cewl", "password", apt="cewl"),
    "airmon-ng": ToolSpec("airmon-ng", "wireless", apt="aircrack-ng"),
    "airodump-ng": ToolSpec("airodump-ng", "wireless", apt="aircrack-ng"),
    "aireplay-ng": ToolSpec("aireplay-ng", "wireless", apt="aircrack-ng"),
    "aircrack-ng": ToolSpec("aircrack-ng", "wireless", apt="aircrack-ng"),
    "wifite": ToolSpec("wifite", "wireless", apt="wifite"),
    "strings": ToolSpec("strings", "forensics", apt="binutils"),
    "binwalk": ToolSpec("binwalk", "forensics", apt="binwalk"),
    "exiftool": ToolSpec("exiftool", "forensics", apt="libimage-exiftool-perl"),
    "file": ToolSpec("file", "forensics", apt="file"),
    "hexdump": ToolSpec("hexdump", "forensics", apt="bsdextrautils"),
    "steghide": ToolSpec("steghide", "forensics", apt="steghide"),
    "volatility3": ToolSpec("volatility3", "forensics", apt="volatility3"),
    "foremost": ToolSpec("foremost", "forensics", apt="foremost"),
}


TASK_HINTS: dict[str, list[str]] = {
    "port": ["nmap", "masscan", "naabu"],
    "service": ["nmap", "whatweb", "httpx"],
    "subdomain": ["subfinder", "amass", "dnsx"],
    "dns": ["dnsx", "dig", "whois"],
    "http": ["httpx", "whatweb", "curl"],
    "directory": ["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    "content": ["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    "vulnerability": ["nuclei", "nikto", "wapiti"],
    "sql": ["sqlmap"],
    "xss": ["dalfox", "xsstrike"],
    "ssl": ["testssl.sh"],
    "waf": ["wafw00f"],
    "exploit": ["searchsploit", "msfconsole"],
    "password": ["john", "hashcat", "hydra"],
    "hash": ["hashid", "john", "hashcat"],
    "packet": ["tcpdump", "tshark"],
    "wireless": ["airmon-ng", "airodump-ng", "aircrack-ng"],
    "forensics": ["file", "strings", "binwalk", "exiftool"],
    "screenshot": ["gowitness"],
}


class ToolResolver:
    """Resolve Kali command availability and installation commands."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config.get("tool_resolver", {})
        self.specs = self._build_specs()
        self.aliases = self._build_aliases()

    @property
    def enabled(self) -> bool:
        """Return whether resolver checks are enabled."""

        return bool(self.config.get("enabled", True))

    @property
    def auto_install(self) -> bool:
        """Return whether missing tools may be installed automatically."""

        return bool(self.config.get("auto_install", False))

    @property
    def install_timeout(self) -> int:
        """Return the timeout for resolver-driven installs."""

        return int(self.config.get("install_timeout", 7200))

    @property
    def default_method(self) -> str:
        """Return the preferred install method."""

        return str(self.config.get("install_method", "auto")).lower()

    def apply_path(self) -> None:
        """Add common WSL tool locations to PATH for this MCP process."""

        current = os.environ.get("PATH", "")
        parts = current.split(os.pathsep) if current else []
        for item in self.config.get("extra_paths", ["~/.local/bin", "~/go/bin"]):
            expanded = str(Path(str(item)).expanduser())
            if expanded not in parts:
                parts.append(expanded)
        os.environ["PATH"] = os.pathsep.join(part for part in parts if part)

    def which(self, tool_name: str) -> str | None:
        """Find a binary while honoring resolver extra PATH entries."""

        if "/" in tool_name:
            path = Path(tool_name).expanduser()
            return str(path) if path.exists() else None
        canonical = self._canonical(tool_name)
        spec = self.specs.get(canonical)
        candidates = [tool_name, canonical]
        if spec:
            candidates.extend(spec.aliases)
        seen: set[str] = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            path = shutil.which(candidate)
            if path:
                return path
        return None

    def check(self, tool_name: str) -> dict[str, Any]:
        """Return installed status, version, and install metadata for a tool."""

        canonical = self._canonical(tool_name)
        spec = self.specs.get(canonical)
        path = self.which(canonical)
        version = self._version(canonical) if path else ""
        return {
            "tool": tool_name,
            "binary": canonical,
            "installed": bool(path),
            "path": path,
            "version": version,
            "resolver": self.resolve(canonical, include_check=False),
            "aliases": list(spec.aliases) if spec else [],
        }

    def resolve(self, tool_name: str, include_check: bool = True) -> dict[str, Any]:
        """Return package suggestions for a tool without installing it."""

        canonical = self._canonical(tool_name)
        spec = self.specs.get(canonical)
        commands = self.install_commands(canonical)
        recommended = self._recommended_method(canonical)
        result: dict[str, Any] = {
            "tool": tool_name,
            "binary": canonical,
            "known": spec is not None,
            "category": spec.category if spec else "unknown",
            "recommended_method": recommended,
            "install_commands": commands,
            "notes": spec.notes if spec else "No curated mapping; apt install is the safest first attempt on Kali.",
        }
        if spec:
            result["packages"] = {
                "apt": spec.apt,
                "go": spec.go,
                "pipx": spec.pipx,
                "pip": spec.pip,
            }
        if include_check:
            path = self.which(canonical)
            result["installed"] = bool(path)
            result["path"] = path
        return result

    def install_commands(self, tool_name: str) -> dict[str, str]:
        """Return available installation commands by method."""

        canonical = self._canonical(tool_name)
        spec = self.specs.get(canonical)
        commands: dict[str, str] = {}
        if spec and spec.apt:
            commands["apt"] = f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {self._q(spec.apt)}"
        elif not spec:
            commands["apt"] = f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {self._q(canonical)}"
        if spec and spec.go:
            commands["go"] = f"go install {self._q(spec.go)}"
        if spec and spec.pipx:
            commands["pipx"] = f"pipx install {self._q(spec.pipx)}"
        if spec and spec.pip:
            commands["pip"] = f"python3 -m pip install --user {self._q(spec.pip)}"
        return commands

    def install_command(self, tool_name: str, method: str = "auto", update_apt: bool = True) -> str:
        """Build a single install command for a tool and method."""

        method = (method or "auto").lower()
        if method == "auto":
            method = self._recommended_method(tool_name)
        commands = self.install_commands(tool_name)
        command = commands.get(method, "")
        if method == "apt" and command and update_apt:
            return f"sudo apt-get update && {command}"
        return command

    def inventory(self, category: str = "", only_missing: bool = False) -> list[dict[str, Any]]:
        """Return installed/missing state for all known tools."""

        selected = []
        for name, spec in sorted(self.specs.items()):
            if category and spec.category != category:
                continue
            item = self.check(name)
            if only_missing and item["installed"]:
                continue
            selected.append(item)
        return selected

    def suggest(self, task: str, target_type: str = "") -> dict[str, Any]:
        """Suggest useful tools based on a short task description."""

        text = f"{task} {target_type}".lower()
        matches: list[str] = []
        for keyword, tools in TASK_HINTS.items():
            if keyword in text:
                matches.extend(tools)
        if not matches:
            matches = ["nmap", "httpx", "ffuf", "nuclei", "whatweb"]
        seen: set[str] = set()
        unique = [tool for tool in matches if not (tool in seen or seen.add(tool))]
        return {
            "task": task,
            "target_type": target_type,
            "recommendations": [self.check(tool) for tool in unique],
        }

    def missing_from_command(self, command: str) -> str | None:
        """Return the first missing executable in a shell command, if obvious."""

        if not self.enabled:
            return None
        executable = self.command_executable(command)
        if not executable:
            return None
        if executable.startswith(("python", "bash", "sh")):
            return None if shutil.which(executable) else executable
        if "/" in executable:
            return None if Path(executable).expanduser().exists() else executable
        return None if self.which(executable) else self._canonical(executable)

    def command_executable(self, command: str) -> str:
        """Best-effort extraction of the primary executable from a shell command."""

        head = self._first_segment(command)
        try:
            tokens = shlex.split(head)
        except ValueError:
            return ""
        while tokens:
            executable = tokens.pop(0)
            if executable in {"sudo", "command", "builtin", "exec"}:
                while tokens and tokens[0].startswith("-"):
                    tokens.pop(0)
                continue
            if executable in {"timeout", "gtimeout"}:
                while tokens and tokens[0].startswith("-"):
                    tokens.pop(0)
                if tokens:
                    tokens.pop(0)
                continue
            if executable == "env":
                while tokens and ("=" in tokens[0] or tokens[0].startswith("-")):
                    tokens.pop(0)
                continue
            if executable in {"time", "stdbuf"}:
                while tokens and tokens[0].startswith("-"):
                    tokens.pop(0)
                continue
            if executable in {"proxychains", "proxychains4"} and tokens:
                continue
            return executable
        return ""

    def _build_specs(self) -> dict[str, ToolSpec]:
        specs = dict(DEFAULT_TOOL_SPECS)
        overrides = self.config.get("package_overrides", {})
        if isinstance(overrides, dict):
            for name, values in overrides.items():
                if not isinstance(values, dict):
                    continue
                canonical = self._canonical(str(name), specs)
                base = specs.get(canonical, ToolSpec(binary=canonical))
                fields = {key: values[key] for key in ("category", "apt", "go", "pipx", "pip", "notes") if key in values}
                if "aliases" in values:
                    fields["aliases"] = tuple(str(item) for item in values["aliases"])
                specs[canonical] = replace(base, **fields)
        return specs

    def _build_aliases(self) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for name, spec in self.specs.items():
            aliases[name] = name
            for alias in spec.aliases:
                aliases[alias] = name
        return aliases

    def _canonical(self, tool_name: str, specs: dict[str, ToolSpec] | None = None) -> str:
        aliases = self.aliases if hasattr(self, "aliases") else {}
        if tool_name in aliases:
            return aliases[tool_name]
        source = specs or getattr(self, "specs", DEFAULT_TOOL_SPECS)
        for name, spec in source.items():
            if tool_name == name or tool_name in spec.aliases:
                return name
        return tool_name

    def _recommended_method(self, tool_name: str) -> str:
        configured = self.default_method
        if configured != "auto":
            return configured
        spec = self.specs.get(self._canonical(tool_name))
        if not spec:
            return "apt"
        for method in ("apt", "go", "pipx", "pip"):
            if getattr(spec, method):
                return method
        return "apt"

    def _version(self, tool_name: str) -> str:
        for flag in ("--version", "-version", "version", "-h"):
            try:
                proc = subprocess.run(
                    [tool_name, flag],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
            except Exception:
                continue
            output = (proc.stdout or proc.stderr).strip()
            if output:
                return output.splitlines()[0][:300]
        return ""

    @staticmethod
    def _first_segment(command: str) -> str:
        separators = ("|", "&&", "||", ";")
        head = command.strip()
        for separator in separators:
            head = head.split(separator, 1)[0].strip()
        return head

    @staticmethod
    def _q(value: str) -> str:
        return shlex.quote(str(value))

    def to_dict(self) -> dict[str, Any]:
        """Return resolver metadata for debugging."""

        return {name: asdict(spec) for name, spec in sorted(self.specs.items())}

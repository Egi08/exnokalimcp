"""Workspace, scope, and target management for ExnoKaliMCP."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _expand(path: str) -> Path:
    return Path(path).expanduser().resolve()


def normalize_host(target: str) -> str:
    """Extract a hostname or IP from a URL, CIDR, host:port, or raw target."""

    text = str(target).strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"//{text}")
    host = parsed.hostname or text
    if "/" in text and "://" not in text:
        return text.split()[0]
    return host.strip("[]").lower()


@dataclass(frozen=True)
class ScopeMatch:
    allowed: bool
    rule: str | None = None
    reason: str = ""


class SessionManager:
    """Manage persistent workspaces and authorized target scope."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        paths = config.get("paths", {})
        security = config.get("security", {})
        self.workspace_dir = _expand(paths.get("workspace_dir", "~/exnokalimcp-workspaces"))
        self.scope_file = _expand(security.get("scope_file", "~/.exnokalimcp/scope.txt"))
        self.scope_enforcement = bool(security.get("scope_enforcement", True))
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.scope_file.parent.mkdir(parents=True, exist_ok=True)
        self.scope_file.touch(exist_ok=True)

    def list_scope(self) -> list[str]:
        """Return all active non-comment scope rules."""

        rules: list[str] = []
        for line in self.scope_file.read_text(encoding="utf-8").splitlines():
            rule = line.strip()
            if rule and not rule.startswith("#"):
                rules.append(rule)
        return rules

    def add_scope(self, target: str) -> None:
        """Add a target or pattern to the scope file if it is not present."""

        target = target.strip()
        if not target:
            raise ValueError("target cannot be empty")
        rules = self.list_scope()
        if target not in rules:
            with self.scope_file.open("a", encoding="utf-8") as handle:
                handle.write(target + "\n")

    def remove_scope(self, target: str) -> bool:
        """Remove a target or pattern from scope."""

        removed = False
        lines = self.scope_file.read_text(encoding="utf-8").splitlines()
        kept: list[str] = []
        for line in lines:
            if line.strip() == target:
                removed = True
            else:
                kept.append(line)
        self.scope_file.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
        return removed

    def check_scope(self, target: str) -> ScopeMatch:
        """Verify that a target is within the configured authorized scope."""

        if not self.scope_enforcement:
            return ScopeMatch(True, reason="scope enforcement disabled")
        if not target:
            return ScopeMatch(True, reason="no network target supplied")

        host = normalize_host(target)
        if not host:
            return ScopeMatch(False, reason="empty target after normalization")

        rules = self.list_scope()
        if not rules:
            return ScopeMatch(False, reason=f"scope file is empty: {self.scope_file}")

        for rule in rules:
            if self._match_rule(host, rule, target):
                return ScopeMatch(True, rule=rule, reason="matched scope rule")
        return ScopeMatch(False, reason=f"{host} is not in authorized scope")

    def check_targets(self, targets: list[str]) -> dict[str, Any]:
        """Check multiple targets and return allow/deny details."""

        results = []
        blocked = []
        for target in targets:
            match = self.check_scope(target)
            item = {"target": target, "allowed": match.allowed, "rule": match.rule, "reason": match.reason}
            results.append(item)
            if not match.allowed:
                blocked.append(item)
        return {"allowed": not blocked, "checked": len(results), "blocked": blocked, "results": results}

    def _match_rule(self, host: str, rule: str, raw_target: str) -> bool:
        rule_text = rule.strip().lower()
        if not rule_text:
            return False
        rule_host = normalize_host(rule_text)

        try:
            if "/" in rule_host:
                network = ipaddress.ip_network(rule_host, strict=False)
                try:
                    if "/" in host:
                        return ipaddress.ip_network(host, strict=False).subnet_of(network)
                    return ipaddress.ip_address(host) in network
                except ValueError:
                    return False
        except ValueError:
            pass

        if rule_host.startswith("*."):
            suffix = rule_host[1:]
            return host.endswith(suffix) and host != rule_host[2:]

        if any(char in rule_host for char in "*?[]"):
            return fnmatch.fnmatch(host, rule_host)

        if rule_host == host:
            return True
        return host.endswith("." + rule_host)

    def create_workspace(self, name: str, target: str = "", description: str = "") -> dict[str, Any]:
        """Create or update a workspace metadata file."""

        safe_name = self._safe_workspace_name(name)
        path = self.workspace_dir / safe_name
        for child in ("raw", "reports", "inputs", "screenshots"):
            (path / child).mkdir(parents=True, exist_ok=True)
        metadata_path = path / "workspace.json"
        metadata = {
            "name": safe_name,
            "target": target,
            "description": description,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "path": str(path),
        }
        if metadata_path.exists():
            old = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["created_at"] = old.get("created_at", metadata["created_at"])
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return metadata

    def list_workspaces(self) -> list[dict[str, Any]]:
        """List workspace metadata."""

        items: list[dict[str, Any]] = []
        for path in sorted(self.workspace_dir.iterdir()):
            if not path.is_dir():
                continue
            metadata_path = path / "workspace.json"
            if metadata_path.exists():
                try:
                    items.append(json.loads(metadata_path.read_text(encoding="utf-8")))
                    continue
                except json.JSONDecodeError:
                    pass
            items.append({"name": path.name, "path": str(path)})
        return items

    def workspace_path(self, name: str = "default") -> Path:
        """Return a workspace path, creating it when needed."""

        safe_name = self._safe_workspace_name(name or "default")
        if not (self.workspace_dir / safe_name / "workspace.json").exists():
            self.create_workspace(safe_name)
        return self.workspace_dir / safe_name

    def output_path(self, workspace: str, tool: str, suffix: str = ".txt", folder: str = "raw") -> Path:
        """Create a timestamped output path inside a workspace."""

        base = self.workspace_path(workspace) / folder
        base.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_tool = re.sub(r"[^A-Za-z0-9_.-]+", "_", tool)
        return base / f"{stamp}_{safe_tool}{suffix}"

    def write_input_file(self, workspace: str, tool: str, content: str, suffix: str = ".txt") -> Path:
        """Write transient command input into the workspace input folder."""

        path = self.output_path(workspace, tool, suffix=suffix, folder="inputs")
        path.write_text(content, encoding="utf-8")
        return path

    def _safe_workspace_name(self, name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip())[:80]
        if not safe:
            raise ValueError("workspace name cannot be empty")
        return safe

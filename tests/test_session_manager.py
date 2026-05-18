"""Tests for scope and workspace management."""

from __future__ import annotations

from pathlib import Path

from tools.session_manager import SessionManager, normalize_host


def _config(tmp_path: Path) -> dict:
    return {
        "paths": {"workspace_dir": str(tmp_path / "workspaces")},
        "security": {"scope_enforcement": True, "scope_file": str(tmp_path / "scope.txt")},
    }


def test_normalize_host() -> None:
    assert normalize_host("https://Example.COM:443/path") == "example.com"
    assert normalize_host("192.168.1.0/24") == "192.168.1.0/24"


def test_scope_allows_domain_subdomain_and_cidr(tmp_path: Path) -> None:
    manager = SessionManager(_config(tmp_path))
    manager.add_scope("example.com")
    manager.add_scope("192.168.56.0/24")
    assert manager.check_scope("example.com").allowed
    assert manager.check_scope("api.example.com").allowed
    assert manager.check_scope("192.168.56.10").allowed
    assert not manager.check_scope("other.com").allowed


def test_check_targets_reports_blocked(tmp_path: Path) -> None:
    manager = SessionManager(_config(tmp_path))
    manager.add_scope("*.example.com")
    result = manager.check_targets(["api.example.com", "evil.test"])
    assert result["allowed"] is False
    assert result["blocked"][0]["target"] == "evil.test"


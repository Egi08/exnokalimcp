"""Tool resolver tests."""

from __future__ import annotations

from tools.tool_resolver import ToolResolver


def test_resolver_maps_go_and_apt_tools() -> None:
    resolver = ToolResolver({"tool_resolver": {}})

    subfinder = resolver.resolve("subfinder")
    nmap = resolver.resolve("nmap")

    assert subfinder["recommended_method"] == "go"
    assert "go install" in subfinder["install_commands"]["go"]
    assert nmap["recommended_method"] == "apt"
    assert "apt-get install" in nmap["install_commands"]["apt"]


def test_resolver_extracts_wrapped_command_executable() -> None:
    resolver = ToolResolver({"tool_resolver": {}})

    assert resolver.command_executable("sudo -E timeout 10 nmap -sV example.com") == "nmap"
    assert resolver.command_executable("env FOO=bar ffuf -u https://example.com/FUZZ") == "ffuf"


def test_resolver_suggests_task_tools() -> None:
    resolver = ToolResolver({"tool_resolver": {}})

    result = resolver.suggest("directory fuzzing for web content", target_type="url")
    names = {item["binary"] for item in result["recommendations"]}

    assert {"ffuf", "gobuster"} <= names

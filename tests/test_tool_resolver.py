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


def test_install_plan_falls_back_when_requested_method_is_unavailable() -> None:
    resolver = ToolResolver({"tool_resolver": {}})

    plan = resolver.install_plan("gowitness", method="apt")

    assert plan["requested_method"] == "apt"
    assert plan["effective_method"] == "go"
    assert plan["method_fallback"] is True
    assert "go install" in plan["command"]
    assert "github.com/sensepost/gowitness@3.0.5" in plan["command"]


def test_configured_install_method_falls_back_for_tool_without_that_method() -> None:
    resolver = ToolResolver({"tool_resolver": {"install_method": "apt"}})

    assert resolver.resolve("gowitness")["recommended_method"] == "go"


def test_version_skips_failed_version_flags(monkeypatch) -> None:
    class Completed:
        def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    calls: list[str] = []

    def fake_run(args, **_kwargs):
        calls.append(args[1])
        if args[1] == "--version":
            return Completed(1, stderr="unknown flag: --version")
        if args[1] == "version":
            return Completed(0, stdout="gowitness 3.0.5\n")
        return Completed(1)

    monkeypatch.setattr("tools.tool_resolver.subprocess.run", fake_run)
    resolver = ToolResolver({"tool_resolver": {}})

    assert resolver._version("gowitness") == "gowitness 3.0.5"
    assert calls[:3] == ["--version", "-version", "version"]

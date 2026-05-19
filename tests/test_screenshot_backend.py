"""Desktop screenshot backend tests."""

from __future__ import annotations

from pathlib import Path

from tools.shell.terminal_tools import (
    _desktop_screenshot_command,
    _powershell_screenshot_script,
    _wsl_windows_path,
)


def test_wsl_windows_path_converts_mounted_drive() -> None:
    assert _wsl_windows_path(Path("/mnt/e/MCP/out.png")) == "E:\\MCP\\out.png"


def test_wsl_windows_path_converts_linux_home_to_unc(monkeypatch) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")

    assert _wsl_windows_path(Path("/home/exnomous/out.png")) == (
        "\\\\wsl.localhost\\kali-linux\\home\\exnomous\\out.png"
    )


def test_powershell_screenshot_script_embeds_output_instead_of_env() -> None:
    script = _powershell_screenshot_script("C:\\Temp\\screen.png", active_window=True, delay_ms=250)

    assert "$out = 'C:\\Temp\\screen.png'" in script
    assert "$active = $true" in script
    assert "$delayMs = 250" in script
    assert "EXNOKALIMCP_SCREENSHOT_OUT" not in script


def test_windows_screenshot_command_does_not_depend_on_wsl_env(monkeypatch) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")

    command = _desktop_screenshot_command(Path("/home/exnomous/out.png"), "windows", True, 0)

    assert "powershell.exe" in command
    assert "EXNOKALIMCP_SCREENSHOT_OUT" not in command

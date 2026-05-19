"""Health output redaction tests."""

from __future__ import annotations

from tools.shell.terminal_tools import _redacted_server_config


def test_redacted_server_config_hides_api_keys() -> None:
    config = {
        "server": {
            "name": "exnokalimcp",
            "auth": {
                "enabled": True,
                "key_file": "/home/user/.exnokalimcp/auth_key",
                "api_keys": ["secret-one", "secret-two"],
            },
        }
    }

    redacted = _redacted_server_config(config)

    assert redacted["auth"]["api_keys"] == ["***REDACTED***", "***REDACTED***"]
    assert "secret-one" not in str(redacted)
    assert config["server"]["auth"]["api_keys"] == ["secret-one", "secret-two"]

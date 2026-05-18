"""Authentication fallback tests."""

from __future__ import annotations

from server import ExnoKaliMCPServices, load_config


def test_authorize_reads_key_file_when_env_missing(tmp_path, monkeypatch) -> None:
    key = "abc123"
    key_file = tmp_path / "auth_key"
    key_file.write_text(key, encoding="utf-8")
    config = load_config()
    config["server"]["auth"]["api_keys"] = [key]
    config["server"]["auth"]["key_file"] = str(key_file)
    config["paths"]["workspace_dir"] = str(tmp_path / "workspaces")
    config["paths"]["results_db"] = str(tmp_path / "results.db")
    config["paths"]["logs_dir"] = str(tmp_path / "logs")
    config["security"]["scope_file"] = str(tmp_path / "scope.txt")
    monkeypatch.delenv("EXNOKALIMCP_AUTH_KEY", raising=False)
    monkeypatch.delenv("KALI_MCP_AUTH_KEY", raising=False)

    ExnoKaliMCPServices(config).authorize()

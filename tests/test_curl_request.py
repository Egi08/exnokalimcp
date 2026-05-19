"""curl_request command option tests."""

from __future__ import annotations

from tools.network.netcat_tools import _curl_options


def test_curl_options_adds_bounded_timeouts() -> None:
    options = _curl_options("-i -sS", timeout=25)

    assert "-i -sS" in options
    assert "--connect-timeout 10" in options
    assert "--max-time 25" in options


def test_curl_options_respects_user_timeouts() -> None:
    options = _curl_options("-i --connect-timeout 3 --max-time 4", timeout=25)

    assert options.count("--connect-timeout") == 1
    assert options.count("--max-time") == 1
    assert "--connect-timeout 3" in options
    assert "--max-time 4" in options


def test_curl_options_respects_short_max_time() -> None:
    options = _curl_options("-i -m10", timeout=25)

    assert "--connect-timeout 10" in options
    assert "--max-time" not in options
    assert "-m10" in options

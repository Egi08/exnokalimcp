"""Tests for structured output parsers."""

from __future__ import annotations

import json

from tools.parsers import parse_dnsx, parse_ffuf, parse_httpx, parse_nuclei


def test_parse_ffuf_summary() -> None:
    output = json.dumps(
        {
            "results": [
                {"url": "https://example.com/admin", "status": 200, "length": 123, "words": 5, "lines": 1},
                {"url": "https://example.com/login", "status": 403, "length": 99, "words": 4, "lines": 1},
            ]
        }
    )
    parsed = parse_ffuf(output)
    assert parsed["type"] == "ffuf"
    assert parsed["result_count"] == 2
    assert parsed["statuses"]["200"] == 1
    assert parsed["statuses"]["403"] == 1


def test_parse_nuclei_summary() -> None:
    output = json.dumps(
        {
            "template-id": "test-template",
            "info": {"name": "Test", "severity": "high"},
            "host": "https://example.com",
        }
    )
    parsed = parse_nuclei(output)
    assert parsed["type"] == "nuclei"
    assert parsed["finding_count"] == 1
    assert parsed["severities"]["high"] == 1


def test_parse_httpx_summary() -> None:
    output = json.dumps(
        {
            "url": "https://example.com",
            "host": "example.com",
            "status-code": 200,
            "title": "Example",
            "tech": ["nginx"],
        }
    )
    parsed = parse_httpx(output)
    assert parsed["host_count"] == 1
    assert parsed["status_codes"]["200"] == 1
    assert parsed["top_tech"]["nginx"] == 1


def test_parse_dnsx_summary() -> None:
    output = json.dumps({"host": "example.com", "a": ["93.184.216.34"], "mx": ["mail.example.com"]})
    parsed = parse_dnsx(output)
    assert parsed["domain_count"] == 1
    assert parsed["record_counts"]["a"] == 1
    assert parsed["record_counts"]["mx"] == 1


"""Structured parsers for common Kali tool output."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any


def parse_json(output: str) -> dict[str, Any]:
    """Parse a JSON object or return a raw preview on failure."""

    text = output.strip()
    if not text:
        return {"type": "json", "empty": True}
    try:
        value = json.loads(text)
        return {"type": "json", "value": value}
    except json.JSONDecodeError as exc:
        return {"type": "json", "error": str(exc), "preview": text[:2000]}


def parse_jsonl(output: str) -> dict[str, Any]:
    """Parse JSON-lines output with a raw fallback per line."""

    items: list[dict[str, Any]] = []
    errors = 0
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            items.append(item if isinstance(item, dict) else {"value": item})
        except json.JSONDecodeError:
            errors += 1
            items.append({"raw": line})
    return {"type": "jsonl", "count": len(items), "errors": errors, "items": items[:500]}


def parse_ffuf(output: str) -> dict[str, Any]:
    """Summarize ffuf JSON output."""

    parsed = parse_json(output)
    value = parsed.get("value")
    if not isinstance(value, dict):
        return parsed
    results = value.get("results") or []
    statuses = Counter(str(item.get("status")) for item in results if isinstance(item, dict))
    words = Counter(str(item.get("words")) for item in results if isinstance(item, dict))
    findings = []
    for item in results[:200]:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "url": item.get("url"),
                "status": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "input": item.get("input"),
            }
        )
    return {
        "type": "ffuf",
        "result_count": len(results),
        "statuses": dict(statuses),
        "word_counts": dict(words.most_common(10)),
        "findings": findings,
    }


def parse_nuclei(output: str) -> dict[str, Any]:
    """Summarize nuclei JSONL findings."""

    parsed = parse_jsonl(output)
    items = parsed.get("items", [])
    severities = Counter()
    templates = Counter()
    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = str(item.get("severity") or info.get("severity") or "unknown")
        template = str(item.get("template-id") or item.get("template") or "unknown")
        severities[severity] += 1
        templates[template] += 1
        findings.append(
            {
                "template": template,
                "name": info.get("name"),
                "severity": severity,
                "host": item.get("host") or item.get("matched-at"),
                "matcher": item.get("matcher-name"),
                "type": item.get("type"),
            }
        )
    return {
        "type": "nuclei",
        "finding_count": len(findings),
        "severities": dict(severities),
        "top_templates": dict(templates.most_common(20)),
        "findings": findings[:300],
        "jsonl_errors": parsed.get("errors", 0),
    }


def parse_httpx(output: str) -> dict[str, Any]:
    """Summarize httpx JSONL results."""

    parsed = parse_jsonl(output)
    items = parsed.get("items", [])
    status_codes = Counter()
    tech = Counter()
    hosts = []
    for item in items:
        if not isinstance(item, dict):
            continue
        status_codes[str(item.get("status-code", "unknown"))] += 1
        for value in item.get("tech", []) or []:
            tech[str(value)] += 1
        hosts.append(
            {
                "url": item.get("url"),
                "host": item.get("host"),
                "status_code": item.get("status-code"),
                "title": item.get("title"),
                "tech": item.get("tech"),
            }
        )
    return {
        "type": "httpx",
        "host_count": len(hosts),
        "status_codes": dict(status_codes),
        "top_tech": dict(tech.most_common(30)),
        "hosts": hosts[:300],
        "jsonl_errors": parsed.get("errors", 0),
    }


def parse_dnsx(output: str) -> dict[str, Any]:
    """Summarize dnsx JSONL results."""

    parsed = parse_jsonl(output)
    items = parsed.get("items", [])
    record_counts = Counter()
    records = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in ("a", "aaaa", "cname", "mx", "ns", "txt", "soa", "ptr"):
            if item.get(key):
                record_counts[key] += len(item[key]) if isinstance(item[key], list) else 1
        records.append(item)
    return {
        "type": "dnsx",
        "domain_count": len(records),
        "record_counts": dict(record_counts),
        "records": records[:300],
        "jsonl_errors": parsed.get("errors", 0),
    }


def parse_feroxbuster(output: str) -> dict[str, Any]:
    """Summarize feroxbuster JSON output, usually JSONL."""

    parsed = parse_jsonl(output)
    items = parsed.get("items", [])
    statuses = Counter(str(item.get("status")) for item in items if isinstance(item, dict) and item.get("status"))
    urls = [
        {"url": item.get("url"), "status": item.get("status"), "content_length": item.get("content_length")}
        for item in items
        if isinstance(item, dict) and item.get("url")
    ]
    return {"type": "feroxbuster", "result_count": len(urls), "statuses": dict(statuses), "findings": urls[:300]}


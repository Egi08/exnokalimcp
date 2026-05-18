"""Tests for SQLite result storage."""

from __future__ import annotations

from tools.result_store import ResultStore


def test_result_store_roundtrip(tmp_path) -> None:
    store = ResultStore(str(tmp_path / "results.db"))
    result_id = store.add_result(
        workspace="default",
        tool="nmap_scan",
        target="example.com",
        command="nmap example.com",
        exit_code=0,
        output_path="/tmp/out.txt",
        summary={"open_ports": 1},
        metadata={"note": "test"},
    )
    rows = store.list_results(workspace="default", tool="nmap_scan", limit=10)
    assert result_id > 0
    assert len(rows) == 1
    assert rows[0]["summary"]["open_ports"] == 1


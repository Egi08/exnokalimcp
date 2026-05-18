"""SQLite-backed result persistence for ExnoKaliMCP."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _expand(path: str) -> Path:
    return Path(path).expanduser().resolve()


class ResultStore:
    """Persist command results and workspace metadata in SQLite."""

    def __init__(self, db_path: str) -> None:
        self.db_path = _expand(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    workspace TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    target TEXT,
                    command TEXT,
                    exit_code INTEGER,
                    output_path TEXT,
                    summary_json TEXT,
                    metadata_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_results_workspace
                    ON results(workspace, timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_results_tool
                    ON results(tool, timestamp DESC);

                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    user TEXT,
                    status TEXT NOT NULL,
                    params_json TEXT,
                    message TEXT
                );
                """
            )

    def add_result(
        self,
        workspace: str,
        tool: str,
        target: str | None,
        command: str,
        exit_code: int | None,
        output_path: str | None,
        summary: dict[str, Any] | list[Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Insert a result row and return its id."""

        timestamp = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO results (
                    timestamp, workspace, tool, target, command, exit_code,
                    output_path, summary_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    workspace,
                    tool,
                    target,
                    command,
                    exit_code,
                    output_path,
                    json.dumps(summary or {}, ensure_ascii=False, default=str),
                    json.dumps(metadata or {}, ensure_ascii=False, default=str),
                ),
            )
            return int(cur.lastrowid)

    def list_results(
        self,
        workspace: str | None = None,
        tool: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return recent results filtered by workspace and/or tool."""

        clauses: list[str] = []
        args: list[Any] = []
        if workspace:
            clauses.append("workspace = ?")
            args.append(workspace)
        if tool:
            clauses.append("tool = ?")
            args.append(tool)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        query = f"SELECT * FROM results{where} ORDER BY timestamp DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        with self._connect() as conn:
            rows = conn.execute(query, args).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_workspace_results(self, workspace: str) -> dict[str, Any]:
        """Return grouped results for a workspace."""

        rows = self.list_results(workspace=workspace, limit=500)
        by_tool: dict[str, int] = {}
        for row in rows:
            by_tool[row["tool"]] = by_tool.get(row["tool"], 0) + 1
        return {"workspace": workspace, "count": len(rows), "by_tool": by_tool, "results": rows}

    def add_tool_call(
        self,
        tool: str,
        params: dict[str, Any],
        user: str,
        status: str,
        message: str = "",
    ) -> int:
        """Record an auditable tool call row."""

        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO tool_calls (timestamp, tool, user, status, params_json, message)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    tool,
                    user,
                    status,
                    json.dumps(params, ensure_ascii=False, default=str),
                    message,
                ),
            )
            return int(cur.lastrowid)

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        for key in ("summary_json", "metadata_json"):
            try:
                item[key[:-5]] = json.loads(item.pop(key) or "{}")
            except json.JSONDecodeError:
                item[key[:-5]] = {}
        return item

"""SQLite audit repository."""

import json
import sqlite3
from pathlib import Path

from trustaix.models import AuditEvent


class AuditRepository:
    def __init__(self, database_path: str = "trustaix.db") -> None:
        self.database_path = Path(database_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL
                )
                """
            )

    def save(self, event: AuditEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_events(event_id, payload, evaluated_at) VALUES (?, ?, ?)",
                (event.event_id, event.model_dump_json(), event.evaluated_at),
            )

    def latest(self, limit: int = 50) -> list[AuditEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM audit_events ORDER BY evaluated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [AuditEvent.model_validate(json.loads(row[0])) for row in rows]

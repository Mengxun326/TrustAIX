"""SQLite audit repository."""

import json
import sqlite3
from datetime import UTC, datetime

from trustaix.models import AuditEvent, AuditFeedback, FeedbackRequest


class AuditRepository:
    def __init__(self, database_path: str = "trustaix.db") -> None:
        self.database_path = database_path
        self.is_postgres = database_path.startswith(("postgres://", "postgresql://"))
        self._initialize()

    def _connect(self):
        if self.is_postgres:
            try:
                import psycopg
            except ImportError as error:  # pragma: no cover - optional dependency
                raise RuntimeError("Install TrustAIX with the 'postgres' extra to use PostgreSQL.") from error
            return psycopg.connect(self.database_path)
        return sqlite3.connect(self.database_path)

    def _execute(self, connection, query: str, values=()):
        return connection.execute(query.replace("?", "%s") if self.is_postgres else query, values)

    def _initialize(self) -> None:
        with self._connect() as connection:
            self._execute(connection,
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default'
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")} if not self.is_postgres else {"tenant_id"}
            if "tenant_id" not in columns:
                self._execute(connection,
                    "ALTER TABLE audit_events ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'"
                )
            self._execute(connection,
                """
                CREATE TABLE IF NOT EXISTS audit_feedback (
                    event_id TEXT PRIMARY KEY,
                    verdict TEXT NOT NULL,
                    note TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def save(self, event: AuditEvent) -> None:
        with self._connect() as connection:
            self._execute(connection,
                "INSERT INTO audit_events(event_id, payload, evaluated_at, tenant_id) VALUES (?, ?, ?, ?)",
                (event.event_id, event.model_dump_json(), event.evaluated_at, event.tenant_id),
            )

    def latest(self, limit: int = 50, tenant_id: str = "default") -> list[AuditEvent]:
        with self._connect() as connection:
            rows = self._execute(connection,
                "SELECT payload FROM audit_events WHERE tenant_id = ? ORDER BY evaluated_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        events = [AuditEvent.model_validate(row[0] if isinstance(row[0], dict) else json.loads(row[0])) for row in rows]
        feedback = self._feedback_for([event.event_id for event in events])
        return [event.model_copy(update={"feedback": feedback.get(event.event_id)}) for event in events]

    def add_feedback(
        self, event_id: str, feedback: FeedbackRequest, tenant_id: str = "default"
    ) -> AuditFeedback | None:
        with self._connect() as connection:
            exists = self._execute(connection,
                "SELECT 1 FROM audit_events WHERE event_id = ? AND tenant_id = ?", (event_id, tenant_id)
            ).fetchone()
            if not exists:
                return None
            updated_at = datetime.now(UTC).isoformat()
            self._execute(connection,
                """
                INSERT INTO audit_feedback(event_id, verdict, note, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                  verdict = excluded.verdict,
                  note = excluded.note,
                  updated_at = excluded.updated_at
                """,
                (event_id, feedback.verdict.value, feedback.note, updated_at),
            )
        return AuditFeedback(event_id=event_id, updated_at=updated_at, **feedback.model_dump())

    def analytics(self, limit: int = 1_000, tenant_id: str = "default") -> dict[str, object]:
        events = self.latest(limit, tenant_id=tenant_id)
        actions = {action: 0 for action in ("allow", "review", "redact", "block")}
        categories: dict[str, int] = {}
        false_positives = 0
        for event in events:
            actions[event.action.value] += 1
            for finding in event.findings:
                categories[finding.category] = categories.get(finding.category, 0) + 1
            if event.feedback and event.feedback.verdict.value == "false_positive":
                false_positives += 1
        return {
            "evaluations": len(events),
            "actions": actions,
            "categories": categories,
            "false_positives": false_positives,
        }

    def purge_before(self, before: datetime, tenant_id: str | None = None) -> int:
        """Delete expired audit records; callers must enforce an admin retention policy."""
        query = "DELETE FROM audit_events WHERE evaluated_at < ?"
        values: list[str] = [before.astimezone(UTC).isoformat()]
        if tenant_id is not None:
            query += " AND tenant_id = ?"
            values.append(tenant_id)
        with self._connect() as connection:
            return self._execute(connection, query, values).rowcount

    def _feedback_for(self, event_ids: list[str]) -> dict[str, AuditFeedback]:
        if not event_ids:
            return {}
        placeholders = ",".join("%s" if self.is_postgres else "?" for _ in event_ids)
        with self._connect() as connection:
            rows = self._execute(connection,
                f"SELECT event_id, verdict, note, updated_at FROM audit_feedback WHERE event_id IN ({placeholders})",
                event_ids,
            ).fetchall()
        return {
            event_id: AuditFeedback(
                event_id=event_id, verdict=verdict, note=note, updated_at=updated_at
            )
            for event_id, verdict, note, updated_at in rows
        }

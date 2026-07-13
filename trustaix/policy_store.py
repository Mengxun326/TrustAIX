"""Versioned, tenant-scoped policy storage and approval workflow."""

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from trustaix.config import PolicyProfile, policy_document, policy_from_document


@dataclass(frozen=True)
class PolicyVersion:
    id: str
    tenant_id: str
    document: dict[str, object]
    status: str
    created_by: str
    created_at: str
    note: str
    parent_id: str | None
    approved_by: str | None
    approved_at: str | None

    def public_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "status": self.status,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "note": self.note,
            "parent_id": self.parent_id,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "document": self.document,
            "policy": policy_from_document(self.document).public_dict(),
        }


class PolicyVersionRepository:
    def __init__(self, database_path: str) -> None:
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
                CREATE TABLE IF NOT EXISTS policy_versions (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    document TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    note TEXT NOT NULL,
                    parent_id TEXT,
                    approved_by TEXT,
                    approved_at TEXT
                )
                """
            )

    def ensure_active(self, tenant_id: str, profile: PolicyProfile, actor_id: str) -> PolicyVersion:
        active = self.active(tenant_id)
        return active or self._insert(tenant_id, policy_document(profile), "active", actor_id, "Initial policy", None, actor_id)

    def create_draft(
        self, tenant_id: str, document: dict[str, object], actor_id: str, note: str, parent_id: str | None = None
    ) -> PolicyVersion:
        validated = policy_from_document(document)
        return self._insert(tenant_id, policy_document(validated), "draft", actor_id, note, parent_id, None)

    def submit(self, version_id: str, tenant_id: str) -> PolicyVersion | None:
        return self._transition(version_id, tenant_id, "draft", "pending")

    def approve(self, version_id: str, tenant_id: str, approver_id: str) -> PolicyVersion | None:
        version = self.get(version_id, tenant_id)
        if version is None:
            return None
        if version.status != "pending":
            raise ValueError("Only a pending policy version can be approved.")
        if version.created_by == approver_id and approver_id != "local-development":
            raise ValueError("A policy author cannot approve their own version.")
        approved_at = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            self._execute(connection,
                "UPDATE policy_versions SET status = 'superseded' WHERE tenant_id = ? AND status = 'active'",
                (tenant_id,),
            )
            self._execute(connection,
                "UPDATE policy_versions SET status = 'active', approved_by = ?, approved_at = ? WHERE id = ?",
                (approver_id, approved_at, version_id),
            )
        return self.get(version_id, tenant_id)

    def rollback_draft(self, version_id: str, tenant_id: str, actor_id: str) -> PolicyVersion | None:
        version = self.get(version_id, tenant_id)
        if version is None:
            return None
        return self.create_draft(tenant_id, version.document, actor_id, f"Rollback draft from {version.id}", version.id)

    def active(self, tenant_id: str) -> PolicyVersion | None:
        with self._connect() as connection:
            row = self._execute(connection,
                "SELECT * FROM policy_versions WHERE tenant_id = ? AND status = 'active' ORDER BY approved_at DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
        return self._row(row) if row else None

    def get(self, version_id: str, tenant_id: str) -> PolicyVersion | None:
        with self._connect() as connection:
            row = self._execute(connection,
                "SELECT * FROM policy_versions WHERE id = ? AND tenant_id = ?", (version_id, tenant_id)
            ).fetchone()
        return self._row(row) if row else None

    def list(self, tenant_id: str, limit: int = 50) -> list[PolicyVersion]:
        with self._connect() as connection:
            rows = self._execute(connection,
                "SELECT * FROM policy_versions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [self._row(row) for row in rows]

    def _transition(self, version_id: str, tenant_id: str, current: str, new: str) -> PolicyVersion | None:
        with self._connect() as connection:
            updated = self._execute(connection,
                "UPDATE policy_versions SET status = ? WHERE id = ? AND tenant_id = ? AND status = ?",
                (new, version_id, tenant_id, current),
            ).rowcount
        return self.get(version_id, tenant_id) if updated else None

    def _insert(
        self, tenant_id: str, document: dict[str, object], status: str, actor_id: str, note: str, parent_id: str | None, approver_id: str | None
    ) -> PolicyVersion:
        version = PolicyVersion(
            id=str(uuid4()), tenant_id=tenant_id, document=document, status=status, created_by=actor_id,
            created_at=datetime.now(UTC).isoformat(), note=note, parent_id=parent_id,
            approved_by=approver_id, approved_at=datetime.now(UTC).isoformat() if approver_id else None,
        )
        with self._connect() as connection:
            self._execute(connection,
                "INSERT INTO policy_versions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (version.id, version.tenant_id, json.dumps(version.document), version.status, version.created_by,
                 version.created_at, version.note, version.parent_id, version.approved_by, version.approved_at),
            )
        return version

    @staticmethod
    def _row(row: tuple) -> PolicyVersion:
        return PolicyVersion(
            id=row[0], tenant_id=row[1], document=row[2] if isinstance(row[2], dict) else json.loads(row[2]), status=row[3], created_by=row[4],
            created_at=row[5], note=row[6], parent_id=row[7], approved_by=row[8], approved_at=row[9],
        )

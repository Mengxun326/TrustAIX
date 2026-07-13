from datetime import UTC, datetime, timedelta

from trustaix.audit import AuditRepository
from trustaix.auth import AuthService, Principal, Role
from trustaix.models import Action, AuditEvent


def test_auth_service_keeps_token_digests_and_accepts_rotated_keys() -> None:
    auth = AuthService(
        True,
        {
            "old-key": Principal("operator", "tenant", Role.ADMIN),
            "new-key": Principal("operator", "tenant", Role.ADMIN),
        },
    )
    assert "old-key" not in auth.credentials
    assert auth.authenticate("new-key").key_id == "operator"


def test_audit_retention_deletes_only_expired_tenant_records(tmp_path) -> None:
    repository = AuditRepository(str(tmp_path / "audit.db"))
    event = AuditEvent(
        event_id="old", request_id=None, action=Action.ALLOW, risk_score=0, findings=[],
        evaluated_at=(datetime.now(UTC) - timedelta(days=30)).isoformat(),
        prompt_length=1, response_length=0, tenant_id="a",
    )
    repository.save(event)
    assert repository.purge_before(datetime.now(UTC) - timedelta(days=1), tenant_id="a") == 1

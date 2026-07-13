import pytest

from trustaix.config import DEFAULT_POLICY, policy_document
from trustaix.policy_store import PolicyVersionRepository


def test_policy_requires_independent_approval_and_supports_rollback(tmp_path) -> None:
    repository = PolicyVersionRepository(str(tmp_path / "policies.db"))
    active = repository.ensure_active("tenant-a", DEFAULT_POLICY, "bootstrap")
    draft = repository.create_draft(
        "tenant-a", policy_document(DEFAULT_POLICY), "author", "Tighten review threshold", active.id
    )
    assert repository.submit(draft.id, "tenant-a").status == "pending"
    with pytest.raises(ValueError, match="cannot approve"):
        repository.approve(draft.id, "tenant-a", "author")

    approved = repository.approve(draft.id, "tenant-a", "approver")
    assert approved.status == "active"
    assert repository.active("tenant-a").id == draft.id
    assert approved.public_dict()["document"] == policy_document(DEFAULT_POLICY)
    rollback = repository.rollback_draft(active.id, "tenant-a", "operator")
    assert rollback.status == "draft"
    assert rollback.parent_id == active.id

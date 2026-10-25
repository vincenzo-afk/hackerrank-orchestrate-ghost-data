"""Identity history must not use changes after the case audit time."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import Datasets, UserIdentity, _parse_iso, resolve_identity


def _identity(user_id, email, updated_at, hash_value="hash"):
    return UserIdentity(
        user_id=user_id,
        name=f"Person {user_id}",
        current_email=email,
        phone="",
        email_hash=hash_value,
        updated_at=_parse_iso(updated_at),
    )


def _row(user_id, when, old, new, field="email"):
    return {
        "audit_id": f"a_{user_id}_{when}_{old}",
        "user_id": user_id,
        "event_time": when,
        "field_name": field,
        "old_value": old,
        "new_value": new,
    }


def _datasets(identities, audit_rows):
    email_map = {i.current_email.lower(): i.user_id for i in identities.values()}
    return Datasets(
        deletion_requests=[],
        sample_requests=[],
        identities=identities,
        email_to_user_id=email_map,
        audit_log=audit_rows,
        historical_emails={},
        historical_email_hashes={},
        historical_phones={},
        system_activity=[],
        deletion_rules=[],
        evidence_files=[],
        policy=None,
    )


def test_pre_audit_alias_is_resolved_and_retained():
    identity = _identity("user_a", "new@example.com", "2026-05-20T00:00:00Z")
    rows = [
        _row("user_a", "2026-05-01T00:00:00Z", "old@example.com", "mid@example.com"),
        _row("user_a", "2026-05-10T00:00:00Z", "mid@example.com", "new@example.com"),
    ]
    datasets = _datasets({"user_a": identity}, rows)
    result = resolve_identity(
        "old@example.com", datasets, as_of=_parse_iso("2026-06-01T00:00:00Z")
    )
    assert result.status == "found"
    assert result.fingerprint.user_id == "user_a"
    assert "old@example.com" in result.fingerprint.all_emails
    assert "mid@example.com" in result.fingerprint.all_emails


def test_pre_audit_new_value_alias_is_resolved():
    identity = _identity("user_a", "new@example.com", "2026-05-20T00:00:00Z")
    rows = [
        _row("user_a", "2026-05-01T00:00:00Z", "old@example.com", "mid@example.com"),
        _row("user_a", "2026-05-10T00:00:00Z", "mid@example.com", "new@example.com"),
    ]
    datasets = _datasets({"user_a": identity}, rows)
    result = resolve_identity(
        "mid@example.com", datasets, as_of=_parse_iso("2026-06-01T00:00:00Z")
    )
    assert result.status == "found"
    assert result.fingerprint.user_id == "user_a"


def test_alias_introduced_after_audit_is_not_used():
    identity = _identity("user_a", "future@example.com", "2026-07-02T00:00:00Z")
    rows = [
        _row("user_a", "2026-07-01T00:00:00Z", "old2@example.com", "future@example.com"),
    ]
    datasets = _datasets({"user_a": identity}, rows)
    result = resolve_identity(
        "old2@example.com", datasets, as_of=_parse_iso("2026-06-01T00:00:00Z")
    )
    assert result.status == "not_found"


def test_snapshot_updated_after_audit_is_not_used_as_current():
    identity = _identity("user_a", "future@example.com", "2026-07-02T00:00:00Z")
    datasets = _datasets(
        {"user_a": identity},
        [_row("user_a", "2026-07-01T00:00:00Z", "old@example.com", "future@example.com")],
    )
    result = resolve_identity(
        "future@example.com", datasets, as_of=_parse_iso("2026-06-01T00:00:00Z")
    )
    assert result.status == "not_found"


def test_later_contradictory_link_does_not_create_ambiguity():
    user_a = _identity("user_a", "new_a@example.com", "2026-05-20T00:00:00Z")
    user_b = _identity("user_b", "new_b@example.com", "2026-07-20T00:00:00Z")
    rows = [
        _row("user_a", "2026-05-01T00:00:00Z", "shared@example.com", "new_a@example.com"),
        _row("user_b", "2026-07-01T00:00:00Z", "shared@example.com", "new_b@example.com"),
    ]
    datasets = _datasets({"user_a": user_a, "user_b": user_b}, rows)
    result = resolve_identity(
        "shared@example.com", datasets, as_of=_parse_iso("2026-06-01T00:00:00Z")
    )
    assert result.status == "found"
    assert result.fingerprint.user_id == "user_a"

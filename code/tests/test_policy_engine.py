"""Regression coverage for the supplied deletion-rule conditions."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from evidence_parser import EvidenceCorpus, ObservedRecord, _parse_iso
from policy_engine import PolicyEngine, PolicyRule
from state_reconstruction import reconstruct_case_state

IDS = {"user_test", "subject@example.com"}
AUDIT_AT = _parse_iso("2026-06-10T00:00:00Z")


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine.from_csv(REPO_ROOT / "dataset" / "deletion_rules.csv")


def record(category, state="PRESENT", details=None, identifiers=None):
    return ObservedRecord(
        evidence_id="evidence_synthetic",
        file_path=Path("synthetic"),
        captured_at=_parse_iso("2026-06-05T10:00:00Z"),
        origin="synthetic",
        system_id="account_service",
        resource_id="resource_test",
        data_category=category,
        state=state,
        has_exposed_pii=state == "PRESENT",
        identifiers=set(IDS if identifiers is None else identifiers),
        details=details or {},
    )


def decide(engine, category, state="PRESENT", details=None, identifiers=None):
    return engine.decide(
        record(category, state, details, identifiers),
        AUDIT_AT,
        IDS,
    )


def test_all_supplied_rules_load_and_actions_are_valid(engine):
    assert len(engine.rules) == 15
    assert {rule.required_action for rule in engine.rules} <= {
        "DELETE", "REDACT", "ANONYMIZE", "RETAIN"
    }
    for rule in engine.rules:
        assert engine.rules_for(rule.data_category)


def test_always_rules(engine):
    expected = {
        "USER_PROFILE": "DELETE",
        "SECONDARY_IDENTIFIER": "DELETE",
        "SEARCH_INDEX_ENTRY": "DELETE",
        "CACHE_ENTRY": "DELETE",
        "USER_EXPORT": "DELETE",
        "MARKETING_PROFILE": "DELETE",
    }
    for category, action in expected.items():
        decision = decide(engine, category)
        assert decision.action == action
        assert decision.condition_value is True


def test_support_message_shared_condition_true_false_unknown(engine):
    true = decide(engine, "SUPPORT_MESSAGE", details={"shared_context": True})
    false = decide(engine, "SUPPORT_MESSAGE", details={"shared_context": False})
    unknown = decide(engine, "SUPPORT_MESSAGE", details={})
    assert (true.action, true.condition_value) == ("REDACT", True)
    assert (false.action, false.condition_value) == ("", False)
    assert (unknown.action, unknown.condition_value) == ("REDACT", None)


def test_support_attachment_belongs_only_condition(engine):
    explicit = decide(
        engine, "SUPPORT_ATTACHMENT", details={"belongs_only_to_subject": True}
    )
    shared = decide(engine, "SUPPORT_ATTACHMENT", details={"shared_context": True})
    subject_ids = decide(
        engine,
        "SUPPORT_ATTACHMENT",
        details={},
        identifiers={"subject@example.com", "user_test"},
    )
    other_ids = decide(
        engine,
        "SUPPORT_ATTACHMENT",
        details={},
        identifiers={"subject@example.com", "other@example.com"},
    )
    assert (explicit.action, explicit.condition_value) == ("DELETE", True)
    assert (shared.action, shared.condition_value) == ("", False)
    assert (subject_ids.action, subject_ids.condition_value) == ("DELETE", True)
    assert (other_ids.action, other_ids.condition_value) == ("", False)


def test_analytics_attributable_condition(engine):
    present = decide(engine, "ANALYTICS_PROFILE", state="PRESENT")
    anonymous = decide(engine, "ANALYTICS_PROFILE", state="ANONYMIZED", identifiers=set())
    assert (present.action, present.condition_value) == ("ANONYMIZE", True)
    assert (anonymous.action, anonymous.condition_value) == ("ANONYMIZE", False)


def test_email_delivery_log_condition(engine):
    contains = decide(engine, "EMAIL_DELIVERY_LOG", details={"email": "subject@example.com"})
    empty = decide(engine, "EMAIL_DELIVERY_LOG", details={"email": ""})
    unknown = decide(engine, "EMAIL_DELIVERY_LOG", details={})
    assert (contains.action, contains.condition_value) == ("REDACT", True)
    assert (empty.action, empty.condition_value) == ("REDACT", False)
    assert (unknown.action, unknown.condition_value) == ("REDACT", None)


def test_audit_retention_condition(engine):
    active = decide(
        engine, "SECURITY_AUDIT_LOG", details={"retention_until": "2030-01-01T00:00:00Z"}
    )
    expired = decide(
        engine, "SECURITY_AUDIT_LOG", details={"retention_until": "2026-05-01T00:00:00Z"}
    )
    unknown = decide(engine, "SECURITY_AUDIT_LOG", details={})
    assert (active.action, active.condition_value) == ("RETAIN", True)
    assert (expired.action, expired.condition_value) == ("", False)
    assert (unknown.action, unknown.condition_value) == ("RETAIN", None)


def test_legal_hold_condition(engine):
    active = decide(
        engine, "LEGAL_HOLD_RECORD", details={"retained_until": "2033-01-01T00:00:00Z"}
    )
    expired = decide(
        engine, "LEGAL_HOLD_RECORD", details={"retained_until": "2026-05-01T00:00:00Z"}
    )
    unknown = decide(engine, "LEGAL_HOLD_RECORD", details={})
    assert (active.action, active.condition_value) == ("RETAIN", True)
    assert (expired.action, expired.condition_value) == ("", False)
    assert (unknown.action, unknown.condition_value) == ("RETAIN", None)


def test_backup_restore_condition(engine):
    blocked = decide(engine, "BACKUP_ARCHIVE", state="BLOCKED", details={"restore_allowed": False})
    active = decide(engine, "BACKUP_ARCHIVE", state="ACTIVE", details={"restore_allowed": True})
    unknown = decide(engine, "BACKUP_ARCHIVE", state="BLOCKED", details={})
    assert (blocked.action, blocked.condition_value) == ("RETAIN", True)
    assert (active.action, active.condition_value) == ("RETAIN", False)
    assert (unknown.action, unknown.condition_value) == ("RETAIN", True)


def test_tombstone_condition(engine):
    deleted = decide(engine, "ACCOUNT_TOMBSTONE", details={"account_status": "DELETED"})
    live = decide(engine, "ACCOUNT_TOMBSTONE", details={"account_status": "ACTIVE"})
    unknown = decide(engine, "ACCOUNT_TOMBSTONE", details={})
    assert (deleted.action, deleted.condition_value) == ("REDACT", True)
    assert (live.action, live.condition_value) == ("", False)
    assert (unknown.action, unknown.condition_value) == ("REDACT", None)


def test_false_conditional_decision_fails_closed_in_reconstruction():
    engine = PolicyEngine.from_csv(REPO_ROOT / "dataset" / "deletion_rules.csv")
    subject_only = record(
        "SUPPORT_MESSAGE", details={"shared_context": False}
    )
    result = reconstruct_case_state(
        case_id="false_policy",
        audit_at=AUDIT_AT,
        is_deletion=True,
        user_identifiers=IDS,
        corpus=EvidenceCorpus([subject_only]),
        require_evidence=True,
        policy_engine=engine,
    )
    assert result.deletion_status == "INCOMPLETE"
    assert result.steps == []


def test_unsupported_condition_fails_closed():
    bad_engine = PolicyEngine(
        [PolicyRule("bad_rule", "USER_PROFILE", "A condition we cannot interpret", "DELETE")]
    )
    decision = bad_engine.decide(record("USER_PROFILE"), AUDIT_AT, IDS)
    assert decision.supported is False
    assert decision.action == ""
    result = reconstruct_case_state(
        case_id="bad_policy",
        audit_at=AUDIT_AT,
        is_deletion=True,
        user_identifiers=IDS,
        corpus=EvidenceCorpus([record("USER_PROFILE")]),
        require_evidence=True,
        policy_engine=bad_engine,
    )
    assert result.deletion_status == "INCOMPLETE"
    assert result.steps == []

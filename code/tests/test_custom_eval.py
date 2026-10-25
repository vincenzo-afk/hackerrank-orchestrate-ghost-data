"""Participant-created evaluation cases (CE-1 .. CE-4).

These cases are not part of the public sample set. They encode the failure
modes found while building the agent, so a regression fails the suite:

  CE-1  Intent: negation / marketing opt-out / multilingual deletion.
  CE-2  Time:   evidence after audit_at must not change the verdict.
  CE-3  Policy: backup restore risk precedes remediation and verification.
  CE-4  Policy: exposed tombstone PII is redacted; a clean tombstone verifies.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import classify_request
from evidence_parser import EvidenceCorpus, ObservedRecord, _parse_iso
from state_reconstruction import reconstruct_case_state

IDS = {"alex@example.com", "user_900"}


def record(system_id, resource_id, category, state, when, evidence_id, pii=False):
    return ObservedRecord(
        evidence_id=evidence_id,
        file_path=Path("synthetic"),
        captured_at=_parse_iso(when),
        origin="synthetic",
        system_id=system_id,
        resource_id=resource_id,
        data_category=category,
        state=state,
        has_exposed_pii=pii,
        identifiers=set(IDS),
        details={},
    )


def audit(records, audit_at, requested_at="2026-06-01T00:00:00Z", system_activity=None):
    return reconstruct_case_state(
        case_id="ce_case",
        audit_at=_parse_iso(audit_at),
        is_deletion=True,
        user_identifiers=IDS,
        corpus=EvidenceCorpus(records),
        system_activity=system_activity,
        require_evidence=True,
        not_before=_parse_iso(requested_at),
    )


class TestCE1Intent:
    def test_negated_and_marketing_requests_are_not_deletion(self):
        texts = [
            "Please stop the promotional emails. I still need the account, so I am not asking for deletion.",
            "Can you correct my surname without removing any of my records?",
            "Please remove me from marketing lists only. I still want receipts.",
            "Could you send me a copy of the information held on my account? Please don't delete anything.",
        ]
        assert [classify_request(t)["is_deletion"] for t in texts] == [False] * 4

    def test_korean_deletion_request_is_detected(self):
        text = (
            "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다. "
            "개인정보 처리 절차에 따라 현재 및 이전 식별자를 검토해 주세요."
        )
        assert classify_request(text)["is_deletion"] is True

    def test_explicit_deletion_still_wins(self):
        text = "Please delete my account and also unsubscribe me from emails."
        assert classify_request(text)["is_deletion"] is True


class TestCE2TemporalIsolation:
    def test_later_evidence_cannot_complete_an_open_case(self):
        """PRESENT at audit_at and ABSENT afterwards: later evidence is ignored."""
        corpus = [
            record("account_service", "account_900", "USER_PROFILE", "PRESENT",
                   "2026-06-05T10:00:00Z", "evidence_a"),
            record("account_service", "account_900", "USER_PROFILE", "ABSENT",
                   "2026-06-20T10:00:00Z", "evidence_b"),
        ]
        result = audit(corpus, audit_at="2026-06-10T00:00:00Z")
        assert result.deletion_status == "INCOMPLETE"
        findings = [s for s in result.steps if s.phase == "FINDING"]
        assert [(s.resource_id, s.evidence_id) for s in findings] == [
            ("account_900", "evidence_a")
        ]

    def test_evidence_before_request_is_not_admissible(self):
        """Only a pre-request PRESENT record leaves the case unproven."""
        corpus = [
            record("account_service", "account_900", "USER_PROFILE", "PRESENT",
                   "2026-05-01T10:00:00Z", "evidence_old"),
        ]
        result = audit(corpus, audit_at="2026-06-10T00:00:00Z")
        assert result.deletion_status == "INCOMPLETE"
        assert result.steps == []

    def test_same_state_uses_earliest_confirming_citation(self):
        first = record(
            "account_service", "account_900", "USER_PROFILE", "ABSENT",
            "2026-06-05T10:00:00Z", "evidence_first",
        )
        later = record(
            "account_service", "account_900", "USER_PROFILE", "ABSENT",
            "2026-06-06T10:00:00Z", "evidence_later",
        )
        result = audit([first, later], audit_at="2026-06-10T00:00:00Z")
        assert [(s.state, s.evidence_id) for s in result.steps] == [
            ("ABSENT", "evidence_first")
        ]

    def test_identified_resource_links_later_anonymous_readback(self):
        identified = record(
            "account_service", "account_900", "USER_PROFILE", "PRESENT",
            "2026-05-01T10:00:00Z", "evidence_old",
        )
        readback = record(
            "account_service", "account_900", "USER_PROFILE", "ABSENT",
            "2026-06-05T10:00:00Z", "evidence_new",
        )
        readback.identifiers = set()
        readback.normalized_identifiers = set()
        result = audit([identified, readback], audit_at="2026-06-10T00:00:00Z")
        assert result.deletion_status == "COMPLETE"
        assert [(s.resource_id, s.evidence_id) for s in result.steps] == [
            ("account_900", "evidence_new")
        ]

    def test_post_cutoff_record_cannot_establish_resource_identity(self):
        readback = record(
            "account_service", "account_900", "USER_PROFILE", "ABSENT",
            "2026-06-05T10:00:00Z", "evidence_new",
        )
        readback.identifiers = set()
        readback.normalized_identifiers = set()
        later_identity = record(
            "account_service", "account_900", "USER_PROFILE", "PRESENT",
            "2026-06-20T10:00:00Z", "evidence_later",
        )
        result = audit([readback, later_identity], audit_at="2026-06-10T00:00:00Z")
        assert result.deletion_status == "INCOMPLETE"
        assert result.steps == []


class TestCE3RestorePolicy:
    def test_restore_risk_is_blocked_before_verification(self):
        corpus = [
            record("account_service", "account_900", "USER_PROFILE", "ABSENT",
                   "2026-06-05T10:00:00Z", "evidence_a"),
            record("security_service", "audit_record_9", "SECURITY_AUDIT_LOG", "PRESENT",
                   "2026-06-05T10:00:00Z", "evidence_a"),
            record("backup_service", "backup_9", "BACKUP_ARCHIVE", "ACTIVE",
                   "2026-06-05T10:00:00Z", "evidence_a"),
        ]
        result = audit(corpus, audit_at="2026-06-10T00:00:00Z")
        assert result.deletion_status == "INCOMPLETE"
        ordered = [(s.phase, s.resource_id, s.operation, s.evidence_id) for s in result.steps]
        assert ordered == [
            ("FINDING", "backup_9", "REPORT_RESTORE_RISK", "evidence_a"),
            ("REMEDIATION", "backup_9", "BLOCK_RESTORE", ""),
            ("VERIFICATION", "account_900", "VERIFY_RECORD_ABSENT", ""),
            ("VERIFICATION", "audit_record_9", "VERIFY_RECORD_PRESENT", ""),
            ("VERIFICATION", "backup_9", "VERIFY_RESTORE_BLOCKED", ""),
        ]


class TestCE4TombstonePolicy:
    def test_exposed_tombstone_requires_redaction(self):
        corpus = [
            record("identity_service", "tombstone_9", "ACCOUNT_TOMBSTONE", "PRESENT",
                   "2026-06-05T10:00:00Z", "evidence_c", pii=True),
        ]
        result = audit(corpus, audit_at="2026-06-10T00:00:00Z")
        assert result.deletion_status == "INCOMPLETE"
        assert [s.operation for s in result.steps] == [
            "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"
        ]

    def test_clean_tombstone_is_complete(self):
        corpus = [
            record("identity_service", "tombstone_9", "ACCOUNT_TOMBSTONE", "REDACTED",
                   "2026-06-05T10:00:00Z", "evidence_c"),
        ]
        result = audit(corpus, audit_at="2026-06-10T00:00:00Z")
        assert result.deletion_status == "COMPLETE"
        assert [(s.operation, s.evidence_id) for s in result.steps] == [
            ("VERIFY_RECORD_REDACTED", "evidence_c")
        ]


class TestCE5ResourceLinks:
    def test_activity_linked_account_adds_future_verification_not_proof(self):
        from activity_linker import ResourceLink

        search = record(
            "search_service", "search_900", "SEARCH_INDEX_ENTRY", "PRESENT",
            "2026-06-05T10:00:00Z", "evidence_search", pii=True,
        )
        result = reconstruct_case_state(
            case_id="ce_case",
            audit_at=_parse_iso("2026-06-10T00:00:00Z"),
            is_deletion=True,
            user_identifiers=IDS,
            corpus=EvidenceCorpus([search]),
            require_evidence=True,
            not_before=_parse_iso("2026-06-01T00:00:00Z"),
            links=[ResourceLink("account_service", "account_900", "USER_PROFILE", "activity", "activity_test")],
        )
        linked = next(s for s in result.steps if s.resource_id == "account_900")
        assert result.deletion_status == "INCOMPLETE"
        assert (linked.phase, linked.operation, linked.state, linked.evidence_id) == (
            "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", ""
        )

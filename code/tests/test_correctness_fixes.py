"""Regression coverage for the Phase 1 correctness fixes.

These tests use synthetic evidence only.  They encode the contract, not any
public-sample labels.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from evidence_parser import (
    EvidenceCorpus,
    EvidenceParseError,
    ObservedRecord,
    _category_for,
    _parse_iso,
    _parse_json_evidence,
    _parse_log_evidence,
    _parse_sql_evidence,
    _state_for_record,
    load_evidence_corpus,
)
from policy_engine import PolicyEngine
from state_reconstruction import (
    _records_from_activity_links,
    reconstruct_case_state,
)

IDS = {"user_test", "subject@example.com"}
AUDIT_AT = _parse_iso("2026-06-10T00:00:00Z")
REQUESTED_AT = _parse_iso("2026-06-01T00:00:00Z")
CAPTURED_AT = _parse_iso("2026-06-05T00:00:00Z")


def record(
    category: str,
    *,
    state: str = "PRESENT",
    resource_id: str = "resource_test",
    system_id: str = "synthetic",
    evidence_id: str = "evidence_synthetic",
    details: dict | None = None,
    identifiers: set[str] | None = None,
    captured_at=None,
) -> ObservedRecord:
    return ObservedRecord(
        evidence_id=evidence_id,
        file_path=Path("synthetic"),
        captured_at=captured_at or CAPTURED_AT,
        origin="synthetic",
        system_id=system_id,
        resource_id=resource_id,
        data_category=category,
        state=state,
        has_exposed_pii=state == "PRESENT",
        identifiers=set(IDS if identifiers is None else identifiers),
        details=details or {},
    )


def audit(records, *, activity=None, require_account_closure=True):
    return reconstruct_case_state(
        case_id="synthetic_case",
        audit_at=AUDIT_AT,
        is_deletion=True,
        user_identifiers=IDS,
        corpus=EvidenceCorpus(records),
        system_activity=activity,
        require_evidence=True,
        not_before=REQUESTED_AT,
        require_account_closure=require_account_closure,
    )


def account_closed():
    return record(
        "USER_PROFILE", state="ABSENT", resource_id="account_900",
        system_id="account_service", evidence_id="evidence_account",
    )


class TestCompletenessGate:
    def test_audit_only_cannot_complete(self):
        result = audit([
            record("SECURITY_AUDIT_LOG", resource_id="audit_900", system_id="security_service"),
        ])
        assert result.deletion_status == "INCOMPLETE"
        assert any("account closure" in gap for gap in result.evidence_gaps)

    def test_account_closure_plus_audit_is_complete(self):
        result = audit([
            account_closed(),
            record("SECURITY_AUDIT_LOG", resource_id="audit_900", system_id="security_service"),
        ])
        assert result.deletion_status == "COMPLETE"
        assert all(step.phase == "VERIFICATION" for step in result.steps)
        assert {step.operation for step in result.steps} == {
            "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT",
        }

    def test_clean_tombstone_closes_the_account(self):
        result = audit([
            record("ACCOUNT_TOMBSTONE", state="REDACTED", resource_id="tombstone_900",
                   system_id="identity_service"),
        ])
        assert result.deletion_status == "COMPLETE"
        assert [(s.operation, s.state) for s in result.steps] == [
            ("VERIFY_RECORD_REDACTED", "REDACTED")
        ]

    def test_unknown_category_prevents_complete(self):
        result = audit([
            account_closed(),
            record("UNAPPROVED_CATEGORY", resource_id="unknown_900"),
        ])
        assert result.deletion_status == "INCOMPLETE"
        assert any("no supplied policy rule" in gap for gap in result.evidence_gaps)
        assert not any(s.resource_id == "unknown_900" for s in result.steps)

    def test_evidence_supported_resource_without_action_is_not_complete(self):
        # A pre-request identified observation establishes the resource, while
        # the in-window record itself has no owner evidence.  The in-window
        # record must be processed and fail closed, not disappear.
        anchor = record(
            "SUPPORT_ATTACHMENT", resource_id="attachment_900",
            system_id="support_platform", details={"shared_context": False},
            captured_at=_parse_iso("2026-05-20T00:00:00Z"),
        )
        anonymous = record(
            "SUPPORT_ATTACHMENT", resource_id="attachment_900",
            system_id="support_platform", details={}, identifiers=set(),
        )
        result = audit([account_closed(), anchor, anonymous])
        assert result.deletion_status == "INCOMPLETE"
        assert any("policy gap" in gap for gap in result.evidence_gaps)
        assert not any(s.resource_id == "attachment_900" for s in result.steps)


class TestSupportCategoryDeduplication:
    def test_message_and_attachment_both_receive_actions(self):
        message = record(
            "SUPPORT_MESSAGE", resource_id="support_900",
            system_id="support_platform", evidence_id="evidence_message",
            details={"shared_context": True},
        )
        attachment = record(
            "SUPPORT_ATTACHMENT", resource_id="support_900",
            system_id="support_platform", evidence_id="evidence_attachment",
            details={"belongs_only_to_subject": True},
        )
        result = audit([account_closed(), message, attachment])
        assert result.deletion_status == "INCOMPLETE"
        steps = [
            (s.phase, s.operation, s.resource_id, s.evidence_id)
            for s in result.steps
            if s.resource_id == "support_900"
        ]
        assert steps == [
            ("FINDING", "REPORT_REMAINING_RECORD", "support_900", "evidence_attachment"),
            ("FINDING", "REPORT_EXPOSED_PII", "support_900", "evidence_message"),
            ("REMEDIATION", "DELETE_RECORD", "support_900", ""),
            ("REMEDIATION", "REDACT_RECORD", "support_900", ""),
            ("VERIFICATION", "VERIFY_RECORD_ABSENT", "support_900", ""),
            ("VERIFICATION", "VERIFY_RECORD_REDACTED", "support_900", ""),
        ]


class TestActivityLinkValidation:
    def _link(self, resource_id="search_900", when="2026-06-05T00:00:00Z", details="linked subject@example.com and user_test"):
        return {
            "activity_id": "activity_link",
            "event_type": "LINK_RESOURCE_IDENTITY",
            "event_time": when,
            "resource_id": resource_id,
            "details": details,
        }

    def test_consistent_link_is_allowed_and_preserves_observation_time(self):
        rec = record("SEARCH_INDEX_ENTRY", resource_id="search_900",
                     system_id="search_service", evidence_id="evidence_search")
        linked = _records_from_activity_links(
            [self._link()], IDS, AUDIT_AT, REQUESTED_AT, EvidenceCorpus([rec])
        )
        assert len(linked) == 1
        assert linked[0].captured_at == CAPTURED_AT
        assert "activity:activity_link" == linked[0].provenance

    def test_contradictory_link_is_rejected(self):
        rec = record(
            "SEARCH_INDEX_ENTRY", resource_id="search_900",
            system_id="search_service", identifiers={"other@example.com"},
        )
        linked = _records_from_activity_links(
            [self._link()], IDS, AUDIT_AT, REQUESTED_AT, EvidenceCorpus([rec])
        )
        assert linked == []

    def test_link_outside_window_is_rejected(self):
        rec = record("SEARCH_INDEX_ENTRY", resource_id="search_900",
                     system_id="search_service")
        linked = _records_from_activity_links(
            [self._link(when="2026-06-20T00:00:00Z")],
            IDS, AUDIT_AT, REQUESTED_AT, EvidenceCorpus([rec]),
        )
        assert linked == []

    def test_unestablished_record_identity_is_rejected(self):
        rec = record("SEARCH_INDEX_ENTRY", resource_id="search_900",
                     system_id="search_service", identifiers=set())
        linked = _records_from_activity_links(
            [self._link()], IDS, AUDIT_AT, REQUESTED_AT, EvidenceCorpus([rec])
        )
        assert linked == []

    def test_explicit_file_link_can_establish_anonymous_record(self):
        rec = record(
            "SUPPORT_ATTACHMENT", resource_id="delivery_confirmation_19",
            system_id="export_service", identifiers=set(),
            details={"object_key": "support-attachments/2026/02/delivery_confirmation_19.pdf"},
        )
        link = self._link(
            resource_id="object_19",
            details=(
                "Attachment catalog confirmed object_19 "
                "(delivery_confirmation_19.pdf) belongs only to "
                "subject@example.com and user_test; no other subject is linked."
            ),
        )
        linked = _records_from_activity_links(
            [link], IDS, AUDIT_AT, REQUESTED_AT, EvidenceCorpus([rec])
        )
        assert len(linked) == 1
        assert linked[0].captured_at == CAPTURED_AT
        assert linked[0].provenance == "activity:activity_link"


class TestAbsentStateNormalization:
    @pytest.mark.parametrize("category", [
        "USER_PROFILE", "SEARCH_INDEX_ENTRY", "ANALYTICS_PROFILE",
        "PRODUCT_TELEMETRY", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT",
        "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG", "ACCOUNT_TOMBSTONE",
        "BACKUP_ARCHIVE", "USER_EXPORT",
    ])
    def test_not_found_forces_absent(self, category):
        assert _state_for_record(category, {"result": "NOT_FOUND"}, "NOT_FOUND") == "ABSENT"

    @pytest.mark.parametrize("category", [
        "USER_PROFILE", "SEARCH_INDEX_ENTRY", "ANALYTICS_PROFILE",
        "PRODUCT_TELEMETRY", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT",
        "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG", "ACCOUNT_TOMBSTONE",
        "BACKUP_ARCHIVE", "USER_EXPORT",
    ])
    def test_unknown_raw_result_is_not_policy_significant(self, category):
        assert _state_for_record(category, {"result": "ARCHIVED"}, "ARCHIVED") == "UNKNOWN"

    def test_known_hit_token_is_present(self):
        assert _state_for_record("SEARCH_INDEX_ENTRY", {"result": "hit"}, "hit") == "PRESENT"

    def test_unknown_account_status_is_unknown(self):
        assert _state_for_record(
            "USER_PROFILE", {"account_status": "ARCHIVED"}, ""
        ) == "UNKNOWN"

    def test_unknown_log_result_is_not_promoted_by_category_branch(self):
        lines = []
        for system, category, resource in [
            ("account_service", "USER_PROFILE", "account_u"),
            ("search_service", "SEARCH_INDEX_ENTRY", "search_u"),
            ("support_platform", "SUPPORT_MESSAGE", "support_u"),
            ("support_platform", "SUPPORT_ATTACHMENT", "support_a"),
            ("analytics_platform", "ANALYTICS_PROFILE", "analytics_u"),
            ("analytics_platform", "PRODUCT_TELEMETRY", "telemetry_u"),
            ("integration_service", "DATA_FLOW", "data_flow_u"),
            ("backup_service", "BACKUP_ARCHIVE", "backup_u"),
            ("export_service", "USER_EXPORT", "export_u"),
            ("security_service", "SECURITY_AUDIT_LOG", "audit_u"),
            ("identity_service", "ACCOUNT_TOMBSTONE", "tombstone_u"),
            ("legal_service", "LEGAL_HOLD_RECORD", "legal_u"),
            ("marketing_platform", "MARKETING_PROFILE", "marketing_u"),
        ]:
            lines.append(
                f"2026-01-01T00:00:00Z INFO service={system} "
                f"event=record_lookup resource_id={resource} "
                f"record_type={category} result=ARCHIVED subject_reference=user_test"
            )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            records = _parse_log_evidence(
                "evidence_log", path, "synthetic", _parse_iso("2026-01-01T00:00:00Z")
            )
        assert len(records) == len(lines)
        assert {r.state for r in records} == {"UNKNOWN"}

    def test_unknown_state_prevents_complete(self):
        result = audit([
            account_closed(),
            record("USER_PROFILE", state="UNKNOWN", resource_id="account_unknown",
                   system_id="account_service"),
        ])
        assert result.deletion_status == "INCOMPLETE"
        assert any("unsupported DELETE state" in gap for gap in result.evidence_gaps)

    def test_log_not_found_is_not_promoted_to_present(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.log"
            path.write_text(
                "2026-01-01T00:00:00Z INFO service=support_platform "
                "event=attachment_lookup resource_id=support_x "
                "record_type=SUPPORT_ATTACHMENT result=NOT_FOUND subject_reference=user_test\n"
                "2026-01-01T00:00:00Z INFO service=security_service "
                "event=audit_lookup resource_id=audit_x "
                "record_type=SECURITY_AUDIT_LOG result=NOT_FOUND subject_reference=user_test\n"
                "2026-01-01T00:00:00Z INFO service=marketing_platform "
                "event=profile_lookup resource_id=marketing_x "
                "record_type=MARKETING_PROFILE result=NOT_FOUND subject_reference=user_test\n",
                encoding="utf-8",
            )
            records = _parse_log_evidence(
                "evidence_log", path, "synthetic", _parse_iso("2026-01-01T00:00:00Z")
            )
        assert len(records) == 3
        assert {r.state for r in records} == {"ABSENT"}


@pytest.mark.parametrize("category,action", [
    ("SECONDARY_IDENTIFIER", "DELETE"),
    ("CACHE_ENTRY", "DELETE"),
    ("PRODUCT_TELEMETRY", "ANONYMIZE"),
    ("EMAIL_DELIVERY_LOG", "REDACT"),
])
def test_sparse_rule_categories_have_policy_actions(category, action):
    engine = PolicyEngine.from_csv(REPO_ROOT / "dataset" / "deletion_rules.csv")
    details = {"email": "subject@example.com"} if category == "EMAIL_DELIVERY_LOG" else {}
    decision = engine.decide(record(category, details=details), AUDIT_AT, IDS)
    assert decision.supported is True
    assert decision.action == action


class TestPolicyAndParserFailClosed:
    def test_unknown_parser_category_is_not_user_profile(self):
        assert _category_for("mystery_service", "mystery_1") == "UNKNOWN_CATEGORY"

    @pytest.mark.parametrize("hint,category", [
        ("SECONDARY_IDENTIFIER", "SECONDARY_IDENTIFIER"),
        ("cache_entry", "CACHE_ENTRY"),
        ("product_telemetry", "PRODUCT_TELEMETRY"),
        ("email_log", "EMAIL_DELIVERY_LOG"),
    ])
    def test_sparse_rule_category_hints(self, hint, category):
        assert _category_for("mystery_service", "resource_1", hint) == category

    def test_false_email_condition_has_no_remediation(self, tmp_path):
        engine = PolicyEngine.from_csv(REPO_ROOT / "dataset" / "deletion_rules.csv")
        decision = engine.decide(
            record("EMAIL_DELIVERY_LOG", details={"email": ""}),
            AUDIT_AT, IDS,
        )
        assert decision.condition_value is False
        assert decision.action == ""
        result = audit([
            account_closed(),
            record("EMAIL_DELIVERY_LOG", resource_id="email_900", details={"email": ""}),
        ])
        assert result.deletion_status == "INCOMPLETE"
        assert any("policy gap" in gap for gap in result.evidence_gaps)
        assert not any(s.resource_id == "email_900" for s in result.steps)

    def test_false_analytics_condition_keeps_compliant_verification(self):
        result = audit([
            account_closed(),
            record("ANALYTICS_PROFILE", state="ANONYMIZED",
                   resource_id="analytics_900", details={"result": "IDENTIFIABLE"}),
        ])
        assert result.deletion_status == "COMPLETE"
        assert [(s.operation, s.state, s.evidence_id) for s in result.steps if s.resource_id == "analytics_900"] == [
            ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "evidence_synthetic")
        ]
        assert not any("policy gap" in gap for gap in result.evidence_gaps)

    def test_false_email_condition_keeps_redacted_verification(self):
        result = audit([
            account_closed(),
            record("EMAIL_DELIVERY_LOG", state="REDACTED",
                   resource_id="email_900", details={"email": ""}),
        ])
        assert result.deletion_status == "COMPLETE"
        assert [(s.operation, s.state, s.evidence_id) for s in result.steps if s.resource_id == "email_900"] == [
            ("VERIFY_RECORD_REDACTED", "REDACTED", "evidence_synthetic")
        ]
        assert not any("policy gap" in gap for gap in result.evidence_gaps)

    def test_false_condition_does_not_authorize_remediation_for_present_record(self):
        result = audit([
            account_closed(),
            record("EMAIL_DELIVERY_LOG", state="PRESENT",
                   resource_id="email_900", details={"email": ""}),
        ])
        assert result.deletion_status == "INCOMPLETE"
        assert not any(s.resource_id == "email_900" and s.operation == "REDACT_RECORD" for s in result.steps)

    def test_case_61_recovers_file_linked_attachment_plan(self):
        from main import audit_request, load_datasets
        datasets = load_datasets(REPO_ROOT / "dataset")
        corpus = load_evidence_corpus(REPO_ROOT / "dataset")
        request = next(r for r in datasets.deletion_requests if r.case_id == "case_61")
        status, steps, failure = audit_request(request, datasets, corpus)
        assert failure is None
        assert status == "INCOMPLETE"
        attachment = [s for s in steps if s.resource_id == "delivery_confirmation_19"]
        assert [(s.phase, s.operation, s.evidence_id) for s in attachment] == [
            ("FINDING", "REPORT_REMAINING_RECORD", "evidence_46"),
            ("REMEDIATION", "DELETE_RECORD", ""),
            ("VERIFICATION", "VERIFY_RECORD_ABSENT", ""),
        ]

    def test_case_63_remains_unresolved_not_fabricated(self):
        from main import audit_request, load_datasets
        datasets = load_datasets(REPO_ROOT / "dataset")
        corpus = load_evidence_corpus(REPO_ROOT / "dataset")
        request = next(r for r in datasets.deletion_requests if r.case_id == "case_63")
        status, steps, failure = audit_request(request, datasets, corpus)
        assert failure is None
        assert status == "INCOMPLETE"
        assert steps == []

    def test_unknown_support_attachment_owner_is_not_deleted(self, tmp_path):
        engine = PolicyEngine.from_csv(REPO_ROOT / "dataset" / "deletion_rules.csv")
        decision = engine.decide(
            record("SUPPORT_ATTACHMENT", identifiers=set(), details={}),
            AUDIT_AT, IDS,
        )
        assert decision.action == ""
        anchor = record(
            "SUPPORT_ATTACHMENT", resource_id="attachment_900",
            system_id="support_platform", details={"shared_context": False},
            captured_at=_parse_iso("2026-05-20T00:00:00Z"),
        )
        anonymous = record(
            "SUPPORT_ATTACHMENT", resource_id="attachment_900",
            system_id="support_platform", identifiers=set(), details={},
        )
        result = audit([account_closed(), anchor, anonymous])
        assert result.deletion_status == "INCOMPLETE"
        assert not any(s.resource_id == "attachment_900" for s in result.steps)

    def test_unknown_category_without_rule_fails_closed(self):
        engine = PolicyEngine([])
        result = reconstruct_case_state(
            case_id="unknown",
            audit_at=AUDIT_AT,
            is_deletion=True,
            user_identifiers=IDS,
            corpus=EvidenceCorpus([record("UNKNOWN_CATEGORY", resource_id="unknown_1")]),
            require_evidence=True,
            not_before=REQUESTED_AT,
            policy_engine=engine,
        )
        assert result.deletion_status == "INCOMPLETE"
        assert any("no supplied policy rule" in gap for gap in result.evidence_gaps)

    def test_malformed_sql_record_json_is_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sql"
            path.write_text(
                "CREATE TABLE t (resource_id TEXT, record_json TEXT);"
                "INSERT INTO t VALUES ('r1','{bad json');",
                encoding="utf-8",
            )
            with pytest.raises(EvidenceParseError):
                _parse_sql_evidence("evidence_bad", path, "synthetic", CAPTURED_AT)

    def test_malformed_log_json_is_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.log"
            path.write_text('2026-01-01T00:00:00Z INFO {"event":}\n', encoding="utf-8")
            with pytest.raises(EvidenceParseError):
                _parse_log_evidence("evidence_bad", path, "synthetic", CAPTURED_AT)

    def test_malformed_json_container_is_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.json"
            path.write_text("[]", encoding="utf-8")
            with pytest.raises(EvidenceParseError):
                _parse_json_evidence("evidence_bad", path, "synthetic", CAPTURED_AT)

    def test_unsupported_evidence_extension_is_an_error(self, tmp_path):
        dataset = tmp_path / "dataset"
        evidence = dataset / "evidence"
        evidence.mkdir(parents=True)
        (evidence / "x.html").write_text("<html></html>", encoding="utf-8")
        (dataset / "evidence_files.csv").write_text(
            "file_id,file_path,origin,captured_at\n"
            "evidence_html,evidence/x.html,synthetic,2026-01-01T00:00:00Z\n",
            encoding="utf-8",
        )
        with pytest.raises(EvidenceParseError):
            load_evidence_corpus(dataset)

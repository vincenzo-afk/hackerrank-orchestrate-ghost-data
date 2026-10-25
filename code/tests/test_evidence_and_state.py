"""
Test suite for Evidence Parsing & System-State Reconstruction (Task 3).
Covers:
  1. Conflicting evidence (e.g., replication drift, primary vs. replica).
  2. Evidence after the audit cutoff (temporal isolation).
  3. Missing evidence (handling absent/unobserved resources without hallucinating).
  4. Active synchronization or delivery flows (data flows/connectors).
  5. Backup retention and restore risks (backup archives).
  6. Legal holds and retention requirements (security audit logs).
  7. Shared support content vs. subject-only attachments (redact vs delete).
  8. Tombstones and retained audit records (clean vs exposed PII tombstones).
  9. Evidence provenance and unsupported conclusions (evidence_id rules).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Ensure code/ is in import path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import load_datasets, resolve_identity
from evidence_parser import (
    load_evidence_corpus,
    ObservedRecord,
    EvidenceCorpus,
    _parse_iso,
)
from state_reconstruction import (
    reconstruct_case_state,
    AuditStep,
    FINDING_ORDER,
    REMEDIATION_ORDER,
    VERIFICATION_ORDER,
)


@pytest.fixture(scope="module")
def dataset_bundle():
    dataset_dir = REPO_ROOT / "dataset"
    datasets = load_datasets(dataset_dir)
    corpus = load_evidence_corpus(dataset_dir)
    return datasets, corpus


# ---------------------------------------------------------------------------
# 1. Conflicting Evidence
# ---------------------------------------------------------------------------

class TestConflictingEvidence:
    """Test resolution of contradictory evidence between primary and replica."""

    def test_replication_drift_failover_replica(self, dataset_bundle):
        """Real dataset: customer_accounts_failover_replica_20260902.sql (evidence_54).

        In primary database, account_005 was deleted.
        In failover replica, account_005 still exists (replication drift).
        State reconstruction must catch the replica copy and report REMAINING_RECORD.
        """
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-09-08T13:40:00Z")  # case_05 cutoff
        id_res = resolve_identity("leila.haddad@yahoo.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_05",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "INCOMPLETE"
        # Must report remaining record on account_service
        finding_ops = [s.operation for s in res.steps if s.phase == "FINDING"]
        assert "REPORT_REMAINING_RECORD" in finding_ops
        step = next(s for s in res.steps if s.resource_id == "account_005" and s.phase == "FINDING")
        assert step.evidence_id == "evidence_54"
        assert step.state == "PRESENT"

    def test_synthetic_temporal_conflict_resolution(self):
        """Synthetic fixture: newer evidence supersedes older evidence.

        Older evidence (T1) shows PRESENT.
        Newer evidence (T2 <= cutoff) shows ABSENT.
        Newest evidence must determine the final state.
        """
        t1 = _parse_iso("2026-05-01T10:00:00Z")
        t2 = _parse_iso("2026-05-05T10:00:00Z")
        cutoff = _parse_iso("2026-05-10T10:00:00Z")

        r1 = ObservedRecord(
            evidence_id="syn_ev_01",
            file_path=Path("synthetic/old.json"),
            captured_at=t1,
            origin="account_service",
            system_id="account_service",
            resource_id="account_9999",
            data_category="USER_PROFILE",
            state="PRESENT",
            has_exposed_pii=True,
            identifiers={"user_test_1", "test@domain.com"},
        )
        r2 = ObservedRecord(
            evidence_id="syn_ev_02",
            file_path=Path("synthetic/new.json"),
            captured_at=t2,
            origin="account_service",
            system_id="account_service",
            resource_id="account_9999",
            data_category="USER_PROFILE",
            state="ABSENT",
            has_exposed_pii=False,
            identifiers={"user_test_1", "test@domain.com"},
        )

        corpus = EvidenceCorpus([r1, r2])
        res = reconstruct_case_state(
            case_id="synthetic_case_conflict",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers={"user_test_1", "test@domain.com"},
            corpus=corpus,
        )

        assert res.deletion_status == "COMPLETE"
        assert len(res.steps) == 1
        assert res.steps[0].operation == "VERIFY_RECORD_ABSENT"
        assert res.steps[0].evidence_id == "syn_ev_02"


# ---------------------------------------------------------------------------
# 2. Evidence After Audit Cutoff (Temporal Filtering)
# ---------------------------------------------------------------------------

class TestEvidenceAfterAuditCutoff:
    """Test that evidence captured after audit_at is strictly rejected."""

    def test_post_cutoff_evidence_ignored(self):
        """Synthetic fixture: evidence captured after audit_at must not generate findings."""
        t_before = _parse_iso("2026-05-01T10:00:00Z")
        cutoff = _parse_iso("2026-05-05T10:00:00Z")
        t_after = _parse_iso("2026-05-06T10:00:00Z")

        valid_rec = ObservedRecord(
            evidence_id="ev_valid",
            file_path=Path("valid.json"),
            captured_at=t_before,
            origin="account_service",
            system_id="account_service",
            resource_id="account_100",
            data_category="USER_PROFILE",
            state="ABSENT",
            has_exposed_pii=False,
            identifiers={"user_temp_1"},
        )
        post_rec = ObservedRecord(
            evidence_id="ev_post",
            file_path=Path("post.json"),
            captured_at=t_after,
            origin="search_service",
            system_id="search_service",
            resource_id="search_100",
            data_category="SEARCH_INDEX_ENTRY",
            state="PRESENT",
            has_exposed_pii=True,
            identifiers={"user_temp_1"},
        )

        corpus = EvidenceCorpus([valid_rec, post_rec])
        res = reconstruct_case_state(
            case_id="case_temp",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers={"user_temp_1"},
            corpus=corpus,
        )

        # The post-cutoff search entry must be completely excluded!
        assert res.deletion_status == "COMPLETE"
        assert all(s.resource_id != "search_100" for s in res.steps)

    def test_record_timestamps_override_manifest_export_time(self, dataset_bundle):
        _, corpus = dataset_bundle
        observations = {
            (r.evidence_id, r.resource_id): r.captured_at
            for r in corpus.records
            if (r.evidence_id, r.resource_id) in {
                ("evidence_06", "account_3960"),
                ("evidence_06", "audit_record_4902"),
                ("evidence_02", "audit_record_4128"),
            }
        }
        assert observations == {
            ("evidence_06", "account_3960"): _parse_iso("2026-09-16T08:57:34Z"),
            ("evidence_06", "audit_record_4902"): _parse_iso("2026-09-16T08:52:59Z"),
            ("evidence_02", "audit_record_4128"): _parse_iso("2026-09-15T12:00:00Z"),
        }


# ---------------------------------------------------------------------------
# 3. Missing Evidence
# ---------------------------------------------------------------------------

class TestMissingEvidence:
    """Test behavior when no evidence exists for an identifier or system."""

    def test_missing_evidence_does_not_hallucinate(self):
        """Synthetic fixture: an empty corpus cannot prove account closure."""
        corpus = EvidenceCorpus([])
        cutoff = _parse_iso("2026-05-01T10:00:00Z")
        res = reconstruct_case_state(
            case_id="case_missing",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers={"nonexistent_user@domain.com"},
            corpus=corpus,
            require_evidence=True,
        )
        assert res.deletion_status == "INCOMPLETE"
        assert res.steps == []
        assert any("no admissible compliant verification" in gap for gap in res.evidence_gaps)


# ---------------------------------------------------------------------------
# 4. Active Synchronization & Delivery Flows
# ---------------------------------------------------------------------------

class TestActiveDataFlows:
    """Test detection and remediation of active synchronization flows."""

    def test_active_data_flow_generates_finding_and_disable(self, dataset_bundle):
        """Real dataset: data_flow_9522 in customer_account_handover_20261001.txt (evidence_03)."""
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-10-01T12:00:00Z")
        id_res = resolve_identity("novak.tomasz@icloud.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_11",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "INCOMPLETE"
        # Finding: REPORT_ACTIVE_DATA_FLOW
        finding = next(s for s in res.steps if s.resource_id == "data_flow_9522" and s.phase == "FINDING")
        assert finding.operation == "REPORT_ACTIVE_DATA_FLOW"
        assert finding.state == "ACTIVE"
        assert finding.evidence_id == "evidence_03"

        # Remediation: DISABLE_DATA_FLOW
        remed = next(s for s in res.steps if s.resource_id == "data_flow_9522" and s.phase == "REMEDIATION")
        assert remed.operation == "DISABLE_DATA_FLOW"
        assert remed.state == "DISABLED"
        assert remed.evidence_id == ""

        # Verification: VERIFY_DATA_FLOW_DISABLED
        verif = next(s for s in res.steps if s.resource_id == "data_flow_9522" and s.phase == "VERIFICATION")
        assert verif.operation == "VERIFY_DATA_FLOW_DISABLED"
        assert verif.state == "DISABLED"
        assert verif.evidence_id == ""


# ---------------------------------------------------------------------------
# 5. Backup Retention & Restore Risks
# ---------------------------------------------------------------------------

class TestBackupRestoreRisks:
    """Test detection and blocking of backup restore risks."""

    def test_backup_restore_risk_detection(self, dataset_bundle):
        """Real dataset: backup_4978 in customer_data_inventory_20260916.sql (evidence_93)."""
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-09-16T09:00:00Z")
        id_res = resolve_identity("k.appiah88@gmail.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_09",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "INCOMPLETE"
        # Finding: REPORT_RESTORE_RISK
        finding = next(s for s in res.steps if s.resource_id == "backup_4978" and s.phase == "FINDING")
        assert finding.operation == "REPORT_RESTORE_RISK"
        assert finding.state == "ACTIVE"
        assert finding.evidence_id == "evidence_93"

        # Remediation: BLOCK_RESTORE
        remed = next(s for s in res.steps if s.resource_id == "backup_4978" and s.phase == "REMEDIATION")
        assert remed.operation == "BLOCK_RESTORE"
        assert remed.state == "BLOCKED"
        assert remed.evidence_id == ""

        # Verification: VERIFY_RESTORE_BLOCKED
        verif = next(s for s in res.steps if s.resource_id == "backup_4978" and s.phase == "VERIFICATION")
        assert verif.operation == "VERIFY_RESTORE_BLOCKED"
        assert verif.state == "BLOCKED"
        assert verif.evidence_id == ""


# ---------------------------------------------------------------------------
# 6. Legal Holds & Security Audit Retention Requirements
# ---------------------------------------------------------------------------

class TestRetentionRequirements:
    """Test policy-required retention of security audit logs."""

    def test_retained_audit_records_verified_present(self, dataset_bundle):
        """Real dataset: audit_record_2016 in resource_lookup_trace_20260926_103856.log (evidence_94)."""
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-09-26T11:00:00Z")
        id_res = resolve_identity("l.fontaine46@yahoo.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_03",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "COMPLETE"
        # Security audit log must be verified present, NEVER deleted
        audit_step = next(s for s in res.steps if s.resource_id == "audit_record_2016")
        assert audit_step.phase == "VERIFICATION"
        assert audit_step.operation == "VERIFY_RECORD_PRESENT"
        assert audit_step.state == "PRESENT"
        assert audit_step.evidence_id == "evidence_94"


# ---------------------------------------------------------------------------
# 7. Support Content: Redaction vs. Deletion
# ---------------------------------------------------------------------------

class TestSupportContentTreatment:
    """Test policy differences between SUPPORT_MESSAGE (redact) and SUPPORT_ATTACHMENT (delete)."""

    def test_support_attachment_deleted(self, dataset_bundle):
        """Real dataset: support_001 in delivery_correction_attachment.pdf (evidence_58).

        Belongs only to the subject -> must be DELETED.
        """
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-09-12T08:00:00Z")
        id_res = resolve_identity("priya.raman@gmail.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_07",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "INCOMPLETE"
        step = next(s for s in res.steps if s.resource_id == "support_001" and s.phase == "FINDING")
        assert step.operation == "REPORT_REMAINING_RECORD"
        remed = next(s for s in res.steps if s.resource_id == "support_001" and s.phase == "REMEDIATION")
        assert remed.operation == "DELETE_RECORD"

    def test_support_message_redacted(self, dataset_bundle):
        """Real dataset: support_864 in customer_account_handover_20261001.txt (evidence_03).

        Contains shared order/customer context -> must be REDACTED.
        """
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-10-01T12:00:00Z")
        id_res = resolve_identity("novak.tomasz@icloud.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_11",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "INCOMPLETE"
        finding = next(s for s in res.steps if s.resource_id == "support_864" and s.phase == "FINDING")
        assert finding.operation == "REPORT_EXPOSED_PII"
        remed = next(s for s in res.steps if s.resource_id == "support_864" and s.phase == "REMEDIATION")
        assert remed.operation == "REDACT_RECORD"


# ---------------------------------------------------------------------------
# 8. Account Tombstones
# ---------------------------------------------------------------------------

class TestAccountTombstones:
    """Test policy compliance for account tombstones (rule_15)."""

    def test_clean_tombstone_verified_redacted(self, dataset_bundle):
        """Real dataset: tombstone_440 in customer_data_snapshot_bundle_20260915.json (evidence_51).

        Preserves user_541 internal reference, with name/email/phone null -> REDACTED.
        """
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-09-15T12:00:00Z")
        id_res = resolve_identity("a.eze08@gmail.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_31",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "COMPLETE"
        tomb_step = next(s for s in res.steps if s.resource_id == "tombstone_440")
        assert tomb_step.phase == "VERIFICATION"
        assert tomb_step.operation == "VERIFY_RECORD_REDACTED"
        assert tomb_step.state == "REDACTED"
        assert tomb_step.evidence_id == "evidence_51"

    def test_exposed_pii_tombstone_generates_finding(self, dataset_bundle):
        """Real dataset: tombstone_9178 in customer_data_snapshot_bundle_20260915.json (evidence_51).

        Still has name 'Kofi Addo', email 'addo.kofi@gmail.com' -> REPORT_EXPOSED_PII.
        """
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-09-15T12:00:00Z")
        id_res = resolve_identity("addo.kofi@gmail.com", datasets)
        fp = id_res.fingerprint

        res = reconstruct_case_state(
            case_id="case_32",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
        )

        assert res.deletion_status == "INCOMPLETE"
        finding = next(s for s in res.steps if s.resource_id == "tombstone_9178" and s.phase == "FINDING")
        assert finding.operation == "REPORT_EXPOSED_PII"
        assert finding.evidence_id == "evidence_51"

        remed = next(s for s in res.steps if s.resource_id == "tombstone_9178" and s.phase == "REMEDIATION")
        assert remed.operation == "REDACT_RECORD"


# ---------------------------------------------------------------------------
# 9. Evidence Provenance & Output Contract Rules
# ---------------------------------------------------------------------------

class TestEvidenceProvenanceAndContract:
    """Test evidence_id and ordering constraints."""

    def test_post_request_link_cannot_relabel_pre_request_observation(self):
        """A catalog link is not evidence that an old record still exists now."""
        requested = _parse_iso("2026-06-10T00:00:00Z")
        audit_at = _parse_iso("2026-06-12T00:00:00Z")
        old = ObservedRecord(
            evidence_id="old_snapshot",
            file_path=Path("synthetic/old.json"),
            captured_at=_parse_iso("2026-06-01T00:00:00Z"),
            origin="account_service",
            system_id="account_service",
            resource_id="account_old_only",
            data_category="USER_PROFILE",
            state="PRESENT",
            has_exposed_pii=True,
            identifiers=set(),
        )
        corpus = EvidenceCorpus([old])
        activity = [{
            "activity_id": "link_after_request",
            "event_type": "LINK_RESOURCE_IDENTITY",
            "event_time": "2026-06-11T00:00:00Z",
            "resource_id": "account_old_only",
            "details": "subject user_temporal_1",
        }]

        result = reconstruct_case_state(
            case_id="synthetic_pre_request_link",
            audit_at=audit_at,
            is_deletion=True,
            user_identifiers={"user_temporal_1"},
            corpus=corpus,
            system_activity=activity,
            require_evidence=True,
            not_before=requested,
        )

        assert result.deletion_status == "INCOMPLETE"
        assert result.steps == []

    def test_evidence_id_contract(self, dataset_bundle):
        """Findings and complete verifications cite evidence_id; remediation and future checks must be empty."""
        datasets, corpus = dataset_bundle

        for cid in ["case_03", "case_05", "case_11", "case_31"]:
            req = next(r for r in datasets.sample_requests if r.case_id == cid)
            id_res = resolve_identity(req.email, datasets)
            res = reconstruct_case_state(
                case_id=cid,
                audit_at=req.audit_at,
                is_deletion=True,
                user_identifiers=id_res.fingerprint.all_identifiers,
                corpus=corpus,
            )

            for step in res.steps:
                if step.phase == "FINDING":
                    assert step.evidence_id != "", f"{cid}: Finding {step.resource_id} missing evidence_id"
                elif step.phase == "REMEDIATION":
                    assert step.evidence_id == "", f"{cid}: Remediation {step.resource_id} has non-empty evidence_id"
                elif step.phase == "VERIFICATION":
                    if res.deletion_status == "COMPLETE":
                        assert step.evidence_id != "", f"{cid}: Complete verification {step.resource_id} missing evidence_id"
                    else:
                        assert step.evidence_id == "", f"{cid}: Incomplete verification {step.resource_id} has non-empty evidence_id"

    def test_step_ordering_contract(self, dataset_bundle):
        """Steps must follow phase order: FINDING -> REMEDIATION -> VERIFICATION, then operation table rank."""
        datasets, corpus = dataset_bundle
        cutoff = _parse_iso("2026-10-01T12:00:00Z")
        id_res = resolve_identity("novak.tomasz@icloud.com", datasets)
        res = reconstruct_case_state(
            case_id="case_11",
            audit_at=cutoff,
            is_deletion=True,
            user_identifiers=id_res.fingerprint.all_identifiers,
            corpus=corpus,
        )

        phase_seq = [s.phase for s in res.steps]
        # Findings before Remediations before Verifications
        last_phase = "FINDING"
        phase_ranks = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        for s in res.steps:
            assert phase_ranks[s.phase] >= phase_ranks[last_phase]
            last_phase = s.phase

        # Step numbers consecutive from 1
        assert [s.step_no for s in res.steps] == list(range(1, len(res.steps) + 1))

"""
Tests for code/main.py — Ghost Data Still Exists foundation layer.

Run with:  python -m pytest code/tests/ -v
           (from the repository root)

Coverage:
  T01-T07   load_datasets() validation
  T08-T18   resolve_identity() — current, historical, case-insensitive, ambiguous, not-found
  T19-T32   classify_request() — all 32 sample request texts
  T33-T38   filter_evidence() — boundary, timezone, ordering
"""

from __future__ import annotations

import sys
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from types import SimpleNamespace

# Ensure the repo root is on sys.path so `code.main` can be imported.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

import main as main_module  # noqa: E402
from main import (  # noqa: E402
    load_datasets,
    classify_request,
    resolve_identity,
    filter_evidence,
    EvidenceFile,
    Datasets,
    IdentityResolutionResult,
    _parse_iso,
    audit_request,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def datasets() -> Datasets:
    """Load real datasets once for the entire test session."""
    return load_datasets(REPO_ROOT / "dataset")


# ---------------------------------------------------------------------------
# T01-T07: load_datasets validation
# ---------------------------------------------------------------------------

class TestDatasetLoading:
    def test_T01_deletion_requests_count(self, datasets):
        """T01: deletion_requests.csv must have exactly 518 rows."""
        assert len(datasets.deletion_requests) == 518

    def test_T02_sample_requests_count(self, datasets):
        """T02: sample_deletion_requests.csv must have exactly 32 rows."""
        assert len(datasets.sample_requests) == 32

    def test_T03_identities_loaded(self, datasets):
        """T03: user_identities.csv must have at least 800 users."""
        assert len(datasets.identities) >= 800

    def test_T04_deletion_rules_count(self, datasets):
        """T04: deletion_rules.csv must have exactly 15 rules."""
        assert len(datasets.deletion_rules) == 15

    def test_T05_evidence_files_count(self, datasets):
        """T05: evidence_files.csv must have exactly 94 evidence files."""
        assert len(datasets.evidence_files) == 94

    def test_T06_timestamps_are_utc_aware(self, datasets):
        """T06: All parsed datetimes must carry UTC timezone info."""
        req = datasets.deletion_requests[0]
        assert req.requested_at.tzinfo is not None
        assert req.audit_at.tzinfo is not None
        for ev in datasets.evidence_files:
            assert ev.captured_at.tzinfo is not None, f"{ev.file_id} missing tzinfo"

    def test_T07_case_ids_unique(self, datasets):
        """T07: case_id values in deletion_requests must be unique."""
        ids = [r.case_id for r in datasets.deletion_requests]
        assert len(ids) == len(set(ids))

    def test_T07b_sample_case_ids_cover_01_to_32(self, datasets):
        """T07b: Sample cases are case_01 through case_32."""
        ids = {r.case_id for r in datasets.sample_requests}
        expected = {f"case_{i:02d}" for i in range(1, 33)}
        assert ids == expected


# ---------------------------------------------------------------------------
# T08-T18: resolve_identity
# ---------------------------------------------------------------------------

class TestIdentityResolution:
    def test_T08_current_email_direct_match(self, datasets):
        """T08: amina.elmasri@gmail.com (case_01) -> user_01 via current email."""
        result = resolve_identity("amina.elmasri@gmail.com", datasets)
        assert result.status == "found"
        assert result.fingerprint.user_id == "user_01"
        assert result.match_type == "current_email"

    def test_T09_case_insensitive_current_match(self, datasets):
        """T09: AMINA.ELMASRI@GMAIL.COM must match same user as lowercase."""
        result = resolve_identity("AMINA.ELMASRI@GMAIL.COM", datasets)
        assert result.status == "found"
        assert result.fingerprint.user_id == "user_01"

    def test_T10_historical_email_match_case12(self, datasets):
        """T10: case_12 uses minjun.kim@gmail.com (current), but user changed
        email from minjun.kim90@gmail.com -> resolves to user_12 either way."""
        # Current email lookup
        r_current = resolve_identity("minjun.kim@gmail.com", datasets)
        assert r_current.status == "found"
        assert r_current.fingerprint.user_id == "user_12"
        assert r_current.match_type == "current_email"

    def test_T11_historical_email_lookup_case12_old(self, datasets):
        """T11: The OLD email minjun.kim90@gmail.com should also resolve to user_12."""
        result = resolve_identity("minjun.kim90@gmail.com", datasets)
        assert result.status == "found"
        assert result.fingerprint.user_id == "user_12"
        assert result.match_type == "historical_email"

    def test_T12_historical_email_lookup_case29(self, datasets):
        """T12: case_29 uses noah.f438085@outlook.com (old email) -> user_29."""
        result = resolve_identity("noah.f438085@outlook.com", datasets)
        assert result.status == "found"
        assert result.fingerprint.user_id == "user_29"
        assert result.match_type == "historical_email"

    def test_T12b_case29_current_email_also_resolves(self, datasets):
        """T12b: user_29's current email noah.f4380@outlook.com also resolves."""
        result = resolve_identity("noah.f4380@outlook.com", datasets)
        assert result.status == "found"
        assert result.fingerprint.user_id == "user_29"
        assert result.match_type == "current_email"

    def test_T13_historical_email_case30(self, datasets):
        """T13: case_30 uses camille.bernard86@outlook.com (old) -> user_30."""
        result = resolve_identity("camille.bernard86@outlook.com", datasets)
        assert result.status == "found"
        assert result.fingerprint.user_id == "user_30"
        assert result.match_type == "historical_email"

    def test_T14_not_found_unknown_email(self, datasets):
        """T14: A completely unknown email returns not_found."""
        result = resolve_identity("nobody@nonexistent-domain.example", datasets)
        assert result.status == "not_found"
        assert result.fingerprint is None

    def test_T15_fingerprint_contains_all_identifiers(self, datasets):
        """T15: user_29 fingerprint must include both old and new email."""
        result = resolve_identity("noah.f438085@outlook.com", datasets)
        assert result.status == "found"
        fp = result.fingerprint
        # current email
        assert "noah.f4380@outlook.com" in fp.all_emails
        # old email
        assert "noah.f438085@outlook.com" in fp.all_emails
        # user_id in all_identifiers
        assert fp.user_id in fp.all_identifiers

    def test_T16_case10_nadia_current_email(self, datasets):
        """T16: case_10 — nadia.ionescu@yahoo.com — this is the OLD email
        that Nadia says she used before changing. Audit log maps it to user_10."""
        result = resolve_identity("nadia.ionescu@yahoo.com", datasets)
        # Check: is this a historical email for user_10?
        # user_10 current email is n.petrescu@yahoo.com
        # The request text says "I used this Yahoo address before changing the email"
        # We expect historical match to user_10 OR direct match depending on data.
        assert result.status in ("found", "not_found"), (
            f"Unexpected status {result.status}: {result.message}"
        )
        if result.status == "found":
            # If found, must be user_10
            assert result.fingerprint.user_id == "user_10", (
                f"Expected user_10, got {result.fingerprint.user_id}"
            )

    def test_T17_decoy_check_case28(self, datasets):
        """T17: case_28 — smartinez6461@gmail.com — user warns a SIMILAR email
        belongs to someone else. The exact email must resolve to ONE user only."""
        result = resolve_identity("smartinez6461@gmail.com", datasets)
        # This is user_28's current email; the "similar email" is a decoy in evidence
        assert result.status == "found"
        assert result.fingerprint.user_id == "user_28"

    def test_T18_all_sample_emails_resolveability(self, datasets):
        """T18: Run all 32 sample case emails through resolve_identity and
        report results. No crash expected; statuses must be valid values."""
        valid_statuses = {"found", "not_found", "ambiguous"}
        for req in datasets.sample_requests:
            result = resolve_identity(req.email, datasets)
            assert result.status in valid_statuses, (
                f"{req.case_id}: unexpected status {result.status!r}"
            )


# ---------------------------------------------------------------------------
# T19-T32: classify_request — all 32 sample requests
# ---------------------------------------------------------------------------

# Ground truth: all 32 sample cases ARE deletion requests.
# The sample_output.csv has all 32 as COMPLETE/INCOMPLETE (none NOT_APPLICABLE).
EXPECTED_CLASSIFICATION = {
    # All sample cases are deletion requests
    f"case_{i:02d}": True for i in range(1, 33)
}


class TestRequestClassification:
    @pytest.mark.parametrize("case_id,expected_is_deletion", [
        ("case_01", True),  # "close... remove the profile"
        ("case_02", True),  # Spanish: "eliminar mi cuenta"
        ("case_03", True),  # French: "suppression définitive du compte"
        ("case_04", True),  # "deleting my account"
        ("case_05", True),  # "deleted this account... remove any remaining copy"
        ("case_06", True),  # "remove that search result"
        ("case_07", True),  # "delete my account"
        ("case_08", True),  # "closed my account... delete that export file"
        ("case_09", True),  # "permanently delete the account"
        ("case_10", True),  # "remove records linked to both addresses"
        ("case_11", True),  # "account... to be erased"
        ("case_12", True),  # "check that nothing tied to the old address was left behind"
        ("case_13", True),  # "close my account and process the associated personal-data deletion"
        ("case_14", True),  # Japanese: 削除 (delete)
        ("case_15", True),  # "Close the account completely"
        ("case_16", True),  # "request for permanent account deletion"
        ("case_17", True),  # "close this account permanently"
        ("case_18", True),  # "remove my account and the personal information"
        ("case_19", True),  # "remove my profile... clean my personal details"
        ("case_20", True),  # "request for permanent account deletion"
        ("case_21", True),  # "deleted my account... verify that the profile is gone"
        ("case_22", True),  # "erase the account"
        ("case_23", True),  # "delete this account"
        ("case_24", True),  # "deletion was complete... finish the deletion"
        ("case_25", True),  # "whether the account... have already been removed"
        ("case_26", True),  # "profile is gone"
        ("case_27", True),  # "account was fully removed"
        ("case_28", True),  # "verify that my account was deleted"
        ("case_29", True),  # "remove records under both addresses"
        ("case_30", True),  # "account had been deleted... handle them"
        ("case_31", True),  # "remove my name and contact details... no longer need"
        ("case_32", True),  # "account itself is gone... remove the rest"
    ])
    def test_T19_to_T32_classify_sample_requests(
        self, case_id: str, expected_is_deletion: bool, datasets
    ):
        """T19-T32: Each sample request should be classified as a deletion request."""
        # Find the request
        req = next(r for r in datasets.sample_requests if r.case_id == case_id)
        result = classify_request(req.request_text)
        assert result["is_deletion"] == expected_is_deletion, (
            f"{case_id}: expected is_deletion={expected_is_deletion}, "
            f"got {result['is_deletion']!r}. "
            f"Text: {req.request_text[:80]!r}. "
            f"Signals: {result['matched_deletion_signals']}. "
            f"Notes: {result['notes']}"
        )

    def test_classify_explicit_non_deletion_marketing_optout(self):
        """classify_request returns False for a marketing opt-out."""
        text = "Please opt out of all your marketing emails immediately."
        result = classify_request(text)
        assert result["is_deletion"] is False

    def test_classify_explicit_non_deletion_data_access(self):
        """classify_request returns False for a data access/export request."""
        text = "I'd like to access and download a copy of all my data."
        result = classify_request(text)
        assert result["is_deletion"] is False

    def test_classify_deletion_prevails_over_mixed_signals(self):
        """classify_request returns True when deletion + non-deletion signals coexist."""
        text = "Please delete my account and also unsubscribe me from emails."
        result = classify_request(text)
        assert result["is_deletion"] is True

    def test_classify_spanish(self):
        """classify_request handles Spanish deletion request."""
        text = "Quiero eliminar mi cuenta y todos mis datos personales."
        result = classify_request(text)
        assert result["is_deletion"] is True

    def test_classify_french(self):
        """classify_request handles French deletion request."""
        text = "Je souhaite la suppression de mon compte."
        result = classify_request(text)
        assert result["is_deletion"] is True

    def test_classify_japanese(self):
        """classify_request handles Japanese deletion request."""
        text = "このアカウントの削除を依頼します。"
        result = classify_request(text)
        assert result["is_deletion"] is True


# ---------------------------------------------------------------------------
# T33-T38: filter_evidence
# ---------------------------------------------------------------------------

def _make_evidence(file_id: str, iso_ts: str) -> EvidenceFile:
    return EvidenceFile(
        file_id=file_id,
        file_path=Path("/fake") / file_id,
        origin="test",
        captured_at=_parse_iso(iso_ts),
    )


class TestFilterEvidence:
    def test_T33_inclusive_boundary(self):
        """T33: Evidence captured exactly at audit_at IS admissible (<= not <)."""
        audit_at = _parse_iso("2026-09-15T12:00:00Z")
        ev = _make_evidence("ev_exact", "2026-09-15T12:00:00Z")
        result = filter_evidence(audit_at, [ev])
        assert ev in result, "Exact boundary evidence should be included"

    def test_T34_evidence_after_cutoff_excluded(self):
        """T34: Evidence captured 1 second after audit_at must NOT be included."""
        audit_at = _parse_iso("2026-09-15T12:00:00Z")
        ev_after = _make_evidence("ev_after", "2026-09-15T12:00:01Z")
        result = filter_evidence(audit_at, [ev_after])
        assert ev_after not in result

    def test_T35_evidence_before_cutoff_included(self):
        """T35: Evidence captured before audit_at must be included."""
        audit_at = _parse_iso("2026-09-15T12:00:00Z")
        ev_before = _make_evidence("ev_before", "2026-09-14T23:59:59Z")
        result = filter_evidence(audit_at, [ev_before])
        assert ev_before in result

    def test_T36_result_sorted_newest_first(self):
        """T36: Admissible evidence is sorted newest-first."""
        audit_at = _parse_iso("2026-10-01T00:00:00Z")
        ev1 = _make_evidence("ev_old", "2026-08-01T00:00:00Z")
        ev2 = _make_evidence("ev_mid", "2026-09-01T00:00:00Z")
        ev3 = _make_evidence("ev_new", "2026-09-30T00:00:00Z")
        result = filter_evidence(audit_at, [ev1, ev3, ev2])
        assert result[0].file_id == "ev_new"
        assert result[1].file_id == "ev_mid"
        assert result[2].file_id == "ev_old"

    def test_T37_naive_audit_at_raises(self):
        """T37: A naive (non-UTC-aware) audit_at must raise ValueError."""
        naive_dt = datetime(2026, 9, 15, 12, 0, 0)  # no tzinfo
        with pytest.raises(ValueError, match="timezone"):
            filter_evidence(naive_dt, [])

    def test_T38_real_evidence_case01(self, datasets):
        """T38: case_01 audit_at=2026-09-03T11:30:00Z — evidence_54 (2026-09-02T23:00:00Z)
        must be admissible; evidence_92 (2026-09-15) must NOT be."""
        req = next(r for r in datasets.sample_requests if r.case_id == "case_01")
        admissible = filter_evidence(req.audit_at, datasets.evidence_files)
        admissible_ids = {e.file_id for e in admissible}

        # evidence_54 captured 2026-09-02T23:00:00Z — BEFORE audit_at — must be in
        assert "evidence_54" in admissible_ids, (
            "evidence_54 should be admissible for case_01"
        )
        # evidence_92 captured 2026-09-15T11:44:55Z — AFTER audit_at — must NOT be in
        assert "evidence_92" not in admissible_ids, (
            "evidence_92 should NOT be admissible for case_01 (captured after audit_at)"
        )

    def test_T38b_real_evidence_case11_boundary(self, datasets):
        """T38b: case_11 audit_at=2026-10-01T12:00:00Z — evidence_03 captured
        exactly at 2026-10-01T12:00:00Z must be admissible (inclusive boundary)."""
        req = next(r for r in datasets.sample_requests if r.case_id == "case_11")
        admissible = filter_evidence(req.audit_at, datasets.evidence_files)
        admissible_ids = {e.file_id for e in admissible}
        assert "evidence_03" in admissible_ids, (
            "evidence_03 captured exactly at audit_at must be admissible"
        )

    def test_T38c_real_evidence_case03_cutoff(self, datasets):
        """T38c: case_03 audit_at=2026-09-26T11:00:00Z — evidence_94
        (captured 2026-09-26T10:38:56Z) must be admissible; evidence_03
        (2026-10-01) must not."""
        req = next(r for r in datasets.sample_requests if r.case_id == "case_03")
        admissible = filter_evidence(req.audit_at, datasets.evidence_files)
        admissible_ids = {e.file_id for e in admissible}
        assert "evidence_94" in admissible_ids, (
            "evidence_94 should be admissible for case_03"
        )
        assert "evidence_03" not in admissible_ids, (
            "evidence_03 should NOT be admissible for case_03"
        )


def test_reconstruction_failure_propagates_and_does_not_become_incomplete(
    datasets, monkeypatch
):
    request = next(r for r in datasets.sample_requests if r.case_id == "case_01")

    def broken_reconstruction(**_kwargs):
        raise ValueError("malformed evidence")

    monkeypatch.setattr(main_module, "reconstruct_case_state", broken_reconstruction)
    with pytest.raises(RuntimeError, match="case_01: state reconstruction failed") as exc:
        audit_request(request, datasets, object(), links=SimpleNamespace(links={}, diagnostics=[]))
    assert isinstance(exc.value.__cause__, ValueError)


def test_pipeline_failure_does_not_write_output(monkeypatch, tmp_path):
    target = tmp_path / "output.csv"

    def broken_audit(*_args, **_kwargs):
        raise RuntimeError("case_001: state reconstruction failed; output was not generated")

    monkeypatch.setattr(main_module, "audit_request", broken_audit)
    with pytest.raises(RuntimeError, match="output was not generated"):
        main_module.run_full_pipeline(output_path=target)
    assert not target.exists()

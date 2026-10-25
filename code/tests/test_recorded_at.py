"""
Regression coverage for record-level ``recorded_at`` timestamps.

JSON evidence bundles often carry an export/snapshot time that is later than
the individual lookup result.  The record-level ``recorded_at`` is the
observation time and must win over the enclosing bundle default, while more
specific ``observed_at`` and record-level ``captured_at`` fields retain their
existing precedence.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import audit_request, load_datasets
from evidence_parser import (
    EvidenceCorpus,
    ObservedRecord,
    _observation_time,
    _parse_iso,
    load_evidence_corpus,
)


@pytest.fixture(scope="module")
def dataset_bundle():
    dataset_dir = REPO_ROOT / "dataset"
    datasets = load_datasets(dataset_dir)
    corpus = load_evidence_corpus(dataset_dir)
    return datasets, corpus


def _observation_times(corpus, evidence_id: str, resource_id: str):
    return sorted(
        record.captured_at
        for record in corpus.records
        if record.evidence_id == evidence_id and record.resource_id == resource_id
    )


def _run_case(datasets, corpus, case_id: str):
    request = next(r for r in datasets.deletion_requests if r.case_id == case_id)
    status, steps, failure = audit_request(request, datasets, corpus)
    assert failure is None
    return request, status, steps


def test_observation_time_precedence():
    default = _parse_iso("2026-01-01T00:00:00Z")
    observed = _parse_iso("2026-02-01T00:00:00Z")
    captured = _parse_iso("2026-02-02T00:00:00Z")
    recorded = _parse_iso("2026-02-03T00:00:00Z")

    assert _observation_time({}, default) == default
    assert _observation_time({"recorded_at": "2026-02-03T00:00:00Z"}, default) == recorded
    assert _observation_time(
        {"captured_at": "2026-02-02T00:00:00Z", "recorded_at": "2026-02-03T00:00:00Z"},
        default,
    ) == captured
    assert _observation_time(
        {
            "observed_at": "2026-02-01T00:00:00Z",
            "captured_at": "2026-02-02T00:00:00Z",
            "recorded_at": "2026-02-03T00:00:00Z",
        },
        default,
    ) == observed


def test_recorded_at_is_used_across_json_formats(dataset_bundle):
    _, corpus = dataset_bundle

    # Top-level records: connector configuration and security ledger.
    assert _observation_times(corpus, "evidence_13", "account_1084") == [
        _parse_iso("2026-08-12T09:00:00Z")
    ]
    assert _observation_times(corpus, "evidence_50", "account_1733") == [
        _parse_iso("2026-10-01T12:00:00Z")
    ]

    # Snapshot operational histories: record time, not bundle export time.
    assert _observation_times(corpus, "evidence_31", "account_614") == [
        _parse_iso("2026-05-04T10:00:00Z")
    ]
    assert _observation_times(corpus, "evidence_45", "account_2961") == [
        _parse_iso("2026-02-18T09:00:00Z")
    ]
    assert _observation_times(corpus, "evidence_22", "account_2614") == [
        _parse_iso("2026-06-23T06:00:00Z")
    ]

    # Export manifest: FOUND and later NOT_FOUND keep their distinct times.
    assert _observation_times(corpus, "evidence_36", "account_7618") == [
        _parse_iso("2026-04-03T12:00:00Z"),
        _parse_iso("2026-04-09T12:00:00Z"),
    ]


def test_request_and_audit_boundaries_are_inclusive():
    requested = _parse_iso("2026-05-01T10:00:00Z")
    audit = _parse_iso("2026-05-10T10:00:00Z")
    records = []
    for resource_id, when in (
        ("boundary_before", requested - timedelta(seconds=1)),
        ("boundary_start", requested),
        ("boundary_end", audit),
        ("boundary_after", audit + timedelta(seconds=1)),
    ):
        records.append(
            ObservedRecord(
                evidence_id="synthetic_boundary",
                file_path=Path("synthetic/boundary.json"),
                captured_at=when,
                origin="synthetic",
                system_id="account_service",
                resource_id=resource_id,
                data_category="USER_PROFILE",
                state="ABSENT",
                has_exposed_pii=False,
                identifiers={"boundary@example.com"},
            )
        )

    corpus = EvidenceCorpus(records)
    selected = corpus.get_records_for_identifiers(
        {"boundary@example.com"}, audit_at=audit, not_before=requested
    )
    assert {record.resource_id for record in selected} == {
        "boundary_start",
        "boundary_end",
    }


def test_stale_found_does_not_override_newer_absent_at_audit(dataset_bundle):
    datasets, corpus = dataset_bundle
    request, status, steps = _run_case(datasets, corpus, "case_390")

    assert status == "COMPLETE"
    assert all(step.phase == "VERIFICATION" for step in steps)
    account = next(step for step in steps if step.resource_id == "account_7618")
    assert account.operation == "VERIFY_RECORD_ABSENT"
    assert account.state == "ABSENT"
    assert account.evidence_id == "evidence_36"


def test_post_audit_reappearance_does_not_change_audit_answer(dataset_bundle):
    datasets, corpus = dataset_bundle
    request, status, steps = _run_case(datasets, corpus, "case_335")

    assert status == "COMPLETE"
    account = next(step for step in steps if step.resource_id == "account_8892")
    assert account.operation == "VERIFY_RECORD_ABSENT"
    # evidence_31 was published after audit_at, so it cannot be cited; the
    # in-time scoped inventory proves the absence instead.
    assert account.evidence_id == "evidence_72"

    later = [
        record
        for record in corpus.records
        if record.evidence_id == "evidence_31"
        and record.resource_id == "account_8892"
        and record.captured_at > request.audit_at
    ]
    assert later and all(record.state == "PRESENT" for record in later)


@pytest.mark.parametrize("case_id,resource_id", [
    ("case_484", "support_7973"),
    ("case_342", "support_3399"),
    ("case_234", "support_1254"),
])
def test_identifiable_support_lookup_is_exposed_pii(dataset_bundle, case_id, resource_id):
    datasets, corpus = dataset_bundle
    _, status, steps = _run_case(datasets, corpus, case_id)
    assert status == "INCOMPLETE"
    finding = next(s for s in steps if s.resource_id == resource_id and s.phase == "FINDING")
    assert finding.operation == "REPORT_EXPOSED_PII"
    assert finding.evidence_id


def test_state_known_only_from_late_file_is_a_future_check(dataset_bundle):
    datasets, corpus = dataset_bundle
    _, status, steps = _run_case(datasets, corpus, "case_234")
    account_check = next(step for step in steps if step.resource_id == "account_2614")
    assert account_check.phase == "VERIFICATION"
    assert account_check.operation == "VERIFY_RECORD_ABSENT"
    assert account_check.evidence_id == ""

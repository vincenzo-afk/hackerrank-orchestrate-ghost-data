"""Regression coverage for general PDF legal-register extraction."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import load_datasets, resolve_identity
from evidence_parser import load_evidence_corpus, _parse_iso


def test_legal_register_rows_are_extracted():
    corpus = load_evidence_corpus(REPO_ROOT / "dataset")
    records = [r for r in corpus.records if r.evidence_id == "evidence_27"]
    assert len(records) == 6
    assert {r.resource_id for r in records} == {
        "ORD-20264118",
        "ORD-20264207",
        "ORD-20264319",
        "ORD-20264402",
        "ORD-20264511",
        "ORD-20264600",
    }
    assert {next(iter(r.identifiers)) for r in records} == {
        "user_08",
        "user_12",
        "user_17",
        "user_21",
        "user_24",
        "user_29",
    }
    capture = _parse_iso("2026-05-29T08:00:00Z")
    for record in records:
        assert record.data_category == "LEGAL_HOLD_RECORD"
        assert record.state == "PRESENT"
        assert record.captured_at == capture
        assert record.details["retained_until"].endswith("T00:00:00+00:00")
        assert record.details["retention_reason"]


def test_legal_register_is_outside_current_request_windows():
    datasets = load_datasets(REPO_ROOT / "dataset")
    capture = _parse_iso("2026-05-29T08:00:00Z")
    users = {
        "user_08",
        "user_12",
        "user_17",
        "user_21",
        "user_24",
        "user_29",
    }
    for request in datasets.deletion_requests:
        fingerprint = resolve_identity(request.email, datasets).fingerprint
        if fingerprint is None or fingerprint.user_id not in users:
            continue
        assert not (request.requested_at <= capture <= request.audit_at)

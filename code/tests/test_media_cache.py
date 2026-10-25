"""Regression tests for SHA-validated Gemini image observations."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import audit_request, load_datasets
from evidence_parser import load_evidence_corpus
from media_cache import load_media_cache, observations_for


def test_every_cache_source_hash_matches_the_local_image():
    cache = load_media_cache()
    assert cache
    for file_id, entry in cache["images"].items():
        source = REPO_ROOT / "dataset" / entry["file_path"]
        assert source.exists(), file_id
        assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["sha256"]
        assert entry["observations"]


def test_changed_image_bytes_invalidate_observations():
    cache = load_media_cache()
    entry = cache["images"]["evidence_28"]
    source = (REPO_ROOT / "dataset" / entry["file_path"]).read_bytes()
    assert observations_for("evidence_28", source, cache=cache)
    assert observations_for("evidence_28", source + b"changed", cache=cache) == []
    assert observations_for("missing_evidence", source, cache=cache) == []


def test_image_observations_are_normalized_into_the_corpus():
    corpus = load_evidence_corpus(REPO_ROOT / "dataset")
    image_records = [r for r in corpus.records if r.evidence_id.startswith("evidence_") and r.provenance.startswith("gemini:")]
    assert image_records
    evidence_37 = [r for r in corpus.records if r.evidence_id == "evidence_37"]
    assert {r.resource_id for r in evidence_37} == {
        "audit_record_001",
        "audit_record_002",
        "audit_record_003",
        "audit_record_004",
        "audit_record_005",
        "audit_record_006",
    }
    assert all(r.data_category == "SECURITY_AUDIT_LOG" for r in evidence_37)
    assert all(r.state == "PRESENT" for r in evidence_37)
    assert any(r.resource_id == "tombstone_user_17" and r.state == "REDACTED" for r in corpus.records)
    assert any(r.resource_id == "support_1034" and r.data_category == "SUPPORT_MESSAGE" for r in corpus.records)
    assert not any(
        r.resource_id == "support_9538" and r.evidence_id == "evidence_04"
        for r in corpus.records
    )


def test_case_45_receives_all_six_visible_audit_verifications():
    datasets = load_datasets(REPO_ROOT / "dataset")
    corpus = load_evidence_corpus(REPO_ROOT / "dataset")
    request = next(r for r in datasets.deletion_requests if r.case_id == "case_45")
    status, steps, failure = audit_request(request, datasets, corpus)
    assert failure is None
    assert status == "COMPLETE"
    audit_steps = [s for s in steps if s.resource_id.startswith("audit_record_")]
    assert [s.resource_id for s in audit_steps] == [
        "audit_record_001",
        "audit_record_002",
        "audit_record_003",
        "audit_record_004",
        "audit_record_005",
        "audit_record_006",
    ]
    assert all(s.operation == "VERIFY_RECORD_PRESENT" for s in audit_steps)
    assert all(s.state == "PRESENT" for s in audit_steps)
    assert all(s.evidence_id in {"evidence_37", "evidence_55"} for s in audit_steps)

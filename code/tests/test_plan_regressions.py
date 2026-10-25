"""Regression gates for the global audit pipeline (synthetic fixtures only).

Covers the activity linker, coverage-aware absence, replicas, restore
authorization, support classification, catalog aliases, and the guarantee
that production code never reads sample answers or hard-codes case ids.
"""

from __future__ import annotations

import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from activity_linker import ActivityLinker, ResourceLink, _hungarian  # noqa: E402
from evidence_parser import (  # noqa: E402
    CatalogLink,
    EvidenceCorpus,
    ObservedRecord,
    SnapshotCoverage,
    _alias_index,
    _parse_log_evidence,
    _parse_sql_evidence,
    _resolve_visible_resource,
    _state_for_record,
    _parse_iso,
)
from state_reconstruction import reconstruct_case_state  # noqa: E402

UTC = timezone.utc
IDS = {"user_test", "subject@example.com"}
REQ = _parse_iso("2026-06-01T00:00:00Z")
AUDIT = _parse_iso("2026-06-10T00:00:00Z")


def rec(system, resource, category, state, when, evidence="ev_1", ids=None, copy="primary",
        available=None, details=None):
    return ObservedRecord(
        evidence_id=evidence, file_path=Path("synthetic"), captured_at=_parse_iso(when),
        origin="synthetic", system_id=system, resource_id=resource, data_category=category,
        state=state, has_exposed_pii=False, identifiers=set(IDS if ids is None else ids),
        details=details or {}, physical_copy=copy,
        available_at=_parse_iso(available) if available else None,
    )


def audit(records, links=None, coverages=None):
    return reconstruct_case_state(
        "synthetic", AUDIT, True, IDS, EvidenceCorpus(records, coverages or []),
        require_evidence=True, not_before=REQ, links=links,
    )


def write(tmp, name, text):
    path = Path(tmp) / name
    path.write_text(text, encoding="utf-8")
    return path


# -- parser state fixes -------------------------------------------------------

def test_identifiable_support_lookup_is_present():
    item = {"result": "IDENTIFIABLE", "lookup_value": "subject@example.com"}
    assert _state_for_record("SUPPORT_MESSAGE", item, "IDENTIFIABLE") == "PRESENT"


def test_row_count_without_body_is_not_redaction_proof():
    assert _state_for_record("SUPPORT_MESSAGE", {"rows": "1"}, "") == "UNKNOWN"


def test_restore_denial_is_blocked_and_unknown_is_not_a_risk():
    with tempfile.TemporaryDirectory() as td:
        path = write(td, "x.log",
                     '2026-06-05T00:00:00Z INFO service=backup_service event=restore_authorization_completed '
                     'resource_id=backup_1 decision="deny" subject_ref=user_test\n'
                     '2026-06-05T00:00:00Z INFO service=backup_service event=restore_authorization_completed '
                     'resource_id=backup_2 decision="pending" subject_ref=user_test\n')
        records = {r.resource_id: r.state for r in _parse_log_evidence("ev", path, "s", AUDIT)}
    assert records == {"backup_1": "BLOCKED", "backup_2": "UNKNOWN"}


def test_attachment_scan_is_an_attachment():
    with tempfile.TemporaryDirectory() as td:
        path = write(td, "x.log",
                     '2026-06-05T00:00:00Z WARN service=support_platform resource_id=support_1 '
                     'event=attachment_pii_scan matched_value="subject@example.com" file=a.pdf\n')
        (record,) = _parse_log_evidence("ev", path, "s", AUDIT)
    assert (record.data_category, record.state) == ("SUPPORT_ATTACHMENT", "PRESENT")


# -- catalog aliases ------------------------------------------------------------

def _link(alias, system="object_storage", resource="object_19", exclusive=True):
    return CatalogLink("activity_1", REQ, system, resource, alias, frozenset({"user_test"}), exclusive)


def test_filename_resolves_to_catalogued_object():
    aliases = _alias_index([_link("delivery_confirmation_19.pdf")])
    obs = {"resource_id": "delivery_confirmation_19", "system_id": "export_service",
           "details": {"file_name": "delivery_confirmation_19.pdf", "visible_text": "delivery_confirmation_19.pdf"}}
    assert _resolve_visible_resource(obs, aliases)[:2] == ("object_storage", "object_19")


def test_uncatalogued_filename_does_not_mint_a_resource():
    obs = {"resource_id": "return_label_1", "system_id": "export_service",
           "details": {"file_name": "return_label_1.pdf", "visible_text": "return_label_1.pdf"}}
    assert _resolve_visible_resource(obs, {}) is None


def test_statement_number_resolves_within_system_only():
    aliases = _alias_index([_link("NST-2026-0718-1842", "export_service", "export_1842")])
    obs = {"resource_id": "x", "system_id": "export_service",
           "details": {"visible_text": "Statement NST-2026-0718-1842"}}
    assert _resolve_visible_resource(obs, aliases)[:2] == ("export_service", "export_1842")
    obs["system_id"] = "search_service"
    assert _resolve_visible_resource(obs, aliases) is None


# -- coverage and replicas ------------------------------------------------------

def _account_link():
    return [ResourceLink("account_service", "account_9", "USER_PROFILE", "activity", "activity_9",
                         _parse_iso("2026-06-02T00:00:00Z"))]


def _coverage(ids, subjects, when="2026-06-05T00:00:00Z", copy="primary"):
    t = _parse_iso(when)
    return SnapshotCoverage("ev_snap", "account_service", "USER_PROFILE", copy, t, t,
                            frozenset(ids), subjects, "test")


def test_full_snapshot_omission_proves_absence():
    result = audit([], links=_account_link(), coverages=[_coverage({"account_1"}, None)])
    assert result.deletion_status == "COMPLETE"
    assert [(s.operation, s.evidence_id) for s in result.steps] == [("VERIFY_RECORD_ABSENT", "ev_snap")]


def test_snapshot_scoped_to_other_subjects_proves_nothing():
    cov = _coverage(set(), frozenset({"other@example.com"}))
    result = audit([], links=_account_link(), coverages=[cov])
    assert result.deletion_status == "INCOMPLETE"
    assert result.steps[0].evidence_id == ""


def test_snapshot_before_deletion_proves_nothing():
    cov = _coverage({"account_1"}, None, when="2026-06-01T12:00:00Z")
    assert audit([], links=_account_link(), coverages=[cov]).deletion_status == "INCOMPLETE"


def test_replica_presence_survives_primary_deletion():
    records = [
        rec("account_service", "account_9", "USER_PROFILE", "ABSENT", "2026-06-06T00:00:00Z", "ev_primary"),
        rec("account_service", "account_9", "USER_PROFILE", "PRESENT", "2026-06-05T00:00:00Z",
            "ev_replica", copy="failover_replica"),
    ]
    result = audit(records)
    finding = next(s for s in result.steps if s.phase == "FINDING")
    assert (finding.operation, finding.evidence_id) == ("REPORT_REMAINING_RECORD", "ev_replica")


def test_post_audit_evidence_is_never_cited():
    late = rec("search_service", "search_1", "SEARCH_INDEX_ENTRY", "ABSENT", "2026-06-05T00:00:00Z",
               available="2026-06-20T00:00:00Z")
    result = audit([late])
    assert result.deletion_status == "INCOMPLETE"
    assert all(s.evidence_id == "" for s in result.steps)


def test_sql_point_in_time_tables_are_full_copies():
    with tempfile.TemporaryDirectory() as td:
        path = write(td, "x.sql",
                     "-- Ghost Data Still Exists: point-in-time database snapshot\n"
                     "-- Captured at: 2026-06-05T00:00:00Z\n"
                     "CREATE TABLE customer_profiles_primary (resource_id TEXT, user_id TEXT, email TEXT, account_status TEXT);\n"
                     "INSERT INTO customer_profiles_primary VALUES ('account_2','user_2','b@example.com','ACTIVE');\n"
                     "CREATE TABLE customer_profiles_failover_replica (resource_id TEXT, user_id TEXT, email TEXT, account_status TEXT);\n"
                     "INSERT INTO customer_profiles_failover_replica VALUES ('account_9','user_test','subject@example.com','ACTIVE');\n")
        coverages = []
        records = _parse_sql_evidence("ev_sql", path, "s", AUDIT, coverages)
    assert {(r.resource_id, r.physical_copy) for r in records} == {
        ("account_2", "primary"), ("account_9", "failover_replica")}
    assert {(c.physical_copy, c.subject_identifiers) for c in coverages} == {
        ("primary", None), ("failover_replica", None)}


# -- global linker ----------------------------------------------------------------

def test_hungarian_is_globally_optimal():
    # Greedy row-by-row choice would take column 0 for row 0 (cost 1) and
    # force row 1 to cost 100; the optimum assigns (0->1, 1->0).
    assert _hungarian([[1, 2], [3, 100]]) == [1, 0]


def _linker_world():
    """Two requests in one burst; one account is identifier-linked, one is not."""
    t0 = datetime(2026, 6, 1, 12, tzinfo=UTC)
    reqs, rows, records, subjects, owner = [], [], [], {}, {}
    for i in range(30):  # resolved history that teaches the cadence
        r = SimpleNamespace(case_id=f"c{i}", reported_at=t0 + timedelta(days=i),
                            audit_at=t0 + timedelta(days=i, hours=5), requested_at=t0 + timedelta(days=i - 1),
                            reported_status="COMPLETE")
        email = f"u{i}@example.com"
        subjects[r.case_id] = (r, f"user_{i}", {email})
        owner[email] = f"user_{i}"
        rows.append({"activity_id": f"a{i}", "event_time": (r.reported_at - timedelta(minutes=60 + i % 7)).isoformat(),
                     "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
                     "target_system": "account_service", "resource_id": f"account_{i}",
                     "reported_result": "SUCCESS", "details": f"submitted primary profile account_{i}"})
        records.append(rec("account_service", f"account_{i}", "USER_PROFILE", "ABSENT",
                           (r.reported_at + timedelta(hours=1)).isoformat(), ids={email}))
    burst = t0 + timedelta(days=40)
    for name, status, result, minutes in (("x", "COMPLETE", "SUCCESS", 62), ("y", "NOT_STARTED", "FAILED", 58)):
        r = SimpleNamespace(case_id=name, reported_at=burst, audit_at=burst + timedelta(hours=5),
                            requested_at=burst - timedelta(days=1), reported_status=status)
        subjects[name] = (r, f"user_{name}", {f"{name}@example.com"})
        owner[f"{name}@example.com"] = f"user_{name}"
        rows.append({"activity_id": f"a_{name}", "event_time": (burst - timedelta(minutes=minutes)).isoformat(),
                     "event_type": "DELETE_RECORD", "source_system": "deletion_worker",
                     "target_system": "account_service", "resource_id": f"account_{name}",
                     "reported_result": result, "details": f"submitted primary profile account_{name}"})
    return EvidenceCorpus(records), rows, subjects, owner


def test_linker_learns_cadence_and_assigns_one_to_one():
    corpus, rows, subjects, owner = _linker_world()
    result = ActivityLinker(corpus, rows, subjects, owner).run()
    assigned = {c: [l.resource_id for l in result.links.get(c, []) if l.method == "activity"] for c in ("x", "y")}
    # reported_status/result agreement breaks the tie: FAILED -> NOT_STARTED.
    assert assigned == {"x": ["account_x"], "y": ["account_y"]}
    assert all(len([l for l in result.links[c] if l.system_id == "account_service"]) == 1 for c in subjects)


def test_linker_rejects_resource_owned_by_another_subject():
    corpus, rows, subjects, owner = _linker_world()
    corpus = EvidenceCorpus(corpus.records + [
        rec("account_service", "account_x", "USER_PROFILE", "PRESENT", "2026-01-01T00:00:00Z",
            ids={"u3@example.com"})])
    result = ActivityLinker(corpus, rows, subjects, owner).run()
    assert not any(l.resource_id == "account_x" for l in result.links.get("x", []))


# -- no shortcuts -----------------------------------------------------------------

def test_production_code_has_no_case_ids_or_sample_answers():
    for path in (REPO_ROOT / "code").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "sample_output" not in text, path.name
        assert not re.search(r"['\"]case_\d+['\"]", text), path.name


def test_visible_fact_screen_references_are_not_records():
    from evidence_parser import _interpret_visible_observation

    obs = {"visible_resource_ids": ["user_11", "account_5762", "support_9538"], "visible_aliases": [],
           "identifiers": {"emails": ["subject@example.com"], "phones": [], "user_ids": ["user_11"], "names": []},
           "visible_controls": {}, "visible_text": "user_11 account_5762 Support support_9538"}
    assert [(s, r) for s, r, *_ in _interpret_visible_observation(obs, {})] == [("account_service", "account_5762")]


def test_visible_fact_user_reference_resolves_through_catalog():
    from evidence_parser import _interpret_visible_observation

    link = CatalogLink("activity_9", REQ, "identity_service", "tombstone_17", "user_17", frozenset({"user_17"}), False)
    obs = {"visible_resource_ids": ["user_17"], "visible_aliases": [], "identifiers": {"user_ids": ["user_17"]},
           "visible_controls": {}, "visible_text": "user_17 Retained reference"}
    (row,) = _interpret_visible_observation(obs, _alias_index([link]))
    assert row[:2] == ("identity_service", "tombstone_17") and row[4] == "REDACTED"

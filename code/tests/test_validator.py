"""Contract validator tests (code/output_validator.py)."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import load_datasets, validate_output_rows  # noqa: E402

DATASETS = load_datasets(REPO_ROOT / "dataset")


def _rows():
    with open(REPO_ROOT / "output.csv", encoding="utf-8") as f:
        return [(r["case_id"], r["deletion_status"], r["steps_json"]) for r in csv.DictReader(f)]


def _errors(rows):
    return validate_output_rows(rows, DATASETS.deletion_requests, DATASETS)


def _replace(rows, cid, status=None, steps=None):
    out = []
    for c, s, j in rows:
        if c == cid:
            s = status or s
            j = json.dumps(steps) if steps is not None else j
        out.append((c, s, j))
    return out


def _first(rows, status):
    return next((c, json.loads(j)) for c, s, j in rows if s == status)


def test_validator_accepts_current_output():
    assert _errors(_rows()) == []


def test_authorized_empty_plan_is_rejected():
    rows = _rows()
    cid, _ = _first(rows, "INCOMPLETE")
    assert any("empty plan" in e for e in _errors(_replace(rows, cid, steps=[])))


def test_finding_without_remediation_is_rejected():
    rows = _rows()
    cid, steps = _first(rows, "INCOMPLETE")
    trimmed = [s for s in steps if s["phase"] != "REMEDIATION"]
    for i, s in enumerate(trimmed, 1):
        s["step_no"] = i
    assert any("lacks its remediation" in e for e in _errors(_replace(rows, cid, steps=trimmed)))


def test_complete_with_future_step_is_rejected():
    rows = _rows()
    cid, steps = _first(rows, "COMPLETE")
    steps[0]["evidence_id"] = ""
    assert any("without evidence" in e for e in _errors(_replace(rows, cid, steps=steps)))


def test_citation_after_audit_is_rejected():
    rows = _rows()
    cid, steps = _first(rows, "COMPLETE")
    steps[0]["evidence_id"] = "evidence_03"  # manifest capture 2026-10-01
    assert any("later than audit_at" in e for e in _errors(_replace(rows, cid, steps=steps)))


def test_shared_account_across_cases_is_rejected():
    rows = _rows()
    owners = [(c, json.loads(j)) for c, s, j in rows if s == "COMPLETE"]
    (c1, s1), (c2, s2) = owners[0], owners[1]
    acct = next(s for s in s1 if s["system_id"] == "account_service")
    s2 = [s for s in s2 if s["system_id"] != "account_service"] + [dict(acct)]
    s2.sort(key=lambda s: (["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                            "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED",
                            "VERIFY_RESTORE_BLOCKED"].index(s["operation"]), s["system_id"], s["resource_id"]))
    for i, s in enumerate(s2, 1):
        s["step_no"] = i
    assert any("several cases" in e for e in _errors(_replace(rows, c2, steps=s2)))


def test_non_deletion_with_steps_is_rejected():
    rows = _rows()
    cid = next(c for c, s, _ in rows if s == "NOT_APPLICABLE")
    _, steps = _first(rows, "COMPLETE")
    assert any("non-deletion" in e for e in _errors(_replace(rows, cid, "COMPLETE", steps)))

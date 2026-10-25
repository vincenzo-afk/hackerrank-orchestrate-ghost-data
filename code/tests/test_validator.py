"""Regression tests for the independent output validator."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import load_datasets
from evidence_parser import load_evidence_corpus
from evaluation.main import validate_output


def _load():
    datasets = load_datasets(REPO_ROOT / "dataset")
    corpus = load_evidence_corpus(REPO_ROOT / "dataset")
    return datasets, corpus


def _rows():
    with open(REPO_ROOT / "output.csv", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for row in rows:
            writer.writerow([row["case_id"], row["deletion_status"], row["steps_json"]])


def test_validator_accepts_current_output():
    datasets, corpus = _load()
    _, errors = validate_output(datasets, corpus, output_path=REPO_ROOT / "output.csv")
    assert errors == []


def test_validator_rejects_complete_without_account_closure(tmp_path):
    datasets, corpus = _load()
    rows = _rows()
    target = next(r for r in rows if r["case_id"] == "case_113")
    steps = [s for s in json.loads(target["steps_json"]) if not s["resource_id"].startswith("account_")]
    target["steps_json"] = json.dumps(steps, separators=(",", ":"))
    path = tmp_path / "output.csv"
    _write(path, rows)
    _, errors = validate_output(datasets, corpus, output_path=path)
    assert any("account closure" in error for error in errors)


def test_validator_rejects_missing_support_category_treatment(tmp_path):
    datasets, corpus = _load()
    rows = _rows()
    target = next(r for r in rows if r["case_id"] == "case_179")
    steps = [
        s for s in json.loads(target["steps_json"])
        if not (s["resource_id"] == "support_2283" and s["operation"] == "DELETE_RECORD")
    ]
    target["steps_json"] = json.dumps(steps, separators=(",", ":"))
    path = tmp_path / "output.csv"
    _write(path, rows)
    _, errors = validate_output(datasets, corpus, output_path=path)
    assert any("SUPPORT_ATTACHMENT" in error for error in errors)


def test_validator_rejects_missing_non_support_verification(tmp_path):
    datasets, corpus = _load()
    rows = _rows()
    target = next(r for r in rows if r["case_id"] == "case_113")
    steps = [
        s for s in json.loads(target["steps_json"])
        if not (s["resource_id"] == "audit_record_1127")
    ]
    target["steps_json"] = json.dumps(steps, separators=(",", ":"))
    path = tmp_path / "output.csv"
    _write(path, rows)
    _, errors = validate_output(datasets, corpus, output_path=path)
    assert any("SECURITY_AUDIT_LOG" in error for error in errors)


def test_validator_rejects_unsupported_extra_action(tmp_path):
    datasets, corpus = _load()
    rows = _rows()
    target = next(r for r in rows if r["case_id"] == "case_179")
    steps = json.loads(target["steps_json"])
    steps.append({
        "step_no": len(steps) + 1,
        "phase": "VERIFICATION",
        "system_id": "support_platform",
        "resource_id": "support_2283",
        "operation": "VERIFY_RECORD_ANONYMIZED",
        "state": "ANONYMIZED",
        "evidence_id": "",
    })
    target["steps_json"] = json.dumps(steps, separators=(",", ":"))
    path = tmp_path / "output.csv"
    _write(path, rows)
    _, errors = validate_output(datasets, corpus, output_path=path)
    assert any("unsupported VERIFY_RECORD_ANONYMIZED" in error for error in errors)


def test_validator_rejects_evidence_backed_empty_incomplete(tmp_path):
    datasets, corpus = _load()
    rows = _rows()
    target = next(r for r in rows if r["case_id"] == "case_179")
    target["steps_json"] = "[]"
    path = tmp_path / "output.csv"
    _write(path, rows)
    _, errors = validate_output(datasets, corpus, output_path=path)
    assert any("INCOMPLETE has evidence but no plan" in error for error in errors)

"""Regression coverage for deterministic CSV serialization."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import _write_output_csv


def test_output_uses_lf_and_exact_header(tmp_path):
    output = tmp_path / "output.csv"
    _write_output_csv(
        [
            ("case_001", "COMPLETE", "[]"),
            ("case_002", "NOT_APPLICABLE", "[]"),
        ],
        output,
    )
    data = output.read_bytes()
    assert b"\r\n" not in data
    assert data.count(b"\n") == 3
    assert data.startswith(b"case_id,deletion_status,steps_json\n")
    with open(output, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == [
        {"case_id": "case_001", "deletion_status": "COMPLETE", "steps_json": "[]"},
        {"case_id": "case_002", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"},
    ]

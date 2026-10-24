"""Reproducible evaluation for the deletion-audit agent.

Run from the repository root:  python code/evaluation/main.py

It (1) scores the 32 public sample cases against dataset/sample_output.csv
using the challenge's comparison rules, and (2) validates the root output.csv
against the output contract. Metrics are printed; the evaluation report quotes
the output of this script.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import _serialize_steps, audit_request, load_datasets  # noqa: E402
from evidence_parser import load_evidence_corpus, _parse_iso  # noqa: E402

DATASET_DIR = REPO_ROOT / "dataset"
FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
OPERATION_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
PHASE_RANK = {p: i for i, p in enumerate(PHASES)}
OPERATION_ORDER = {
    "FINDING": [
        "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    ],
    "REMEDIATION": [
        "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD",
        "REDACT_RECORD", "ANONYMIZE_RECORD",
    ],
    "VERIFICATION": [
        "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
    ],
}


def _ordered(gold_steps):
    return [{k: s[k] for k in FIELDS} for s in gold_steps]


def score_samples(datasets, corpus):
    gold = {}
    with open(DATASET_DIR / "sample_output.csv", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gold[row["case_id"]] = (row["deletion_status"], json.loads(row["steps_json"]))

    results = {}
    for req in datasets.sample_requests:
        status, steps, _ = audit_request(req, datasets, corpus)
        results[req.case_id] = (status, _serialize_steps(steps))

    status_ok = exact_ok = sequence_ok = 0
    tp = fp = fn = 0
    field_ok = field_total = 0
    mismatches = []
    for cid in sorted(gold):
        g_status, g_steps = gold[cid]
        p_status, p_json = results[cid]
        p_steps = json.loads(p_json)
        step_ok = g_status == p_status
        status_ok += step_ok

        g_tuples = [tuple(s[k] for k in FIELDS[1:]) for s in g_steps]
        p_tuples = [tuple(s[k] for k in FIELDS[1:]) for s in p_steps]
        g_count, p_count = Counter(g_tuples), Counter(p_tuples)
        hit = sum((g_count & p_count).values())
        tp += hit
        fp += sum(p_count.values()) - hit
        fn += sum(g_count.values()) - hit

        exact = step_ok and g_tuples == p_tuples
        exact_ok += exact
        sequence_ok += g_tuples == p_tuples

        ordered_gold = _ordered(g_steps)
        for index in range(max(len(ordered_gold), len(p_steps))):
            for name in FIELDS:
                field_total += 1
                field_ok += (
                    index < len(ordered_gold)
                    and index < len(p_steps)
                    and ordered_gold[index][name] == p_steps[index].get(name)
                )

        if not exact:
            mismatches.append((cid, g_status, len(g_steps), p_status, len(p_steps), step_ok))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cases": len(gold),
        "status_correct": status_ok,
        "status_accuracy": status_ok / len(gold),
        "exact_case": exact_ok,
        "sequence_accuracy": sequence_ok / len(gold),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "field_correct": field_ok, "field_total": field_total,
        "field_accuracy": field_ok / field_total if field_total else 0.0,
        "mismatches": mismatches,
    }


def validate_output(datasets, corpus):
    observations = {}
    for rec in corpus.records:
        state = rec.state
        if state == "ACTIVE" and rec.data_category not in ("DATA_FLOW", "BACKUP_ARCHIVE"):
            state = "PRESENT"
        key = (rec.evidence_id, rec.system_id, rec.resource_id, state)
        observations.setdefault(key, []).append(rec.captured_at)
    activity_time = {r["activity_id"]: _parse_iso(r["event_time"]) for r in datasets.system_activity}
    audit_time = {r["audit_id"]: _parse_iso(r["event_time"]) for r in datasets.audit_log}
    requests_by_id = {r.case_id: r for r in datasets.deletion_requests}

    with open(REPO_ROOT / "output.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    errors = []
    if [r["case_id"] for r in rows] != sorted(requests_by_id):
        errors.append("case_ids are not exactly the sorted request ids")
    for row in rows:
        cid = row["case_id"]
        req = requests_by_id.get(cid)
        if req is None:
            continue
        if row["deletion_status"] not in STATUSES:
            errors.append(f"{cid}: invalid status {row['deletion_status']}")
            continue
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            errors.append(f"{cid}: steps_json is not valid JSON")
            continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not an array")
            continue
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            errors.append(f"{cid}: NOT_APPLICABLE must use []")
        order_keys = []
        for index, step in enumerate(steps, 1):
            if set(step) != set(FIELDS):
                errors.append(f"{cid} step {index}: wrong fields")
                continue
            if step["step_no"] != index:
                errors.append(f"{cid} step {index}: step_no is {step['step_no']}")
            if step["phase"] not in PHASE_RANK:
                errors.append(f"{cid} step {index}: bad phase")
                continue
            if row["deletion_status"] == "COMPLETE" and step["phase"] != "VERIFICATION":
                errors.append(f"{cid} step {index}: COMPLETE contains non-verification step")
            if step["operation"] not in OPERATION_STATE:
                errors.append(f"{cid} step {index}: bad operation {step['operation']}")
                continue
            if step["operation"] not in OPERATION_ORDER[step["phase"]]:
                errors.append(f"{cid} step {index}: operation not allowed in phase")
                continue
            if step["state"] != OPERATION_STATE[step["operation"]]:
                errors.append(f"{cid} step {index}: state/operation mismatch")
            order_keys.append((
                PHASE_RANK[step["phase"]],
                OPERATION_ORDER[step["phase"]].index(step["operation"]),
                step["system_id"],
                step["resource_id"],
            ))
            if step["phase"] == "FINDING" or (
                row["deletion_status"] == "COMPLETE" and step["phase"] == "VERIFICATION"
            ):
                if not step["evidence_id"]:
                    errors.append(f"{cid} step {index}: missing evidence")
            elif step["evidence_id"]:
                errors.append(f"{cid} step {index}: future step carries evidence")
            eid = step["evidence_id"]
            if eid:
                key = (eid, step["system_id"], step["resource_id"], step["state"])
                captured_times = observations.get(key)
                if captured_times is not None:
                    if not any(req.requested_at <= t <= req.audit_at for t in captured_times):
                        errors.append(f"{cid} step {index}: cited observation outside request window")
                else:
                    captured = activity_time.get(eid) or audit_time.get(eid)
                    if captured is None:
                        errors.append(f"{cid} step {index}: evidence does not contain cited resource/state")
                    elif captured > req.audit_at:
                        errors.append(f"{cid} step {index}: evidence after audit_at")
                    elif captured < req.requested_at:
                        errors.append(f"{cid} step {index}: evidence before requested_at")
        if order_keys != sorted(order_keys):
            errors.append(f"{cid}: steps violate phase/operation/system/resource ordering")
        if row["deletion_status"] == "COMPLETE" and not steps:
            errors.append(f"{cid}: COMPLETE without verification steps")
    return rows, errors


def main():
    datasets = load_datasets(DATASET_DIR)
    corpus = load_evidence_corpus(DATASET_DIR)

    scores = score_samples(datasets, corpus)
    print("== SAMPLE EVALUATION (32 public cases) ==")
    for key in ("cases", "status_correct", "status_accuracy", "exact_case",
                "sequence_accuracy", "tp", "fp", "fn", "precision", "recall", "f1",
                "field_correct", "field_total", "field_accuracy"):
        print(f"{key}: {scores[key]}")
    print("\nmismatches (case, gold_status, gold_steps, pred_status, pred_steps, status_ok):")
    for item in scores["mismatches"]:
        print(" ", item)

    rows, errors = validate_output(datasets, corpus)
    steps = sum(len(json.loads(r["steps_json"])) for r in rows)
    print("\n== FULL OUTPUT VALIDATION (518 cases) ==")
    print("rows:", len(rows))
    print("status_counts:", dict(Counter(r["deletion_status"] for r in rows)))
    print("total_steps:", steps)
    print("errors:", len(errors))
    for err in errors[:50]:
        print(" ", err)

    if errors or scores["status_accuracy"] < 1.0:
        print("\nNOTE: failures above are reported as-is; they are not masked.")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())

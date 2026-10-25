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
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import (  # noqa: E402
    _serialize_steps,
    audit_request,
    load_datasets,
    resolve_identity,
)
from evidence_parser import load_evidence_corpus, _parse_iso  # noqa: E402
from policy_engine import ALLOWED_STEP_STATES  # noqa: E402

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


def _effective_state(rec):
    if rec.state == "ACTIVE" and rec.data_category not in ("DATA_FLOW", "BACKUP_ARCHIVE"):
        return "PRESENT"
    return rec.state


def _strong_identifiers(rec):
    """Identifiers strong enough to establish a subject without an anchor.

    Names/display names are weak and deliberately excluded; they are not used
    for identity resolution in the production pipeline either.
    """
    result = set()
    for value in rec.normalized_identifiers:
        if "@" in value or value.startswith("+") or value.startswith("user_"):
            result.add(value)
        elif len(value) == 64 and all(ch in "0123456789abcdef" for ch in value):
            result.add(value)
    return result


def _expected_operations(datasets, rec, audit_at, user_identifiers, state):
    """Return the operations the supplied rules require for one observation.

    This is a validator-side restatement of the allowed operation mapping; it
    does not add a policy that is absent from ``deletion_rules.csv``.
    """
    category = rec.data_category
    if category == "DATA_FLOW":
        if state == "ACTIVE":
            return {"REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"}
        if state == "DISABLED":
            return {"VERIFY_DATA_FLOW_DISABLED"}
        return set()
    if category == "BACKUP_ARCHIVE":
        if state == "ACTIVE":
            return {"REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"}
        if state == "BLOCKED":
            return {"VERIFY_RESTORE_BLOCKED"}
        return set()

    decision = datasets.policy.decide(rec, audit_at, user_identifiers)
    if decision.condition_value is False:
        if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY") and state == "ANONYMIZED":
            return {"VERIFY_RECORD_ANONYMIZED"}
        if category == "EMAIL_DELIVERY_LOG" and state == "REDACTED":
            return {"VERIFY_RECORD_REDACTED"}
        return set()
    if not decision.supported or not decision.action:
        return set()
    action = decision.action

    if action == "DELETE":
        if state == "ABSENT":
            return {"VERIFY_RECORD_ABSENT"}
        if state in ("PRESENT", "REDACTED", "ANONYMIZED", "ACTIVE"):
            return {"REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"}
        return set()
    if action == "REDACT":
        if state == "PRESENT":
            return {"REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"}
        if state == "REDACTED":
            return {"VERIFY_RECORD_REDACTED"}
        return set()
    if action == "ANONYMIZE":
        if state == "PRESENT":
            return {"REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"}
        if state == "ANONYMIZED":
            return {"VERIFY_RECORD_ANONYMIZED"}
        return set()
    if action == "RETAIN":
        if state == "PRESENT":
            return {"VERIFY_RECORD_PRESENT"}
        return set()
    return set()


def _activity_link_supports(rec, req, wants, activity_rows):
    """Whether an admissible explicit file/object link supports this citation."""
    for row in activity_rows:
        if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue
        try:
            event_time = _parse_iso(str(row.get("event_time") or ""))
        except ValueError:
            continue
        if event_time < req.requested_at or event_time > req.audit_at:
            continue
        details = str(row.get("details") or "").lower()
        if not any(len(value) >= 4 and value in details for value in wants):
            continue
        resource_id = str(row.get("resource_id") or "").strip()
        if resource_id == rec.resource_id:
            return True
        match = re.search(r"\(([^()]+\.[A-Za-z0-9]+)\)", details)
        if match and str(rec.details.get("object_key") or "").endswith("/" + match.group(1)):
            return True
    return False


def validate_output(datasets, corpus, output_path=None):
    observations = {}
    records_by_key = {}
    records_by_resource = {}
    category_by_resource = {}
    for rec in corpus.records:
        state = _effective_state(rec)
        key = (rec.evidence_id, rec.system_id, rec.resource_id, state)
        observations.setdefault(key, []).append(rec.captured_at)
        records_by_key.setdefault(key, []).append(rec)
        records_by_resource.setdefault((rec.system_id, rec.resource_id), []).append(rec)
        category_by_resource.setdefault((rec.system_id, rec.resource_id), set()).add(rec.data_category)
    activity_time = {r["activity_id"]: _parse_iso(r["event_time"]) for r in datasets.system_activity}
    audit_time = {r["audit_id"]: _parse_iso(r["event_time"]) for r in datasets.audit_log}
    requests_by_id = {r.case_id: r for r in datasets.deletion_requests}
    fingerprints = {
        cid: resolve_identity(req.email, datasets, as_of=req.audit_at).fingerprint
        for cid, req in requests_by_id.items()
    }
    known_categories = {rule.data_category for rule in datasets.policy.rules} | {"DATA_FLOW"}
    unsupported_categories = sorted(
        {rec.data_category for rec in corpus.records if rec.data_category not in known_categories}
    )
    unsupported_states = sorted(
        {rec.state for rec in corpus.records if rec.state not in ALLOWED_STEP_STATES}
    )

    with open(output_path or (REPO_ROOT / "output.csv"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    errors = []
    if unsupported_categories:
        errors.append(f"unsupported evidence categories: {unsupported_categories}")
    if unsupported_states:
        errors.append(f"unsupported evidence states: {unsupported_states}")
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
        fp = fingerprints.get(cid)
        wants = {str(i).strip().lower() for i in (fp.all_identifiers if fp else set())}
        matched_records = (
            corpus.get_records_for_identifiers(
                fp.all_identifiers, req.audit_at, not_before=req.requested_at
            )
            if fp
            else []
        )
        account_closed = False
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
                if captured_times is not None:
                    candidates = records_by_key.get(key, [])
                    direct = any(_strong_identifiers(rec) & wants for rec in candidates)
                    if not direct:
                        has_strong = any(_strong_identifiers(rec) for rec in candidates)
                        anchor = any(
                            rec.captured_at <= req.audit_at
                            and _strong_identifiers(rec) & wants
                            for rec in records_by_resource.get(
                                (step["system_id"], step["resource_id"]), []
                            )
                        )
                        if has_strong:
                            errors.append(
                                f"{cid} step {index}: cited evidence identity conflicts with the case"
                            )
                        elif not anchor and not _activity_link_supports(
                            rec=candidates[0], req=req, wants=wants,
                            activity_rows=datasets.system_activity,
                        ):
                            errors.append(
                                f"{cid} step {index}: cited evidence identity is unestablished"
                            )
            # Account closure must be evidence-backed for COMPLETE cases.
            cats = category_by_resource.get(
                (step["system_id"], step["resource_id"]), set()
            )
            if (
                step["phase"] == "VERIFICATION"
                and step["operation"] == "VERIFY_RECORD_ABSENT"
                and "USER_PROFILE" in cats
            ) or (
                step["phase"] == "VERIFICATION"
                and step["operation"] == "VERIFY_RECORD_REDACTED"
                and "ACCOUNT_TOMBSTONE" in cats
            ):
                account_closed = True
        if order_keys != sorted(order_keys):
            errors.append(f"{cid}: steps violate phase/operation/system/resource ordering")
        if row["deletion_status"] == "COMPLETE" and not steps:
            errors.append(f"{cid}: COMPLETE without verification steps")
        if row["deletion_status"] == "COMPLETE" and not account_closed:
            errors.append(f"{cid}: COMPLETE without evidence-backed account closure")
        output_steps = [s for s in steps if set(s) == set(FIELDS)]

        # Validate the deterministic required operations for every category
        # that is supported by matched evidence.  Choose the newest record per
        # (system, resource, category), matching reconstruction's state choice.
        latest_records = {}
        for rec in matched_records:
            key = (rec.system_id, rec.resource_id, rec.data_category)
            current = latest_records.get(key)
            if current is None or rec.captured_at > current.captured_at:
                latest_records[key] = rec

        required_by_resource = {}
        expected_by_resource = {}
        if row["deletion_status"] != "NOT_APPLICABLE":
            for (system_id, resource_id, category), rec in latest_records.items():
                state = _effective_state(rec)
                expected = _expected_operations(
                    datasets, rec, req.audit_at, fp.all_identifiers if fp else (), state
                )
                if not expected:
                    continue
                required_by_resource.setdefault((system_id, resource_id), {})[category] = expected
                expected_by_resource.setdefault((system_id, resource_id), set()).update(expected)

        for (system_id, resource_id), categories in required_by_resource.items():
            present_ops = {
                s["operation"]
                for s in output_steps
                if s["system_id"] == system_id and s["resource_id"] == resource_id
            }
            for category, expected in categories.items():
                missing = expected - present_ops
                if missing:
                    errors.append(
                        f"{cid}: missing {category} treatment for {resource_id}: "
                        f"{sorted(missing)}"
                    )

        matched_resources = {
            (rec.system_id, rec.resource_id) for rec in latest_records.values()
        }
        for step in output_steps:
            key = (step["system_id"], step["resource_id"])
            if key in matched_resources and step["operation"] not in expected_by_resource.get(key, set()):
                errors.append(
                    f"{cid}: unsupported {step['operation']} for {step['resource_id']}"
                )

        if row["deletion_status"] == "INCOMPLETE" and not steps and any(expected_by_resource.values()):
            errors.append(f"{cid}: INCOMPLETE has evidence but no plan")
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

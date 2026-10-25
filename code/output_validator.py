"""Contract and plan-consistency checks for output rows.

Used by main.py before output.csv is written (the run fails instead of
writing an invalid file) and by evaluation/main.py.  The checks are
structural: they do not re-derive resource states, they verify that every
plan is well-formed, internally consistent, cites only evidence available at
the case's audit time, and never assigns one account or analytics record to
two requests.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Iterable, Optional

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
OPERATION_ORDER = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"],
    "VERIFICATION": [
        "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
    ],
}
# Each finding must be followed by one of these (remediation, verification) pairs.
FINDING_PLANS = {
    "REPORT_REMAINING_RECORD": {("DELETE_RECORD", "VERIFY_RECORD_ABSENT")},
    "REPORT_EXPOSED_PII": {
        ("REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
        ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    },
    "REPORT_ACTIVE_DATA_FLOW": {("DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED")},
    "REPORT_RESTORE_RISK": {("BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED")},
}
RECORD_TREATMENTS = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"}
RECORD_VERIFICATIONS = {
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
}
ONE_OWNER_SYSTEMS = ("account_service", "analytics_platform")


def validate_rows(
    rows: list[tuple[str, str, str]],
    requests: dict,
    authorized: set[str],
    evidence_times: dict[str, datetime],
    diagnostics: Optional[dict[str, list[str]]] = None,
    scope: Optional[dict[str, set[tuple[str, str]]]] = None,
) -> list[str]:
    """Return every contract violation in ``rows`` (case_id, status, steps_json).

    ``requests`` maps case_id -> request; ``authorized`` is the set of case
    ids whose request authorizes deletion.  ``evidence_times`` maps every
    citable id (file_id, activity_id, audit_id) to the time it existed.
    ``diagnostics`` (optional) explains unresolved links for empty plans.
    ``scope`` (optional) maps case_id -> resources the pipeline linked to the
    subject; a citation outside it is reported.
    """
    errors: list[str] = []
    ids = [cid for cid, _, _ in rows]
    if ids != sorted(requests):
        errors.append("case_ids are not exactly the sorted request ids")
    if len(set(ids)) != len(ids):
        errors.append("duplicate case_id rows")

    owners: dict[tuple[str, str], set[str]] = defaultdict(set)
    for cid, status, steps_json in rows:
        req = requests.get(cid)
        if req is None:
            errors.append(f"{cid}: not a request in the input")
            continue
        if status not in STATUSES:
            errors.append(f"{cid}: invalid status {status}")
            continue
        try:
            steps = json.loads(steps_json)
        except json.JSONDecodeError:
            errors.append(f"{cid}: steps_json is not valid JSON")
            continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not an array")
            continue

        if cid not in authorized:
            if status != "NOT_APPLICABLE" or steps:
                errors.append(f"{cid}: non-deletion request must be NOT_APPLICABLE with []")
            continue
        if status == "NOT_APPLICABLE":
            errors.append(f"{cid}: deletion request reported as NOT_APPLICABLE")
            continue
        if not steps:
            why = "; ".join((diagnostics or {}).get(cid, [])) or "no diagnostic recorded"
            errors.append(f"{cid}: authorized request has an empty plan ({why})")
            continue

        errors.extend(_check_steps(cid, status, steps, req, evidence_times, scope))
        for s in steps:
            if isinstance(s, dict) and s.get("system_id") in ONE_OWNER_SYSTEMS:
                owners[(s["system_id"], s["resource_id"])].add(cid)

    for (system_id, resource_id), cases in sorted(owners.items()):
        if len(cases) > 1:
            errors.append(f"{resource_id} ({system_id}) is assigned to several cases: {sorted(cases)}")
    return errors


def _check_steps(cid, status, steps, req, evidence_times, scope) -> list[str]:
    errors: list[str] = []
    order_keys = []
    by_resource: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict) or set(step) != set(FIELDS):
            errors.append(f"{cid} step {index}: wrong fields")
            continue
        if step["step_no"] != index:
            errors.append(f"{cid} step {index}: step_no is {step['step_no']}")
        phase, operation = step["phase"], step["operation"]
        if phase not in OPERATION_ORDER or operation not in OPERATION_ORDER[phase]:
            errors.append(f"{cid} step {index}: operation {operation} not allowed in phase {phase}")
            continue
        if step["state"] != OPERATION_STATE[operation]:
            errors.append(f"{cid} step {index}: state/operation mismatch")
        order_keys.append((PHASES.index(phase), OPERATION_ORDER[phase].index(operation),
                           step["system_id"], step["resource_id"]))
        by_resource[(step["system_id"], step["resource_id"])][phase].add(operation)

        eid = step["evidence_id"]
        if status == "COMPLETE":
            if phase != "VERIFICATION":
                errors.append(f"{cid} step {index}: COMPLETE contains a {phase} step")
            if not eid:
                errors.append(f"{cid} step {index}: COMPLETE verification without evidence")
        elif phase == "FINDING":
            if not eid:
                errors.append(f"{cid} step {index}: finding without evidence")
        elif eid:
            errors.append(f"{cid} step {index}: future {phase.lower()} step carries evidence")
        if eid:
            when = evidence_times.get(eid)
            if when is None:
                errors.append(f"{cid} step {index}: unknown evidence id {eid}")
            elif when > req.audit_at:
                errors.append(f"{cid} step {index}: {eid} is later than audit_at")
            if scope is not None and (step["system_id"], step["resource_id"]) not in scope.get(cid, set()):
                errors.append(f"{cid} step {index}: cited resource {step['resource_id']} is not linked to the subject")

    if order_keys != sorted(order_keys):
        errors.append(f"{cid}: steps violate phase/operation/system/resource ordering")

    for (system_id, resource_id), phases in by_resource.items():
        found = phases.get("FINDING", set())
        fixes = phases.get("REMEDIATION", set())
        checks = phases.get("VERIFICATION", set())
        # A support ticket may hold a message (redacted) and a separate
        # attachment (deleted) captured together; nothing else may combine.
        separate = system_id == "support_platform" and fixes & RECORD_TREATMENTS == {"DELETE_RECORD", "REDACT_RECORD"}
        if len(fixes & RECORD_TREATMENTS) > 1 and not separate:
            errors.append(f"{cid}: contradictory treatments for {resource_id}: {sorted(fixes)}")
        final_states = checks & RECORD_VERIFICATIONS
        if len(final_states) > 1 and not (
            separate and final_states == {"VERIFY_RECORD_ABSENT", "VERIFY_RECORD_REDACTED"}
        ):
            errors.append(f"{cid}: contradictory final states for {resource_id}: {sorted(checks)}")
        for finding in found:
            if not any(f in fixes and v in checks for f, v in FINDING_PLANS[finding]):
                errors.append(f"{cid}: {finding} on {resource_id} lacks its remediation and verification")
        for fix in fixes:
            if not any(fix == f for plans in (FINDING_PLANS[x] for x in found) for f, _ in plans):
                errors.append(f"{cid}: {fix} on {resource_id} has no matching finding")
    return errors


def evidence_time_index(datasets) -> dict[str, datetime]:
    """When every citable id existed: manifest files, activities, audit rows."""
    from main import _parse_iso

    times = {ev.file_id: ev.captured_at for ev in datasets.evidence_files}
    times.update({r["activity_id"]: _parse_iso(r["event_time"]) for r in datasets.system_activity})
    times.update({r["audit_id"]: _parse_iso(r["event_time"]) for r in datasets.audit_log})
    return times

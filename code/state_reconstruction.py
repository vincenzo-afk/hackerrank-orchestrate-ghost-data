"""
System-state reconstruction module for Ghost Data Still Exists.

Determines the ground-truth state of each relevant resource at audit_at,
applies deletion rules, generates findings, remediation, and verification steps.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from evidence_parser import (
    EvidenceCorpus,
    ObservedRecord,
    _normalize_system_id,
    _parse_iso,
)
from policy_engine import PolicyEngine


@dataclass
class AuditStep:
    step_no: int
    phase: str          # FINDING | REMEDIATION | VERIFICATION
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str    # Non-empty for findings and COMPLETE verification; "" for future steps

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


# Operation ordering defined in problem_statement.md & AGENTS.md §6.4 & §126
FINDING_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]

REMEDIATION_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]

VERIFICATION_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]

# deletion_rules.csv grouped by required action.
DELETE_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "SUPPORT_ATTACHMENT",
}
REDACT_CATEGORIES = {
    "SUPPORT_MESSAGE",
    "ACCOUNT_TOMBSTONE",
    "EMAIL_DELIVERY_LOG",
}
ANONYMIZE_CATEGORIES = {
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
}
RETAIN_CATEGORIES = {
    "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD",
}

# When two observations of the same resource share a capture time, prefer the
# non-compliant reading so an ambiguous snapshot can never manufacture a
# COMPLETE verdict.
_STATE_PRIORITY = {
    "PRESENT": 4,
    "ACTIVE": 4,
    "REDACTED": 3,
    "ANONYMIZED": 3,
    "BLOCKED": 2,
    "DISABLED": 2,
    "ABSENT": 1,
}


@dataclass
class CaseAuditResult:
    case_id: str
    deletion_status: str  # COMPLETE | INCOMPLETE | NOT_APPLICABLE
    steps: list[AuditStep]
    findings: list[ObservedRecord] = field(default_factory=list)
    verified_clean: list[ObservedRecord] = field(default_factory=list)


def _sort_steps(steps: list[AuditStep]) -> list[AuditStep]:
    """Sort steps strictly by Phase -> Operation table rank -> system_id -> resource_id."""
    phase_rank = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

    def op_rank(phase: str, op: str) -> int:
        if phase == "FINDING":
            return FINDING_ORDER.index(op) if op in FINDING_ORDER else 99
        elif phase == "REMEDIATION":
            return REMEDIATION_ORDER.index(op) if op in REMEDIATION_ORDER else 99
        elif phase == "VERIFICATION":
            return VERIFICATION_ORDER.index(op) if op in VERIFICATION_ORDER else 99
        return 99

    sorted_steps = sorted(
        steps,
        key=lambda s: (
            phase_rank.get(s.phase, 99),
            op_rank(s.phase, s.operation),
            s.system_id,
            s.resource_id,
        ),
    )

    # Renumber step_no consecutively starting at 1
    for i, step in enumerate(sorted_steps, 1):
        step.step_no = i

    return sorted_steps


def _effective_state(rec: ObservedRecord) -> str:
    if rec.state == "ACTIVE" and rec.data_category not in ("DATA_FLOW", "BACKUP_ARCHIVE"):
        return "PRESENT"
    return rec.state


def _step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str = "",
) -> AuditStep:
    return AuditStep(
        step_no=0,
        phase=phase,
        system_id=system_id,
        resource_id=resource_id,
        operation=operation,
        state=state,
        evidence_id=evidence_id,
    )


def _records_from_activity_links(
    system_activity: list[dict],
    user_identifiers: set[str],
    audit_at: datetime,
    not_before: Optional[datetime],
    corpus: EvidenceCorpus,
) -> list[ObservedRecord]:
    """Attribute anonymous evidence records through LINK_RESOURCE_IDENTITY events.

    A data-catalog link names the subject and the resource (sometimes only by
    file name). The linked evidence file itself carries no identifier, so the
    link is what makes it retrievable. State always comes from the evidence
    record; the activity never invents a record of its own.
    """
    subject_patterns = [
        re.compile(rf"(?<![a-z0-9_]){re.escape(i)}(?![a-z0-9_])", re.I)
        for i in user_identifiers
        if len(i) >= 4
    ]
    if not subject_patterns:
        return []

    attributed: list[ObservedRecord] = []
    for row in system_activity:
        if row.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue
        details = str(row.get("details") or "")
        if not any(p.search(details) for p in subject_patterns):
            continue
        event_time = _parse_iso(str(row.get("event_time") or ""))
        if event_time > audit_at or (not_before and event_time < not_before):
            continue
        resource_id = str(row.get("resource_id") or "").strip()
        file_hint = re.search(r"\(([^()]+\.[A-Za-z0-9]+)\)", details)

        match: Optional[ObservedRecord] = None
        for rec in corpus.records:
            if rec.captured_at > audit_at:
                continue
            object_key = str(rec.details.get("object_key") or "")
            same_resource = bool(resource_id) and rec.resource_id == resource_id
            same_file = bool(file_hint) and object_key.endswith("/" + file_hint.group(1))
            if not (same_resource or same_file):
                continue
            if match is None or rec.captured_at > match.captured_at:
                match = rec
        if match is None:
            continue
        attributed.append(
            replace(
                match,
                captured_at=event_time,
                identifiers=set(match.identifiers) | set(user_identifiers),
                provenance=f"activity:{row.get('activity_id')}",
            )
        )
    return attributed


def _linked_activity_verifications(
    records: list[ObservedRecord],
    system_activity: list[dict],
    audit_at: datetime,
    not_before: Optional[datetime],
) -> list[AuditStep]:
    linked_ids = {
        str(rec.details.get("source_resource_id") or "").strip()
        for rec in records
        if str(rec.details.get("source_resource_id") or "").strip()
    }
    if not linked_ids:
        return []

    verification_for = {
        "DELETE_RECORD": ("VERIFY_RECORD_ABSENT", "ABSENT"),
        "REDACT_RECORD": ("VERIFY_RECORD_REDACTED", "REDACTED"),
        "ANONYMIZE_RECORD": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
        "DISABLE_DATA_FLOW": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        "BLOCK_RESTORE": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    }
    steps: list[AuditStep] = []
    for row in system_activity:
        resource_id = str(row.get("resource_id") or "").strip()
        event_type = str(row.get("event_type") or "")
        if resource_id not in linked_ids or event_type not in verification_for:
            continue
        event_time = _parse_iso(str(row.get("event_time") or ""))
        if event_time > audit_at or (not_before and event_time < not_before):
            continue
        operation, state = verification_for[event_type]
        steps.append(_step(
            "VERIFICATION",
            _normalize_system_id(str(row.get("target_system") or "")),
            resource_id,
            operation,
            state,
        ))
    return steps


def _load_default_policy() -> PolicyEngine:
    path = Path(__file__).resolve().parents[1] / "dataset" / "deletion_rules.csv"
    if path.exists():
        return PolicyEngine.from_csv(path)
    return PolicyEngine([])


def reconstruct_case_state(
    case_id: str,
    audit_at: datetime,
    is_deletion: bool,
    user_identifiers: set[str],
    corpus: EvidenceCorpus,
    system_activity: Optional[list[dict]] = None,
    require_evidence: bool = False,
    not_before: Optional[datetime] = None,
    policy_engine: Optional[PolicyEngine] = None,
) -> CaseAuditResult:
    """Reconstruct system state for a given case and generate the audit plan.

    ``require_evidence`` makes a COMPLETE verdict conditional on at least one
    admissible compliant observation. ``not_before`` excludes evidence captured
    before the deletion request, which describes an earlier state. The defaults
    preserve the historical behaviour for callers that only need step
    generation; the pipeline sets both so no case is declared COMPLETE on stale
    or absent evidence.
    """
    if not is_deletion:
        return CaseAuditResult(
            case_id=case_id,
            deletion_status="NOT_APPLICABLE",
            steps=[],
        )

    policy = policy_engine or _load_default_policy()

    # 1. Retrieve admissible evidence for the identifiers.
    records = corpus.get_records_for_identifiers(
        user_identifiers, audit_at, not_before=not_before
    )

    if system_activity:
        records = records + _records_from_activity_links(
            system_activity, user_identifiers, audit_at, not_before, corpus
        )

    # 2. De-duplicate multiple observations of the same (system_id, resource_id).
    # The newest admissible evidence wins; equal capture times resolve toward the
    # non-compliant reading so ambiguity cannot create a false COMPLETE.
    latest_by_resource: dict[tuple[str, str], ObservedRecord] = {}
    for r in records:
        key = (r.system_id, r.resource_id)
        current = latest_by_resource.get(key)
        if current is None:
            latest_by_resource[key] = r
        elif r.captured_at > current.captured_at:
            latest_by_resource[key] = r
        elif r.captured_at == current.captured_at:
            if _STATE_PRIORITY.get(r.state, 0) > _STATE_PRIORITY.get(current.state, 0):
                latest_by_resource[key] = r

    for key, latest in list(latest_by_resource.items()):
        confirming = [
            r for r in records
            if (r.system_id, r.resource_id) == key
            and _effective_state(r) == _effective_state(latest)
        ]
        latest_by_resource[key] = min(confirming, key=lambda r: r.captured_at)

    findings: list[AuditStep] = []
    remediations: list[AuditStep] = []
    verifications: list[AuditStep] = []
    retention_gap = False
    policy_gap = False

    # 3. Apply the supplied policy rules to each observed resource.
    for (sys_id, res_id), rec in sorted(latest_by_resource.items()):
        cat = rec.data_category
        eid = rec.evidence_id
        state = _effective_state(rec)

        if cat == "DATA_FLOW":
            # Data flows are operational mechanisms rather than a rule category.
            if state == "ACTIVE":
                findings.append(_step("FINDING", sys_id, res_id, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", eid))
                remediations.append(_step("REMEDIATION", sys_id, res_id, "DISABLE_DATA_FLOW", "DISABLED"))
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
            elif state == "DISABLED":
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", eid))
            continue

        if cat == "BACKUP_ARCHIVE":
            # The policy action is RETAIN; restore access must also be blocked.
            if state == "ACTIVE":
                findings.append(_step("FINDING", sys_id, res_id, "REPORT_RESTORE_RISK", "ACTIVE", eid))
                remediations.append(_step("REMEDIATION", sys_id, res_id, "BLOCK_RESTORE", "BLOCKED"))
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED"))
            elif state == "BLOCKED":
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", eid))
            continue

        decision = policy.decide(rec, audit_at, user_identifiers)
        if not decision.supported or (decision.rule_id and not decision.action):
            policy_gap = True
            continue
        action = decision.action

        if action == "DELETE":
            if state == "ABSENT":
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT", eid))
            elif state in ("PRESENT", "REDACTED", "ANONYMIZED", "ACTIVE"):
                findings.append(_step("FINDING", sys_id, res_id, "REPORT_REMAINING_RECORD", "PRESENT", eid))
                remediations.append(_step("REMEDIATION", sys_id, res_id, "DELETE_RECORD", "ABSENT"))
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT"))

        elif action == "REDACT":
            if state == "PRESENT":
                findings.append(_step("FINDING", sys_id, res_id, "REPORT_EXPOSED_PII", "PRESENT", eid))
                remediations.append(_step("REMEDIATION", sys_id, res_id, "REDACT_RECORD", "REDACTED"))
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_REDACTED", "REDACTED"))
            elif state == "REDACTED":
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_REDACTED", "REDACTED", eid))

        elif action == "ANONYMIZE":
            if state == "PRESENT":
                findings.append(_step("FINDING", sys_id, res_id, "REPORT_EXPOSED_PII", "PRESENT", eid))
                remediations.append(_step("REMEDIATION", sys_id, res_id, "ANONYMIZE_RECORD", "ANONYMIZED"))
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"))
            elif state == "ANONYMIZED":
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", eid))

        elif action == "RETAIN":
            if state == "PRESENT":
                verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_PRESENT", "PRESENT", eid))
            elif state == "ABSENT":
                # A policy-required retained record is missing: the case cannot
                # be proven complete, and no allowed operation can remediate it.
                retention_gap = True

    # 4. Determine overall deletion status
    if findings or retention_gap or policy_gap:
        status = "INCOMPLETE"
    elif require_evidence and not verifications:
        # No admissible evidence proves the compliant state.
        status = "INCOMPLETE"
    else:
        status = "COMPLETE"

    # 5. Assemble final steps
    if status == "INCOMPLETE":
        # Findings cite evidence; remediation and post-remediation verification
        # describe future work and therefore carry an empty evidence_id.
        for v in verifications:
            v.evidence_id = ""
        if system_activity:
            existing = {
                (v.system_id, v.resource_id, v.operation)
                for v in verifications
            }
            for v in _linked_activity_verifications(
                records, system_activity, audit_at, not_before
            ):
                key = (v.system_id, v.resource_id, v.operation)
                if key not in existing:
                    verifications.append(v)
                    existing.add(key)
        all_steps = findings + remediations + verifications
    else:
        # COMPLETE cases contain only evidence-backed verification checks.
        all_steps = verifications

    # 6. Apply mandatory step ordering
    sorted_steps = _sort_steps(all_steps)

    return CaseAuditResult(
        case_id=case_id,
        deletion_status=status,
        steps=sorted_steps,
        findings=list(latest_by_resource.values()),
    )

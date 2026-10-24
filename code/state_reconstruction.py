"""
System-state reconstruction module for Ghost Data Still Exists.

Determines the ground-truth state of each relevant resource at audit_at,
applies deletion rules, generates findings, remediation, and verification steps.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from evidence_parser import EvidenceCorpus, ObservedRecord


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


def reconstruct_case_state(
    case_id: str,
    audit_at: datetime,
    is_deletion: bool,
    user_identifiers: set[str],
    corpus: EvidenceCorpus,
    system_activity: Optional[list[dict]] = None,
) -> CaseAuditResult:
    """Reconstruct system state for a given case and generate the audit plan."""
    if not is_deletion:
        return CaseAuditResult(
            case_id=case_id,
            deletion_status="NOT_APPLICABLE",
            steps=[],
        )

    # 1. Retrieve all evidence matching the user identifiers captured <= audit_at
    records = corpus.get_records_for_identifiers(user_identifiers, audit_at)

    # 2. De-duplicate multiple observations of the same (system_id, resource_id)
    # The newest evidence captured <= audit_at represents the most current truth.
    latest_by_resource: dict[tuple[str, str], ObservedRecord] = {}
    for r in records:
        key = (r.system_id, r.resource_id)
        if key not in latest_by_resource:
            latest_by_resource[key] = r

    findings: list[AuditStep] = []
    remediations: list[AuditStep] = []
    verifications: list[AuditStep] = []

    # Track resources that have been remediated
    remaining_records: list[ObservedRecord] = []

    # 3. Apply deletion rules to each observed resource
    for (sys_id, res_id), rec in sorted(latest_by_resource.items()):
        cat = rec.data_category
        state = rec.state
        eid = rec.evidence_id

        # Rule evaluation
        if cat in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT", "MARKETING_PROFILE", "SUPPORT_ATTACHMENT"):
            if state == "PRESENT":
                # Policy requires deletion, but record still exists!
                findings.append(
                    AuditStep(
                        step_no=0,
                        phase="FINDING",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="REPORT_REMAINING_RECORD",
                        state="PRESENT",
                        evidence_id=eid,
                    )
                )
                remediations.append(
                    AuditStep(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="DELETE_RECORD",
                        state="ABSENT",
                        evidence_id="",
                    )
                )
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_ABSENT",
                        state="ABSENT",
                        evidence_id="",
                    )
                )
            elif state == "ABSENT":
                # Compliant state verified
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_ABSENT",
                        state="ABSENT",
                        evidence_id=eid,
                    )
                )

        elif cat in ("SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE"):
            if rec.has_exposed_pii or state == "PRESENT":
                # Policy requires redaction, but direct PII is exposed!
                findings.append(
                    AuditStep(
                        step_no=0,
                        phase="FINDING",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="REPORT_EXPOSED_PII",
                        state="PRESENT",
                        evidence_id=eid,
                    )
                )
                remediations.append(
                    AuditStep(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="REDACT_RECORD",
                        state="REDACTED",
                        evidence_id="",
                    )
                )
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_REDACTED",
                        state="REDACTED",
                        evidence_id="",
                    )
                )
            elif state == "REDACTED":
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_REDACTED",
                        state="REDACTED",
                        evidence_id=eid,
                    )
                )

        elif cat == "ANALYTICS_PROFILE":
            if rec.has_exposed_pii or state == "PRESENT":
                findings.append(
                    AuditStep(
                        step_no=0,
                        phase="FINDING",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="REPORT_EXPOSED_PII",
                        state="PRESENT",
                        evidence_id=eid,
                    )
                )
                remediations.append(
                    AuditStep(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="ANONYMIZE_RECORD",
                        state="ANONYMIZED",
                        evidence_id="",
                    )
                )
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_ANONYMIZED",
                        state="ANONYMIZED",
                        evidence_id="",
                    )
                )
            elif state == "ANONYMIZED":
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_ANONYMIZED",
                        state="ANONYMIZED",
                        evidence_id=eid,
                    )
                )

        elif cat == "DATA_FLOW":
            if state == "ACTIVE":
                findings.append(
                    AuditStep(
                        step_no=0,
                        phase="FINDING",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="REPORT_ACTIVE_DATA_FLOW",
                        state="ACTIVE",
                        evidence_id=eid,
                    )
                )
                remediations.append(
                    AuditStep(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="DISABLE_DATA_FLOW",
                        state="DISABLED",
                        evidence_id="",
                    )
                )
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_DATA_FLOW_DISABLED",
                        state="DISABLED",
                        evidence_id="",
                    )
                )
            elif state == "DISABLED":
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_DATA_FLOW_DISABLED",
                        state="DISABLED",
                        evidence_id=eid,
                    )
                )

        elif cat == "BACKUP_ARCHIVE":
            if state == "ACTIVE":
                findings.append(
                    AuditStep(
                        step_no=0,
                        phase="FINDING",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="REPORT_RESTORE_RISK",
                        state="ACTIVE",
                        evidence_id=eid,
                    )
                )
                remediations.append(
                    AuditStep(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="BLOCK_RESTORE",
                        state="BLOCKED",
                        evidence_id="",
                    )
                )
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RESTORE_BLOCKED",
                        state="BLOCKED",
                        evidence_id="",
                    )
                )
            elif state == "BLOCKED":
                verifications.append(
                    AuditStep(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RESTORE_BLOCKED",
                        state="BLOCKED",
                        evidence_id=eid,
                    )
                )

        elif cat == "SECURITY_AUDIT_LOG":
            # Policy requires retention: verify record present
            verifications.append(
                AuditStep(
                    step_no=0,
                    phase="VERIFICATION",
                    system_id=sys_id,
                    resource_id=res_id,
                    operation="VERIFY_RECORD_PRESENT",
                    state="PRESENT",
                    evidence_id=eid,
                )
            )

    # 4. Determine overall deletion status
    has_findings = len(findings) > 0
    status = "INCOMPLETE" if has_findings else "COMPLETE"

    # 5. Assemble final steps
    all_steps: list[AuditStep] = []
    if status == "INCOMPLETE":
        # For INCOMPLETE cases: findings (with evidence_id) + remediation (evidence_id="") + post-remediation verifications (evidence_id="")
        for v in verifications:
            v.evidence_id = ""  # Future verification checks have empty evidence_id
        all_steps = findings + remediations + verifications
    else:
        # For COMPLETE cases: ONLY verification checks proving the compliant state at audit_at, citing evidence_id
        all_steps = verifications

    # 6. Apply mandatory step ordering
    sorted_steps = _sort_steps(all_steps)

    return CaseAuditResult(
        case_id=case_id,
        deletion_status=status,
        steps=sorted_steps,
        findings=list(latest_by_resource.values()),
    )

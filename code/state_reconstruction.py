"""
System-state reconstruction module for Ghost Data Still Exists.

Determines the state of every resource in a case's audit scope at audit_at,
one physical copy at a time, applies deletion_rules.csv, and emits findings,
remediation and verification steps in canonical order.

A case is COMPLETE only when every in-scope resource has the required
treatment, proven by admissible evidence.  There is no separate account
closure gate: the account is an ordinary in-scope resource whose obligation
is proven, violated, or unresolved like any other.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from evidence_parser import (
    EvidenceCorpus,
    ObservedRecord,
    SnapshotCoverage,
    catalog_links,
    strong_identifiers,
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


# False conditional branches can have compliant evidence without any action
# being required by the supplied CSV.  Verification-only steps are allowed for
# those already-compliant states; no remediation is invented.
_FALSE_CONDITION_VERIFICATIONS = {
    "ANALYTICS_PROFILE": ("ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"),
    "PRODUCT_TELEMETRY": ("ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"),
    "EMAIL_DELIVERY_LOG": ("REDACTED", "VERIFY_RECORD_REDACTED"),
}

# Operation ordering defined in problem_statement.md & AGENTS.md §6.4
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

# When observations disagree (same capture time, or different physical
# copies), the non-compliant reading wins so an ambiguous snapshot can never
# manufacture a COMPLETE verdict.  For retained records PRESENT is also the
# reading that must survive, so the same order serves every category.
_STATE_PRIORITY = {
    "PRESENT": 4,
    "ACTIVE": 4,
    "REDACTED": 3,
    "ANONYMIZED": 3,
    "BLOCKED": 2,
    "DISABLED": 2,
    "ABSENT": 1,
}

# Final state each action must reach, for planning unobserved obligations.
_FINAL_VERIFICATION = {
    "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
    "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
    "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
    "DATA_FLOW": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    "BACKUP": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}


@dataclass
class CaseAuditResult:
    case_id: str
    deletion_status: str  # COMPLETE | INCOMPLETE | NOT_APPLICABLE
    steps: list[AuditStep]
    findings: list[ObservedRecord] = field(default_factory=list)
    verified_clean: list[ObservedRecord] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)


@dataclass
class _Scope:
    """One in-scope resource and how it entered the scope."""
    system_id: str
    resource_id: str
    category_hint: str = ""
    methods: set = field(default_factory=set)
    required: bool = False
    deletion_time: Optional[datetime] = None


def _sort_steps(steps: list[AuditStep]) -> list[AuditStep]:
    """Sort steps strictly by Phase -> Operation table rank -> system_id -> resource_id."""
    phase_rank = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
    order = {"FINDING": FINDING_ORDER, "REMEDIATION": REMEDIATION_ORDER, "VERIFICATION": VERIFICATION_ORDER}

    def op_rank(phase: str, op: str) -> int:
        ops = order.get(phase, [])
        return ops.index(op) if op in ops else 99

    sorted_steps = sorted(
        steps,
        key=lambda s: (phase_rank.get(s.phase, 99), op_rank(s.phase, s.operation), s.system_id, s.resource_id),
    )
    for i, step in enumerate(sorted_steps, 1):
        step.step_no = i
    return sorted_steps


def _effective_state(rec: ObservedRecord) -> str:
    if rec.state == "ACTIVE" and rec.data_category not in ("DATA_FLOW", "BACKUP_ARCHIVE"):
        return "PRESENT"
    return rec.state


def _step(phase, system_id, resource_id, operation, state, evidence_id="") -> AuditStep:
    return AuditStep(0, phase, system_id, resource_id, operation, state, evidence_id)


def _load_default_policy() -> PolicyEngine:
    path = Path(__file__).resolve().parents[1] / "dataset" / "deletion_rules.csv"
    if path.exists():
        return PolicyEngine.from_csv(path)
    return PolicyEngine([])


def _category_action(policy: PolicyEngine, category: str) -> str:
    """The action a category's rule names, independent of its condition."""
    if category == "DATA_FLOW":
        return "DATA_FLOW"
    if category == "BACKUP_ARCHIVE":
        return "BACKUP"
    rules = policy.rules_for(category)
    return rules[0].required_action if rules else ""


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def _scope_resources(
    ids: set[str],
    corpus: EvidenceCorpus,
    audit_at: datetime,
    links: Iterable,
) -> dict[tuple[str, str], _Scope]:
    scope: dict[tuple[str, str], _Scope] = {}
    for rec in corpus.records_with_identifiers(ids):
        if rec.observed_within(audit_at):
            entry = scope.setdefault((rec.system_id, rec.resource_id), _Scope(rec.system_id, rec.resource_id))
            entry.methods.add("identifier")
    for link in links:
        key = (link.system_id, link.resource_id)
        entry = scope.setdefault(key, _Scope(link.system_id, link.resource_id))
        entry.methods.add(link.method)
        entry.category_hint = entry.category_hint or link.category
        # The worker processed this resource for this request: its final
        # state is an obligation even when no readback was captured.
        if link.method in ("direct", "activity"):
            entry.required = True
            if link.event_time is not None and (
                entry.deletion_time is None or link.event_time > entry.deletion_time
            ):
                entry.deletion_time = link.event_time
    return scope


def case_scope(user_identifiers, corpus: EvidenceCorpus, audit_at: datetime, links) -> set[tuple[str, str]]:
    """(system, resource) pairs linked to a subject by identifiers or by the linker."""
    ids = {str(i).strip().lower() for i in user_identifiers if str(i).strip()}
    return set(_scope_resources(ids, corpus, audit_at, links))


def _catalog_scope_links(ids: set[str], corpus: EvidenceCorpus, system_activity, audit_at):
    """Catalog links for callers that do not run the global linker."""
    from activity_linker import ResourceLink

    links = corpus.catalog_links or catalog_links(system_activity or [])
    result = []
    for link in links:
        if link.event_time <= audit_at and link.identifiers & ids:
            result.append(ResourceLink(link.system_id, link.resource_id, "", "catalog", link.activity_id, link.event_time))
    return result


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

def _omission_records(
    entry: _Scope,
    category: str,
    corpus: EvidenceCorpus,
    ids: set[str],
    audit_at: datetime,
    not_before: Optional[datetime],
) -> list[ObservedRecord]:
    """ABSENT observations implied by complete snapshots that omit the resource."""
    inferred = []
    for cov in corpus.coverages:
        if cov.system_id != entry.system_id or cov.data_category != category:
            continue
        if entry.resource_id in cov.resource_ids:
            continue
        if not cov.observed_within(audit_at, not_before) or not cov.covers_subject(ids):
            continue
        if entry.deletion_time is not None and cov.observed_at < entry.deletion_time:
            # Omitted before the deletion ran: the snapshot does not describe
            # the post-deletion state.
            continue
        inferred.append(ObservedRecord(
            evidence_id=cov.evidence_id,
            file_path=Path(""),
            captured_at=cov.observed_at,
            origin="snapshot_coverage",
            system_id=entry.system_id,
            resource_id=entry.resource_id,
            data_category=category,
            state="ABSENT",
            has_exposed_pii=False,
            identifiers=set(),
            details={
                "inferred_from": cov.provenance,
                "inference_rank": 2 if cov.subject_identifiers is None else 1,
            },
            provenance=f"omission:{cov.evidence_id}:{cov.provenance}",
            physical_copy=cov.physical_copy,
            available_at=cov.available_at,
        ))
    return inferred


_DELETED_ACCOUNT_STATUSES = ("DELETED", "PURGED", "ERASED")


def _tombstone_absence(
    entry: _Scope,
    corpus: EvidenceCorpus,
    ids: set[str],
    audit_at: datetime,
    not_before: Optional[datetime],
) -> list[ObservedRecord]:
    """ABSENT readings of the subject's account from its deleted-account record.

    A tombstone naming the subject with account_status DELETED is the account
    service's own statement that the subject's account no longer exists.  It
    applies to the account the linker placed in this subject's scope (one per
    subject) and only after that account's deletion ran.
    """
    inferred = []
    for rec in corpus.records_with_identifiers(ids):
        if rec.data_category != "ACCOUNT_TOMBSTONE" or not rec.observed_within(audit_at, not_before):
            continue
        status = str(rec.details.get("account_status") or "").strip().upper()
        if status not in _DELETED_ACCOUNT_STATUSES:
            continue
        if entry.deletion_time is not None and rec.captured_at < entry.deletion_time:
            continue
        inferred.append(ObservedRecord(
            evidence_id=rec.evidence_id,
            file_path=rec.file_path,
            captured_at=rec.captured_at,
            origin="snapshot_coverage",
            system_id=entry.system_id,
            resource_id=entry.resource_id,
            data_category="USER_PROFILE",
            state="ABSENT",
            has_exposed_pii=False,
            identifiers=set(),
            details={
                "inferred_from": f"tombstone:{rec.resource_id}:account_status={status}",
                "inference_rank": 1,
            },
            provenance=f"tombstone_status:{rec.evidence_id}:{rec.resource_id}",
            physical_copy="primary",
            available_at=rec.available_at,
        ))
    return inferred


def _resolve_support_category(observations: list[ObservedRecord]) -> list[ObservedRecord]:
    """A support record is a message or an attachment; the latest reading wins.

    The latest interpretation replaces earlier ones for the same physical
    record, so earlier readbacks still describe its state under the right
    category.  Both categories are kept only when one capture shows them as
    separate components of the same record at the same time.
    """
    cats = {r.data_category for r in observations}
    if not {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"} <= cats:
        return observations
    latest = max(observations, key=lambda r: (r.captured_at, r.data_category == "SUPPORT_ATTACHMENT"))
    same_capture = {
        r.data_category for r in observations
        if r.evidence_id == latest.evidence_id and r.captured_at == latest.captured_at
    }
    if {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"} <= same_capture:
        return observations
    return [
        r if r.data_category == latest.data_category else replace(r, data_category=latest.data_category)
        for r in observations
    ]


def _latest(observations: list[ObservedRecord]) -> Optional[ObservedRecord]:
    best = None
    for rec in observations:
        if best is None or rec.captured_at > best.captured_at or (
            rec.captured_at == best.captured_at
            and _STATE_PRIORITY.get(_effective_state(rec), 0) > _STATE_PRIORITY.get(_effective_state(best), 0)
        ):
            best = rec
    return best


def _citation(
    observations: list[ObservedRecord], latest: ObservedRecord, audit_at: datetime
) -> Optional[ObservedRecord]:
    """The record to cite for the latest state.

    Candidates are the observations in the final unbroken run of that state
    whose file existed by audit_at.  A direct readback is preferred, then an
    inference from evidence that names the subject, then an omission from a
    full copy; within each, the earliest.
    """
    state = _effective_state(latest)
    run: list[ObservedRecord] = []
    run_start = latest.captured_at
    for rec in sorted(observations, key=lambda r: (r.captured_at, r.evidence_id), reverse=True):
        if rec.captured_at > latest.captured_at:
            continue
        if _effective_state(rec) == state:
            run.append(rec)
            run_start = min(run_start, rec.captured_at)
        elif rec.captured_at < run_start:
            break
    citable = [r for r in run if r.citable(audit_at)]
    if not citable:
        return None
    return min(citable, key=lambda r: (r.details.get("inference_rank", 0), r.captured_at, r.evidence_id))


def _resource_state(observations: list[ObservedRecord], audit_at: datetime):
    """Latest state per physical copy, then the worst copy for the resource.

    Returns (state, policy_record, citation_record_or_None), or None when no
    copy has an interpretable observation.
    """
    by_copy: dict[str, list[ObservedRecord]] = {}
    for rec in observations:
        if _effective_state(rec) in _STATE_PRIORITY:
            by_copy.setdefault(rec.physical_copy, []).append(rec)
    chosen = None
    for copy, recs in sorted(by_copy.items()):
        latest = _latest(recs)
        rank = (_STATE_PRIORITY[_effective_state(latest)], copy == "primary", latest.captured_at)
        if chosen is None or rank > chosen[0]:
            chosen = (rank, latest, _citation(recs, latest, audit_at))
    if chosen is None:
        return None
    _, latest, cite = chosen
    return _effective_state(latest), latest, cite


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

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
    require_account_closure: Optional[bool] = None,
    links: Optional[list] = None,
) -> CaseAuditResult:
    """Reconstruct system state for a case and generate the audit plan.

    ``links`` are the resources the global activity linker placed in this
    case's scope (identifier-free accounts, anonymized analytics, catalog
    links).  Without them only identifier-linked resources and catalog links
    are considered.  ``require_evidence`` makes COMPLETE conditional on at
    least one admissible compliant observation.  ``not_before`` excludes
    observations from before the deletion request.

    ``require_account_closure`` is accepted for backward compatibility and
    ignored: the account is an ordinary obligation, not a separate gate.
    """
    if not is_deletion:
        return CaseAuditResult(case_id=case_id, deletion_status="NOT_APPLICABLE", steps=[])

    policy = policy_engine or _load_default_policy()
    ids = {str(i).strip().lower() for i in user_identifiers if str(i).strip()}
    strong = strong_identifiers(ids)
    if links is None:
        links = _catalog_scope_links(strong, corpus, system_activity, audit_at)
    scope = _scope_resources(ids, corpus, audit_at, links)

    findings: list[AuditStep] = []
    remediations: list[AuditStep] = []
    verifications: list[AuditStep] = []
    evidence_gaps: list[str] = []
    gap = False
    considered: list[ObservedRecord] = []

    for key in sorted(scope):
        entry = scope[key]
        sys_id, res_id = key
        observed = [
            rec for rec in corpus.records_for(sys_id, res_id)
            if rec.observed_within(audit_at, not_before)
        ]
        categories = {rec.data_category for rec in observed} or (
            {entry.category_hint} if entry.category_hint else set()
        )
        for category in sorted(categories):
            if _category_action(policy, category) == "DELETE":
                observed += _omission_records(entry, category, corpus, strong, audit_at, not_before)
        if sys_id == "account_service" and "USER_PROFILE" in categories and entry.required:
            observed += _tombstone_absence(entry, corpus, strong, audit_at, not_before)
        if sys_id == "support_platform":
            observed = _resolve_support_category(observed)

        if not observed:
            if not entry.required:
                continue
            # The worker touched this resource for this request but no
            # admissible evidence shows its state: an unresolved obligation.
            gap = True
            evidence_gaps.append(f"no admissible state evidence for {entry.category_hint or 'resource'} {res_id}")
            _plan_final_state(policy, entry.category_hint, _Stub(entry.category_hint), sys_id, res_id,
                              audit_at, ids, verifications)
            continue

        by_category: dict[str, list[ObservedRecord]] = {}
        for rec in observed:
            by_category.setdefault(rec.data_category, []).append(rec)
        for cat, recs in sorted(by_category.items()):
            resolved = _resource_state(recs, audit_at)
            if resolved is None:
                gap = True
                evidence_gaps.append(f"state of {cat}/{res_id} is not interpretable")
                continue
            state, policy_rec, citation_rec = resolved
            considered.append(policy_rec)
            if citation_rec is None:
                # The state is known only from a file published after
                # audit_at: it cannot be cited, so it proves nothing yet.
                gap = True
                evidence_gaps.append(f"{cat}/{res_id} state {state} is not citable at audit_at")
                _plan_final_state(policy, cat, policy_rec, sys_id, res_id, audit_at, ids, verifications)
                continue
            outcome = _apply_policy(
                policy, cat, sys_id, res_id, state, policy_rec, citation_rec.evidence_id,
                audit_at, ids, findings, remediations, verifications, evidence_gaps,
            )
            gap = gap or outcome

    if findings or gap:
        status = "INCOMPLETE"
    elif require_evidence and not any(v.evidence_id for v in verifications):
        status = "INCOMPLETE"
        evidence_gaps.append("no admissible compliant verification")
    elif not verifications:
        status = "INCOMPLETE" if require_evidence else "COMPLETE"
    else:
        status = "COMPLETE"

    if status == "INCOMPLETE":
        # Findings cite evidence; remediation and post-remediation checks
        # describe future work and carry an empty evidence_id.
        for v in verifications:
            v.evidence_id = ""
        all_steps = findings + remediations + verifications
    else:
        all_steps = verifications

    return CaseAuditResult(
        case_id=case_id,
        deletion_status=status,
        steps=_sort_steps(_dedupe(all_steps)),
        findings=considered,
        evidence_gaps=evidence_gaps,
    )


class _Stub:
    """Minimal record for asking the policy about an unobserved resource."""

    def __init__(self, category: str):
        self.data_category = category
        self.details: dict = {}
        self.state = ""
        self.identifiers: set = set()


def _plan_final_state(policy, category, record, sys_id, res_id, audit_at, ids, verifications) -> None:
    """Future check of the state an unproven resource must end in."""
    action = _category_action(policy, category)
    if action not in ("DATA_FLOW", "BACKUP"):
        # Conditional rules fall back to their conservative action.
        action = policy.decide(record, audit_at, ids).action or action
    if action in _FINAL_VERIFICATION:
        operation, final_state = _FINAL_VERIFICATION[action]
        verifications.append(_step("VERIFICATION", sys_id, res_id, operation, final_state))


def _dedupe(steps: list[AuditStep]) -> list[AuditStep]:
    seen = set()
    result = []
    for s in steps:
        key = (s.phase, s.system_id, s.resource_id, s.operation, s.state)
        if key in seen:
            continue
        seen.add(key)
        result.append(s)
    return result


def _apply_policy(
    policy, cat, sys_id, res_id, state, policy_rec, eid, audit_at, ids,
    findings, remediations, verifications, evidence_gaps,
) -> bool:
    """Append the steps one resource/category requires; return True on a gap."""
    if cat == "DATA_FLOW":
        # Data flows are operational mechanisms rather than a rule category.
        if state == "ACTIVE":
            findings.append(_step("FINDING", sys_id, res_id, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", eid))
            remediations.append(_step("REMEDIATION", sys_id, res_id, "DISABLE_DATA_FLOW", "DISABLED"))
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
        elif state == "DISABLED":
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", eid))
        elif state != "ABSENT":
            evidence_gaps.append(f"unsupported DATA_FLOW state {state!r} for {res_id}")
            return True
        return False

    if cat == "BACKUP_ARCHIVE":
        # The policy action is RETAIN; restore access must also be blocked.
        if state == "ACTIVE":
            findings.append(_step("FINDING", sys_id, res_id, "REPORT_RESTORE_RISK", "ACTIVE", eid))
            remediations.append(_step("REMEDIATION", sys_id, res_id, "BLOCK_RESTORE", "BLOCKED"))
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED"))
        elif state == "BLOCKED":
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", eid))
        elif state == "ABSENT":
            evidence_gaps.append(f"required backup archive is not present: {res_id}")
            return True
        else:
            evidence_gaps.append(f"unsupported BACKUP_ARCHIVE state {state!r} for {res_id}")
            return True
        return False

    decision = policy.decide(policy_rec, audit_at, ids)
    if decision.condition_value is False:
        verification = _FALSE_CONDITION_VERIFICATIONS.get(cat)
        if verification is not None and state == verification[0]:
            expected_state, operation = verification
            verifications.append(_step("VERIFICATION", sys_id, res_id, operation, expected_state, eid))
            return False
        evidence_gaps.append(f"policy gap for {cat}/{res_id}: {decision.reason}")
        return True
    if not decision.supported or (decision.rule_id and not decision.action):
        evidence_gaps.append(f"policy gap for {cat}/{res_id}: {decision.reason}")
        return True
    action = decision.action

    if action == "DELETE":
        if state == "ABSENT":
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT", eid))
        else:
            findings.append(_step("FINDING", sys_id, res_id, "REPORT_REMAINING_RECORD", "PRESENT", eid))
            remediations.append(_step("REMEDIATION", sys_id, res_id, "DELETE_RECORD", "ABSENT"))
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ABSENT", "ABSENT"))
        return False

    if action == "REDACT":
        if state == "PRESENT":
            findings.append(_step("FINDING", sys_id, res_id, "REPORT_EXPOSED_PII", "PRESENT", eid))
            remediations.append(_step("REMEDIATION", sys_id, res_id, "REDACT_RECORD", "REDACTED"))
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_REDACTED", "REDACTED"))
        elif state == "REDACTED":
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_REDACTED", "REDACTED", eid))
        elif state != "ABSENT":
            evidence_gaps.append(f"unsupported REDACT state {state!r} for {res_id}")
            return True
        return False

    if action == "ANONYMIZE":
        if state == "PRESENT":
            findings.append(_step("FINDING", sys_id, res_id, "REPORT_EXPOSED_PII", "PRESENT", eid))
            remediations.append(_step("REMEDIATION", sys_id, res_id, "ANONYMIZE_RECORD", "ANONYMIZED"))
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"))
        elif state == "ANONYMIZED":
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", eid))
        elif state != "ABSENT":
            evidence_gaps.append(f"unsupported ANONYMIZE state {state!r} for {res_id}")
            return True
        return False

    if action == "RETAIN":
        if state == "PRESENT":
            verifications.append(_step("VERIFICATION", sys_id, res_id, "VERIFY_RECORD_PRESENT", "PRESENT", eid))
            return False
        if state == "ABSENT":
            # A policy-required retained record is missing: the case cannot
            # be proven complete, and no allowed operation can remediate it.
            evidence_gaps.append(f"required retained record is not present: {res_id}")
        else:
            evidence_gaps.append(f"unsupported RETAIN state {state!r} for {res_id}")
        return True

    evidence_gaps.append(f"unsupported policy action {action!r} for {res_id}")
    return True

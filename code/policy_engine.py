"""Traceable evaluation of the supplied deletion-rules policy.

The CSV conditions are short English predicates.  This module maps only the
documented conditions to explicit, bounded predicates; it never treats an
unknown or unsupported condition as true.  When a condition field is absent,
the conservative action that the previous pipeline used for that category is
retained and recorded as ``condition_value=None``.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

ALLOWED_ACTIONS = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}
ALLOWED_STEP_STATES = {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}
SUPPORTED_CONDITIONS = {
    "always",
    "conversation contains shared customer, agent, or order context that must be retained",
    "attachment belongs only to the deletion subject",
    "record is still attributable to a user",
    "log contains a user email address",
    "record is within the supplied retention period",
    "a supplied legal hold is active",
    "restore access can be blocked",
    "account is deleted and only a stable internal user_id is needed to preserve references to retained records",
}

# An explicit false condition means the supplied rule does not prescribe an
# action.  The CSV has no inverse-action column, so the reconstruction layer
# treats this as a policy gap rather than inventing DELETE/REDACT/ANONYMIZE.
#
# When the evidence does not expose the condition field, only non-destructive
# treatments may be used.  Support-attachment ownership is intentionally absent:
# an unknown owner must never cause deletion of possibly shared content.
_UNKNOWN_ACTIONS = {
    "SUPPORT_MESSAGE": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "ACCOUNT_TOMBSTONE": "REDACT",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "BACKUP_ARCHIVE": "RETAIN",
}


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    rule_id: str
    condition: str
    condition_value: Optional[bool]
    reason: str
    category: str
    supported: bool = True


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1", "yes", "y", "active", "enabled"):
            return True
        if low in ("false", "0", "no", "n", "inactive", "disabled"):
            return False
    return None


def _emails_phones_user_ids(identifiers: Iterable[str]) -> set[str]:
    result = set()
    for raw in identifiers:
        text = str(raw).strip()
        if not text:
            continue
        low = text.lower()
        if "@" in text or text.startswith("+") or low.startswith("user_"):
            result.add(low)
    return result


class PolicyEngine:
    """Bounded condition evaluator for ``deletion_rules.csv``."""

    def __init__(self, rules: Iterable[PolicyRule]):
        self.rules = tuple(rules)
        self._by_category: dict[str, list[PolicyRule]] = {}
        for rule in self.rules:
            self._by_category.setdefault(rule.data_category, []).append(rule)

    @classmethod
    def from_csv(cls, path: Path) -> "PolicyEngine":
        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        rules = []
        for row in rows:
            action = (row.get("required_action") or "").strip().upper()
            if action not in ALLOWED_ACTIONS:
                raise ValueError(f"Unsupported policy action {action!r} in {row.get('rule_id')}")
            rules.append(
                PolicyRule(
                    rule_id=(row.get("rule_id") or "").strip(),
                    data_category=(row.get("data_category") or "").strip().upper(),
                    condition=(row.get("condition") or "").strip(),
                    required_action=action,
                )
            )
        return cls(rules)

    @classmethod
    def from_rows(cls, rows: Iterable[dict[str, Any]]) -> "PolicyEngine":
        rules = []
        for row in rows:
            action = str(row.get("required_action") or "").strip().upper()
            if action not in ALLOWED_ACTIONS:
                raise ValueError(f"Unsupported policy action {action!r}")
            rules.append(
                PolicyRule(
                    rule_id=str(row.get("rule_id") or "").strip(),
                    data_category=str(row.get("data_category") or "").strip().upper(),
                    condition=str(row.get("condition") or "").strip(),
                    required_action=action,
                )
            )
        return cls(rules)

    def rules_for(self, category: str) -> tuple[PolicyRule, ...]:
        return tuple(self._by_category.get(category, ()))

    def _evaluate(self, rule: PolicyRule, record: Any, audit_at: datetime, user_identifiers: set[str]) -> Optional[bool]:
        condition = rule.condition.strip().lower()
        details = getattr(record, "details", {}) or {}
        state = getattr(record, "state", "")
        category = rule.data_category

        if condition == "always":
            return True

        if condition == "conversation contains shared customer, agent, or order context that must be retained":
            for key in ("shared_context", "shared", "shared_with_others"):
                if key in details:
                    val = _as_bool(details.get(key))
                    if val is not None:
                        return val
            return None

        if condition == "attachment belongs only to the deletion subject":
            for key in ("belongs_only_to_subject", "subject_only"):
                if key in details:
                    val = _as_bool(details.get(key))
                    if val is not None:
                        return val
            if "shared_context" in details:
                shared = _as_bool(details.get("shared_context"))
                if shared is not None:
                    return not shared
            strong = _emails_phones_user_ids(getattr(record, "identifiers", set()))
            if strong:
                return strong.issubset(user_identifiers)
            return None

        if condition == "record is still attributable to a user":
            if state == "ANONYMIZED":
                return False
            if state == "PRESENT":
                return True
            if details.get("user_id") or details.get("email") or details.get("phone") or details.get("email_hash"):
                return True
            return None

        if condition == "log contains a user email address":
            keys = ("email", "customer_email", "owner_email", "requester_email")
            if any(str(details.get(k) or "").strip() for k in keys):
                return True
            if any(k in details for k in keys):
                return False
            return None

        if condition == "record is within the supplied retention period":
            retained = _parse_dt(details.get("retention_until") or details.get("retained_until"))
            if retained is None:
                return None
            return retained >= audit_at

        if condition == "a supplied legal hold is active":
            retained = _parse_dt(details.get("retained_until") or details.get("retention_until"))
            if retained is not None:
                return retained >= audit_at
            for key in ("active", "hold_active", "hold_status"):
                if key in details:
                    val = _as_bool(details.get(key))
                    if val is not None:
                        return val
            return None

        if condition == "restore access can be blocked":
            if "restore_allowed" in details:
                allowed = _as_bool(details.get("restore_allowed"))
                if allowed is not None:
                    return not allowed
            if state == "BLOCKED":
                return True
            if state == "ACTIVE":
                return False
            return None

        if condition.startswith("account is deleted and only a stable internal user_id"):
            status = str(details.get("account_status") or "").strip().upper()
            if status:
                return status in ("DELETED", "PURGED", "ERASED")
            if state in ("REDACTED", "PRESENT"):
                return None
            return None

        return None

    def decide(self, record: Any, audit_at: datetime, user_identifiers: Iterable[str] = ()) -> PolicyDecision:
        category = str(getattr(record, "data_category", "") or "").upper()
        rules = self.rules_for(category)
        user_ids = {str(value).strip().lower() for value in user_identifiers if str(value).strip()}
        if not rules:
            # DATA_FLOW and BACKUP_ARCHIVE are handled before this layer.  Any
            # other category without a supplied rule must fail closed rather
            # than disappear from the audit.
            return PolicyDecision(
                "", "", "", None, "no supplied policy rule", category,
                supported=False,
            )

        for rule in rules:
            if rule.condition.strip().lower() not in SUPPORTED_CONDITIONS:
                return PolicyDecision(
                    "", rule.rule_id, rule.condition, None,
                    "unsupported policy condition: failing closed", category,
                    supported=False,
                )
            value = self._evaluate(rule, record, audit_at, user_ids)
            if value is True:
                return PolicyDecision(
                    rule.required_action, rule.rule_id, rule.condition, True,
                    "documented condition is true", category,
                )
            if value is None:
                action = _UNKNOWN_ACTIONS.get(category, "")
                return PolicyDecision(
                    action, rule.rule_id, rule.condition, None,
                    "condition field is absent or ambiguous; no action unless safely supported",
                    category,
                )
            # Explicit false: the CSV does not supply an inverse action.
            # Do not invent remediation; leave the action empty so the
            # reconstruction layer records a policy gap.
            return PolicyDecision(
                "", rule.rule_id, rule.condition, False,
                "documented condition is false; no supplied action; policy gap",
                category,
            )

        return PolicyDecision("", "", "", None, "no matching policy rule", category)

"""
Evidence parser and normalized evidence model for Ghost Data Still Exists.
All file paths resolved relative to repository root.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

import pypdf

from media_cache import load_media_cache, observations_for

# ---------------------------------------------------------------------------
# Normalized Evidence Data Model
# ---------------------------------------------------------------------------

class EvidenceParseError(RuntimeError):
    """A structured evidence item could not be interpreted safely."""

@dataclass
class ObservedRecord:
    evidence_id: str
    file_path: Path
    captured_at: datetime  # observed_at: the time the state was true
    origin: str
    system_id: str
    resource_id: str
    data_category: str
    state: str             # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    has_exposed_pii: bool  # True if direct PII remains where policy requires redaction/anonymization
    identifiers: set[str]  # emails, user_ids, phones, hashes found in the record
    details: dict[str, Any] = field(default_factory=dict)
    provenance: str = ""
    # Which stored copy was read: primary, or a named replica table.
    physical_copy: str = "primary"
    # When the evidence file itself became available (manifest captured_at).
    # A state observed before audit_at is still inadmissible if the file
    # that reports it was produced after audit_at.
    available_at: Optional[datetime] = None

    def __post_init__(self):
        # Normalize identifiers to lowercase for robust lookup while preserving originals
        self.normalized_identifiers: set[str] = {i.strip().lower() for i in self.identifiers if i and isinstance(i, str)}
        if self.available_at is None:
            self.available_at = self.captured_at

    @property
    def observed_at(self) -> datetime:
        return self.captured_at

    def observed_within(self, audit_at: datetime, not_before: Optional[datetime] = None) -> bool:
        """The state this record describes held at or before audit_at."""
        if self.captured_at > audit_at:
            return False
        return not_before is None or self.captured_at >= not_before

    def citable(self, audit_at: datetime) -> bool:
        """The file reporting the state existed by audit_at, so it can be cited."""
        return self.available_at <= audit_at

    def admissible(self, audit_at: datetime, not_before: Optional[datetime] = None) -> bool:
        """Both the state time and the file availability must precede audit_at."""
        return self.observed_within(audit_at, not_before) and self.citable(audit_at)


@dataclass(frozen=True)
class SnapshotCoverage:
    """What a snapshot is complete for, so an omitted resource can be inferred absent.

    ``subject_identifiers`` is None for a full physical copy (every subject),
    otherwise the strong identifiers of the subjects the capture was scoped to.
    """
    evidence_id: str
    system_id: str
    data_category: str
    physical_copy: str
    observed_at: datetime
    available_at: datetime
    resource_ids: frozenset
    subject_identifiers: Optional[frozenset]
    provenance: str

    def covers_subject(self, identifiers: set[str]) -> bool:
        if self.subject_identifiers is None:
            return True
        return bool(self.subject_identifiers & identifiers)

    def observed_within(self, audit_at: datetime, not_before: Optional[datetime] = None) -> bool:
        if self.observed_at > audit_at:
            return False
        return not_before is None or self.observed_at >= not_before

    def admissible(self, audit_at: datetime, not_before: Optional[datetime] = None) -> bool:
        return self.observed_within(audit_at, not_before) and self.available_at <= audit_at


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def is_strong_identifier(value: str) -> bool:
    """Emails, phones, user references and email hashes identify a subject; names do not."""
    v = str(value).strip().lower()
    return bool(v) and ("@" in v or v.startswith("+") or v.startswith("user_") or bool(_HEX64.match(v)))


def strong_identifiers(values) -> set[str]:
    return {str(v).strip().lower() for v in values if is_strong_identifier(v)}


def _parse_iso(ts: str) -> datetime:
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_system_id(sys_id: str) -> str:
    s = sys_id.strip().lower()
    mapping = {
        "account_service": "account_service",
        "customer_account_service": "account_service",
        "profile_service": "account_service",
        "search_service": "search_service",
        "search_index_service": "search_service",
        "analytics_platform": "analytics_platform",
        "analytics_identity_store": "analytics_platform",
        "support_platform": "support_platform",
        "support_replica": "support_platform",
        "support_storage_service": "support_platform",
        "integration_service": "integration_service",
        "connector_service": "integration_service",
        "backup_service": "backup_service",
        "backup_restore_service": "backup_service",
        "security_service": "security_service",
        "security_audit_service": "security_service",
        "identity_service": "identity_service",
        "export_service": "export_service",
        "customer_export_service": "export_service",
        "user_export_store": "export_service",
        "marketing_platform": "marketing_platform",
        "legal_service": "legal_service",
        "cache_service": "cache_service",
        "notification_service": "email_delivery_service",
        "downstream_delivery_service": "email_delivery_service",
        "email_delivery_service": "email_delivery_service",
        "deletion_worker": "deletion_worker",
    }
    if s in mapping:
        return mapping[s]
    # Generic fallbacks for exporter names such as "central_observability_export".
    for needle, target in (
        ("account", "account_service"),
        ("profile", "account_service"),
        ("search", "search_service"),
        ("analytics", "analytics_platform"),
        ("support", "support_platform"),
        ("integration", "integration_service"),
        ("connector", "integration_service"),
        ("backup", "backup_service"),
        ("security", "security_service"),
        ("audit", "security_service"),
        ("identity", "identity_service"),
        ("export", "export_service"),
        ("marketing", "marketing_platform"),
        ("legal", "legal_service"),
        ("cache", "cache_service"),
        ("delivery", "email_delivery_service"),
    ):
        if needle in s:
            return target
    return s


# Canonical data categories and the raw result/status tokens used in evidence.
_ALL_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE",
}

_RESULT_STATES = {
    "FOUND": "PRESENT",
    "HIT": "PRESENT",
    "IDENTIFIABLE": "PRESENT",
    "PRESENT": "PRESENT",
    "NOT_FOUND": "ABSENT",
    "NOTFOUND": "ABSENT",
    "MISSING": "ABSENT",
    "DELETED": "ABSENT",
    "ANONYMIZED": "ANONYMIZED",
    "REDACTED": "REDACTED",
    "ACTIVE": "ACTIVE",
    "ENABLED": "ACTIVE",
    "DISABLED": "DISABLED",
    "BLOCKED": "BLOCKED",
}
_ACCOUNT_STATUSES = {"ACTIVE", "DELETION_PENDING", "DELETED", "PURGED", "ERASED"}

# Identifier-bearing fields found across SQL, JSON, log, PDF and image evidence.
_ID_FIELDS = (
    "subject_reference",
    "customer_reference",
    "user_id",
    "subject_ref",
    "lookup_value",
    "lookup_key",
    "match_key",
    "subject_key",
    "scan_key",
    "owner_key",
    "correlation_key",
    "email",
    "customer_email",
    "owner_email",
    "requester_email",
    "uploaded_by",
    "subject_selector",
    "matched_value",
    "phone",
    "owner_phone",
    "requester_phone",
    "display_name",
    "full_name",
    "requester_name",
    "name",
    "email_hash",
    "query",
)


def _clean_value(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    if text.lower() in ("null", "none", "n/a"):
        return ""
    return text


def _observation_time(item: dict[str, Any], default: datetime) -> datetime:
    for key in ("observed_at", "captured_at", "recorded_at"):
        value = _clean_value(item.get(key))
        if value:
            return _parse_iso(value)
    return default


def _collect_ids(*sources: Any) -> set[str]:
    """Collect non-empty identifier values from dicts and nested ``document`` blobs."""
    ids: set[str] = set()
    for src in sources:
        if not isinstance(src, dict):
            continue
        for key in _ID_FIELDS:
            val = _clean_value(src.get(key))
            if val:
                ids.add(val)
        doc = src.get("document")
        if isinstance(doc, dict):
            ids.update(_collect_ids(doc))
    return ids


def _has_direct_ids(item: dict[str, Any]) -> bool:
    return any(
        _clean_value(item.get(k))
        for k in ("customer_reference", "user_id", "subject_reference", "email",
                  "customer_email", "owner_email", "requester_email", "phone",
                  "owner_phone", "requester_phone", "email_hash")
    )


# Direct identifiers that a REDACT rule must strip. A stable user reference is
# explicitly allowed to remain, so it does not count here.
_DIRECT_PII_FIELDS = (
    "name", "full_name", "display_name",
    "email", "customer_email", "owner_email", "requester_email",
    "phone", "owner_phone", "requester_phone",
    "email_hash",
)


def _has_direct_pii(item: dict[str, Any]) -> bool:
    return any(_clean_value(item.get(k)) for k in _DIRECT_PII_FIELDS)


_MESSAGE_BODY_FIELDS = ("message_text", "message", "message_excerpt", "body", "content")


def _has_message_body(item: dict[str, Any]) -> bool:
    """Whether the record body (or its identifying fields) was actually read."""
    return any(k in item for k in _MESSAGE_BODY_FIELDS + _DIRECT_PII_FIELDS)


def _restore_state(item: dict[str, Any]) -> str:
    """Restore authorization fields → BLOCKED / ACTIVE, or "" when not stated."""
    decision = _clean_value(item.get("decision")).lower()
    if decision in ("deny", "denied", "block", "blocked"):
        return "BLOCKED"
    if decision in ("allow", "allowed", "grant", "granted"):
        return "ACTIVE"
    if _clean_value(item.get("deletion_block")).lower() == "true":
        return "BLOCKED"
    allowed = _clean_value(item.get("restore_allowed")).lower()
    if allowed in ("true", "1", "false", "0"):
        return "ACTIVE" if allowed in ("true", "1") else "BLOCKED"
    if _clean_value(item.get("deletion_block")).lower() == "false":
        return "ACTIVE"
    if _clean_value(item.get("eligible")).lower() == "true":
        return "ACTIVE"
    return ""


_ATTACHMENT_EVENTS = ("attachment_pii_scan", "attachment_scan_completed")


def _is_attachment_event(item: dict[str, Any]) -> bool:
    event = _clean_value(item.get("event")).lower()
    if event in _ATTACHMENT_EVENTS:
        return True
    payload = _clean_value(item.get("file")) or _clean_value(item.get("object_key"))
    return "attachment" in event and bool(payload)


def _category_from_hint(hint: str, resource_id: str = "") -> str | None:
    """Map a record_type/collection/table name onto a canonical data category."""
    h = hint.strip().lower()
    r = resource_id.strip().lower()
    if h.upper() in _ALL_CATEGORIES:
        return h.upper()
    if "tombstone" in h or "deleted_customer" in h or r.startswith("tombstone_"):
        return "ACCOUNT_TOMBSTONE"
    if "attachment" in h or r.startswith("attachment_"):
        return "SUPPORT_ATTACHMENT"
    if "legal" in h or r.startswith("legal_"):
        return "LEGAL_HOLD_RECORD"
    if "audit" in h or "security" in h or r.startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG"
    if "support" in h or r.startswith("support_"):
        return "SUPPORT_MESSAGE"
    if "analytics" in h or r.startswith("analytics_"):
        return "ANALYTICS_PROFILE"
    if "consent" in h or "marketing" in h:
        return "MARKETING_PROFILE"
    if "search" in h or r.startswith("search_"):
        return "SEARCH_INDEX_ENTRY"
    if "cache" in h or r.startswith("cache_"):
        return "CACHE_ENTRY"
    if "telemetry" in h or r.startswith("telemetry_"):
        return "PRODUCT_TELEMETRY"
    if "delivery" in h or "email_log" in h or r.startswith("email_delivery_"):
        return "EMAIL_DELIVERY_LOG"
    if "backup" in h or r.startswith("backup_"):
        return "BACKUP_ARCHIVE"
    if "connector" in h or "data_flow" in h or r.startswith("data_flow_"):
        return "DATA_FLOW"
    if "export" in h or r.startswith("export_"):
        return "USER_EXPORT"
    if "secondary" in h or "identifier" in h:
        return "SECONDARY_IDENTIFIER"
    if "profile" in h or "account" in h or r.startswith("account_"):
        return "USER_PROFILE"
    return None


def _category_for(
    system_id: str,
    resource_id: str,
    *hints: str,
) -> str:
    for hint in hints:
        if hint:
            cat = _category_from_hint(str(hint), resource_id)
            if cat:
                return cat
    cat = _category_from_hint(system_id, resource_id)
    # An unmapped hint must not become a deletable account profile.  The
    # policy layer will treat this sentinel as an unsupported category and
    # fail the case closed.
    return cat or "UNKNOWN_CATEGORY"


def _state_for_record(
    category: str,
    item: dict[str, Any],
    raw_result: str = "",
) -> str:
    """Derive the observed state for a record from its fields.

    An explicit NOT_FOUND/DELETED/MISSING result is authoritative absence.  It
    must not be rewritten into a compliant-looking PRESENT, REDACTED, or
    ANONYMIZED state by a category-specific default.
    """
    result = _clean_value(raw_result).upper()
    state = _RESULT_STATES.get(result, "")

    if result and not state:
        return "UNKNOWN"

    if state == "ABSENT":
        return "ABSENT"

    if category == "USER_PROFILE":
        status = _clean_value(item.get("account_status")).upper()
        if status:
            if status in ("DELETED", "PURGED", "ERASED"):
                return "ABSENT"
            if status not in _ACCOUNT_STATUSES:
                return "UNKNOWN"
        return state or "PRESENT"

    if category == "SUPPORT_MESSAGE":
        # Subject-owned stable references (user_id) are allowed to remain;
        # only direct identifiers trigger a redaction requirement.
        if state == "REDACTED":
            return "REDACTED"
        if result == "IDENTIFIABLE":
            # The lookup itself reports the record as identifiable, wherever
            # the identifier is stored (lookup_value, subject_reference, ...).
            return "PRESENT"
        if _has_direct_pii(item):
            return "PRESENT"
        if _text_ids(item):
            return "PRESENT"
        if not _has_message_body(item):
            # Without the record body, missing identifiers prove nothing.
            return "UNKNOWN"
        return "REDACTED"

    if category == "SUPPORT_ATTACHMENT":
        return state or "PRESENT"

    if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
        if state == "ANONYMIZED":
            return "ANONYMIZED"
        attributable = any(
            _clean_value(item.get(k))
            for k in ("user_id", "customer_reference", "customer_email",
                      "owner_email", "email", "phone", "email_hash")
        )
        return "PRESENT" if attributable else "ANONYMIZED"

    if category == "ACCOUNT_TOMBSTONE":
        direct = any(
            _clean_value(item.get(k))
            for k in ("name", "full_name", "display_name", "customer_email",
                      "owner_email", "email", "phone", "email_hash")
        )
        return "PRESENT" if direct else "REDACTED"

    if category == "BACKUP_ARCHIVE":
        restore = _restore_state(item)
        if restore:
            return restore
        if "restore_authorization" in _clean_value(item.get("event")).lower():
            # An authorization result we cannot read is not a restore risk.
            return "UNKNOWN"
        return state or "ACTIVE"

    if category == "DATA_FLOW":
        if "enabled" in item:
            return "ACTIVE" if _as_bool(item.get("enabled")) else "DISABLED"
        return state or "ACTIVE"

    if category == "USER_EXPORT":
        if "download_available" in item:
            return "PRESENT" if _as_bool(item.get("download_available")) else "ABSENT"
        if "available" in item:
            return "PRESENT" if _as_bool(item.get("available")) else "ABSENT"
        return state or "PRESENT"

    if category == "EMAIL_DELIVERY_LOG":
        if state == "REDACTED":
            return "REDACTED"
        has_email = any(
            _clean_value(item.get(k))
            for k in ("email", "customer_email", "owner_email", "requester_email")
        )
        return "PRESENT" if has_email else "REDACTED"

    if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
        return "PRESENT"

    return state or "PRESENT"


def _pii_for(category: str, item: dict[str, Any], state: str) -> bool:
    if category in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT",
                    "MARKETING_PROFILE", "SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER",
                    "CACHE_ENTRY"):
        if state == "PRESENT":
            return any(_clean_value(item.get(k)) for k in (
                "email", "customer_email", "owner_email", "requester_email",
                "phone", "owner_phone", "requester_phone",
            ))
        return False
    if category == "SUPPORT_MESSAGE":
        return state == "PRESENT" and (_has_direct_pii(item) or bool(_text_ids(item)))
    if category == "ANALYTICS_PROFILE":
        return state == "PRESENT" and _has_direct_ids(item)
    if category == "ACCOUNT_TOMBSTONE":
        return state == "PRESENT"
    if category == "PRODUCT_TELEMETRY":
        return state == "PRESENT"
    if category == "EMAIL_DELIVERY_LOG":
        return state == "PRESENT"
    return False


def _make_record(
    *,
    evidence_id: str,
    file_path: Path,
    captured_at: datetime,
    origin: str,
    system_id: str,
    resource_id: str,
    category: str,
    state: str,
    identifiers: set[str],
    details: dict[str, Any],
    provenance: str,
) -> ObservedRecord:
    return ObservedRecord(
        evidence_id=evidence_id,
        file_path=file_path,
        captured_at=captured_at,
        origin=origin,
        system_id=system_id,
        resource_id=resource_id,
        data_category=category,
        state=state,
        has_exposed_pii=_pii_for(category, details, state),
        identifiers=identifiers,
        details=details,
        provenance=provenance,
    )


# ---------------------------------------------------------------------------
# Parsers for each evidence format
# ---------------------------------------------------------------------------

def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("true", "1", "yes", "y")


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+\d[\d\s\-()]{7,}\d")

_SQL_TABLE_SYSTEMS = (
    ("customer_profiles", "account_service"),
    ("search_documents", "search_service"),
    ("customer_search_documents", "search_service"),
    ("analytics", "analytics_platform"),
    ("support", "support_platform"),
    ("customer_exports", "export_service"),
    ("connector", "integration_service"),
    ("backup", "backup_service"),
    ("security", "security_service"),
    ("deleted_customer_references", "identity_service"),
    ("retained_order_records", "legal_service"),
)


def _sql_system_for_table(table: str, origin_system: str = "") -> str:
    norm = _normalize_system_id(origin_system) if origin_system else ""
    if norm and norm not in ("", "central_observability_export"):
        return norm
    t = table.lower()
    for needle, system in _SQL_TABLE_SYSTEMS:
        if needle in t:
            return system
    return "account_service"


def _text_ids(item: dict[str, Any]) -> set[str]:
    """Identifiers embedded in free-text fields (support messages, notes)."""
    ids: set[str] = set()
    for key in ("message_text", "message", "message_excerpt", "note", "body", "content"):
        text = _clean_value(item.get(key))
        if not text:
            continue
        ids.update(_EMAIL_RE.findall(text))
        ids.update(_PHONE_RE.findall(text))
    return ids


def _merge_document(item: dict[str, Any]) -> dict[str, Any]:
    """Search documents keep their subject fields in a nested document blob."""
    doc = item.get("document")
    if not isinstance(doc, dict):
        return item
    merged = dict(item)
    for key, value in doc.items():
        merged.setdefault(key, value)
    return merged


def _physical_copy_for_table(table: str) -> str:
    """customer_profiles_failover_replica -> failover_replica; *_primary -> primary."""
    t = table.lower()
    if t.endswith("_primary") or "replica" not in t:
        return "primary"
    head, _, tail = t.partition("replica")
    qualifier = head.rstrip("_").rsplit("_", 1)[-1]
    if qualifier in ("failover", "read", "reporting"):
        return f"{qualifier}_replica{tail}"
    return f"replica{tail}"


def _sql_header(text: str) -> dict[str, str]:
    header: dict[str, str] = {}
    for line in text.splitlines()[:12]:
        if not line.startswith("--"):
            continue
        body = line[2:].strip()
        if "point-in-time database snapshot" in body:
            header["point_in_time"] = "true"
        key, sep, value = body.partition(":")
        if sep and key.strip().lower() in ("captured at", "database topology"):
            header[key.strip().lower()] = value.strip()
    return header


def _parse_sql_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
    coverages: Optional[list[SnapshotCoverage]] = None,
) -> list[ObservedRecord]:
    records: list[ObservedRecord] = []
    conn = sqlite3.connect(":memory:")
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as sf:
            script = sf.read()
        header = _sql_header(script)
        if header.get("captured at"):
            captured_at = _parse_iso(header["captured at"])
        conn.executescript(script)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cursor.fetchall()]

        scope: dict[str, datetime] = {}
        if "snapshot_scope" in (t.lower() for t in tables):
            cursor.execute("SELECT origin_system, captured_at FROM snapshot_scope")
            for system, scope_time in cursor.fetchall():
                scope[_normalize_system_id(str(system))] = _parse_iso(str(scope_time))

        # Dedicated single-category tables: (table, system, category, copy, ids).
        dedicated: list[tuple[str, str, str, str, set[str]]] = []
        # Mixed record_json tables, and the collection of each record in them.
        mixed_tables: list[str] = []
        mixed_collection: dict[int, str] = {}
        for tbl in tables:
            if tbl.lower() == "snapshot_scope":
                continue
            copy = _physical_copy_for_table(tbl)
            cursor.execute(f"PRAGMA table_info({tbl})")
            cols = [r[1] for r in cursor.fetchall()]
            first_record = len(records)
            if "record_json" not in cols:
                table_system = _sql_system_for_table(tbl)
                table_category = _category_from_hint(tbl) or "UNKNOWN_CATEGORY"
                if table_category == "USER_PROFILE" and table_system == "integration_service":
                    table_category = "DATA_FLOW"
                table_ids: set[str] = set()
                dedicated.append((tbl, table_system, table_category, copy, table_ids))
            else:
                mixed_tables.append(tbl)
            cursor.execute(f"SELECT * FROM {tbl}")
            for row in cursor.fetchall():
                row_dict = dict(zip(cols, row))
                res_id = _clean_value(row_dict.get("resource_id"))
                if not res_id:
                    continue

                if "record_json" in row_dict and row_dict.get("record_json"):
                    try:
                        item = json.loads(row_dict["record_json"])
                    except Exception as exc:
                        raise EvidenceParseError(
                            f"{file_id}: invalid record_json in {tbl}:{res_id}"
                        ) from exc
                    if not isinstance(item, dict):
                        raise EvidenceParseError(
                            f"{file_id}: record_json in {tbl}:{res_id} is not an object"
                        )
                    item.setdefault("resource_id", res_id)
                    origin_system = row_dict.get("origin_system", "")
                    system_id = _sql_system_for_table(tbl, origin_system)
                    collection = row_dict.get("collection_name", "")
                    merged = _merge_document(item)
                    category = _category_for(
                        system_id,
                        _clean_value(merged.get("resource_id")),
                        collection,
                    )
                    if category == "USER_PROFILE" and system_id == "integration_service":
                        category = "DATA_FLOW"
                    state = _state_for_record(category, merged, merged.get("result", ""))
                    ids = _collect_ids(merged) | _text_ids(merged)
                    records.append(
                        _make_record(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=system_id,
                            resource_id=_clean_value(merged.get("resource_id")),
                            category=category,
                            state=state,
                            identifiers=ids,
                            details=merged,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )
                    mixed_collection[id(records[-1])] = str(collection)
                    continue

                system_id = _sql_system_for_table(tbl)
                category = _category_for(system_id, res_id, tbl)
                if category == "USER_PROFILE" and system_id == "integration_service":
                    category = "DATA_FLOW"
                state = _state_for_record(category, row_dict)
                ids = _collect_ids(row_dict) | _text_ids(row_dict)
                records.append(
                    _make_record(
                        evidence_id=file_id,
                        file_path=file_path,
                        captured_at=captured_at,
                        origin=origin,
                        system_id=system_id,
                        resource_id=res_id,
                        category=category,
                        state=state,
                        identifiers=ids,
                        details=row_dict,
                        provenance=f"{tbl}:{res_id}",
                    )
                )
            for rec in records[first_record:]:
                rec.physical_copy = copy
                if "record_json" not in cols:
                    table_ids.add(rec.resource_id)
    finally:
        conn.close()

    if coverages is not None:
        if header.get("point_in_time"):
            # A point-in-time database snapshot captures every row of each
            # dedicated table, per physical copy.  An empty table is treated
            # as an unproven export, never as proof that everything is gone.
            for tbl, system, category, copy, ids in dedicated:
                if not ids or category == "UNKNOWN_CATEGORY":
                    continue
                coverages.append(SnapshotCoverage(
                    evidence_id=file_id, system_id=system, data_category=category,
                    physical_copy=copy, observed_at=captured_at, available_at=captured_at,
                    resource_ids=frozenset(ids), subject_identifiers=None,
                    provenance=f"sql_full_table:{tbl}",
                ))
            # Mixed tables hold several collections captured for the subjects
            # the snapshot names.  Every table in the topology is a copy of
            # the same database, so a collection seen in any copy is one of
            # its collections, and a copy with no rows of it holds none for
            # those subjects (replication drift).
            subjects = frozenset(
                ident for rec in records for ident in strong_identifiers(rec.identifiers)
            )
            collections: dict[str, tuple[str, str]] = {}
            per_copy: dict[str, dict[str, set[str]]] = {}
            for rec in records:
                table = rec.provenance.split(":", 1)[0]
                collection = mixed_collection.get(id(rec))
                if collection is None:
                    continue
                collections.setdefault(collection, (rec.system_id, rec.data_category))
                per_copy.setdefault(table, {}).setdefault(collection, set()).add(rec.resource_id)
            for table in (mixed_tables if subjects else []):
                copy = _physical_copy_for_table(table)
                for collection, (system, category) in sorted(collections.items()):
                    if category == "UNKNOWN_CATEGORY" or not _category_from_hint(collection):
                        continue
                    coverages.append(SnapshotCoverage(
                        evidence_id=file_id, system_id=system, data_category=category,
                        physical_copy=copy, observed_at=captured_at, available_at=captured_at,
                        resource_ids=frozenset(per_copy.get(table, {}).get(collection, set())),
                        subject_identifiers=subjects,
                        provenance=f"sql_full_collection:{table}.{collection}",
                    ))
        elif scope:
            # A scoped inventory is complete only for the subjects it was
            # captured for; an inventory naming no subject proves nothing.
            subjects = frozenset(
                ident for rec in records for ident in strong_identifiers(rec.identifiers)
            )
            if subjects:
                for tbl, system, category, copy, ids in dedicated:
                    if system not in scope or category == "UNKNOWN_CATEGORY":
                        continue
                    coverages.append(SnapshotCoverage(
                        evidence_id=file_id, system_id=system, data_category=category,
                        physical_copy=copy, observed_at=scope[system], available_at=captured_at,
                        resource_ids=frozenset(ids), subject_identifiers=subjects,
                        provenance=f"sql_scoped_inventory:{tbl}",
                    ))

    return records


def _json_item_record(
    *,
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
    system_id: str,
    item: dict[str, Any],
    resource_id: str,
    category_hint: str = "",
    provenance: str,
) -> Optional[ObservedRecord]:
    merged = _merge_document(item)
    res_id = _clean_value(merged.get("resource_id")) or resource_id
    if not res_id:
        return None
    system_id = _normalize_system_id(system_id)
    category = _category_for(system_id, res_id, category_hint)
    if category == "USER_PROFILE" and system_id == "integration_service":
        category = "DATA_FLOW"
    state = _state_for_record(category, merged, merged.get("result", ""))
    ids = _collect_ids(merged) | _text_ids(merged)
    return _make_record(
        evidence_id=file_id,
        file_path=file_path,
        captured_at=_observation_time(merged, captured_at),
        origin=origin,
        system_id=system_id,
        resource_id=res_id,
        category=category,
        state=state,
        identifiers=ids,
        details=merged,
        provenance=provenance,
    )


def _parse_json_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
    coverages: Optional[list[SnapshotCoverage]] = None,
) -> list[ObservedRecord]:
    records: list[ObservedRecord] = []
    with open(file_path, "r", encoding="utf-8") as jf:
        data = json.load(jf)
    if not isinstance(data, dict):
        raise EvidenceParseError(f"{file_id}: top-level JSON is not an object")
    captured_at = _observation_time(data, captured_at)

    # 1. Per-service resource exports (evidence_62/65/.../92).
    service_exports = data.get("service_exports") or {}
    if not isinstance(service_exports, dict):
        raise EvidenceParseError(f"{file_id}: service_exports is not an object")
    for sname, scontent in service_exports.items():
        if not isinstance(scontent, dict):
            raise EvidenceParseError(f"{file_id}: service export {sname!r} is not an object")
        norm_sys = _normalize_system_id(sname)
        for collection, items in scontent.items():
            if not isinstance(items, list):
                raise EvidenceParseError(
                    f"{file_id}: service export {sname}.{collection} is not a list"
                )
            for item in items:
                if not isinstance(item, dict):
                    raise EvidenceParseError(
                        f"{file_id}: service export {sname}.{collection} contains a non-object item"
                    )
                res_id = _clean_value(item.get("resource_id"))

                if collection == "profile_lookups":
                    profile = item.get("profile") if isinstance(item.get("profile"), dict) else {}
                    merged = dict(item)
                    merged.update(profile)
                    merged["resource_id"] = res_id
                    state = "ABSENT" if item.get("status_code") == 404 or not profile else "PRESENT"
                    ids = _collect_ids(merged)
                    records.append(
                        _make_record(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=_observation_time(merged, captured_at),
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            category="USER_PROFILE",
                            state=state,
                            identifiers=ids,
                            details=merged,
                            provenance=f"service_exports.{collection}:{res_id}",
                        )
                    )
                    continue

                if collection == "index_queries":
                    hits = item.get("hits") if isinstance(item.get("hits"), dict) else {}
                    docs = hits.get("documents") or []
                    total = hits.get("total", len(docs))
                    merged = dict(item)
                    if docs:
                        merged = _merge_document(docs[0])
                        merged.update({k: v for k, v in item.items() if k not in merged})
                        merged["resource_id"] = _clean_value(
                            merged.get("resource_id")
                        ) or res_id
                    else:
                        merged["resource_id"] = res_id
                    ids = _collect_ids(item) | _collect_ids(merged)
                    for doc in docs:
                        ids |= _collect_ids(doc)
                    state = "PRESENT" if _as_bool(total) or docs else "ABSENT"
                    if str(total).strip() == "0":
                        state = "ABSENT"
                    records.append(
                        _make_record(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=_observation_time(merged, captured_at),
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=_clean_value(merged.get("resource_id")) or res_id,
                            category="SEARCH_INDEX_ENTRY",
                            state=state,
                            identifiers=ids,
                            details=merged,
                            provenance=f"service_exports.{collection}:{res_id}",
                        )
                    )
                    continue

                rec = _json_item_record(
                    file_id=file_id,
                    file_path=file_path,
                    origin=origin,
                    captured_at=captured_at,
                    system_id=norm_sys,
                    item=item,
                    resource_id=res_id,
                    category_hint="",
                    provenance=f"service_exports.{collection}:{res_id}",
                )
                if rec:
                    records.append(rec)

    # 2. Snapshot bundles and direct record lists.
    snapshots = data.get("snapshots")
    if snapshots is not None and not isinstance(snapshots, list):
        raise EvidenceParseError(f"{file_id}: snapshots is not a list")
    if isinstance(snapshots, list):
        # Snapshots sharing one capture time form a single scoped capture;
        # each collection in it is complete for the subjects it names.
        groups: dict[datetime, list[tuple[str, str, list[ObservedRecord]]]] = {}
        for snap in snapshots:
            if not isinstance(snap, dict):
                raise EvidenceParseError(f"{file_id}: snapshot entry is not an object")
            system_id = _normalize_system_id(snap.get("data_store", ""))
            collection = snap.get("collection", "")
            snapshot_time = _observation_time(snap, captured_at)
            snapshot_records = snap.get("records", []) or []
            if not isinstance(snapshot_records, list):
                raise EvidenceParseError(f"{file_id}: snapshot records is not a list")
            members: list[ObservedRecord] = []
            groups.setdefault(snapshot_time, []).append((system_id, collection, members))
            for item in snapshot_records:
                if not isinstance(item, dict):
                    raise EvidenceParseError(f"{file_id}: snapshot record is not an object")
                hint = collection
                item_system = system_id
                if collection == "operational_record_history":
                    item_system = _normalize_system_id(
                        _clean_value(item.get("system")) or system_id
                    )
                    hint = _clean_value(item.get("record_type")) or collection
                rec = _json_item_record(
                    file_id=file_id,
                    file_path=file_path,
                    origin=origin,
                    captured_at=snapshot_time,
                    system_id=item_system,
                    item=item,
                    resource_id=_clean_value(item.get("resource_id")),
                    category_hint=hint,
                    provenance=f"snapshot.{collection}:{item.get('resource_id')}",
                )
                if rec:
                    records.append(rec)
                    members.append(rec)
        if coverages is not None:
            for snapshot_time, collections in groups.items():
                subjects = frozenset(
                    ident
                    for _, _, members in collections
                    for rec in members
                    for ident in strong_identifiers(rec.identifiers)
                )
                if not subjects:
                    continue
                for system_id, collection, members in collections:
                    # A mixed history collection is not a complete copy of
                    # any one store.
                    category = _category_from_hint(collection) if collection != "operational_record_history" else None
                    if not category:
                        continue
                    coverages.append(SnapshotCoverage(
                        evidence_id=file_id, system_id=system_id, data_category=category,
                        physical_copy="primary", observed_at=snapshot_time, available_at=captured_at,
                        resource_ids=frozenset(rec.resource_id for rec in members),
                        subject_identifiers=subjects,
                        provenance=f"snapshot_group:{collection}",
                    ))
        return records

    raw_records = data.get("records")
    if raw_records is not None and not isinstance(raw_records, list):
        raise EvidenceParseError(f"{file_id}: records is not a list")
    if isinstance(raw_records, list):
        source = data.get("source") or data.get("origin") or ""
        collection = data.get("collection") or ""
        for item in raw_records:
            if not isinstance(item, dict):
                raise EvidenceParseError(f"{file_id}: record is not an object")
            item_system = item.get("system")
            if item_system:
                system_id = _normalize_system_id(str(item_system))
                hint = _clean_value(item.get("record_type")) or collection
            else:
                system_id = _normalize_system_id(str(source))
                hint = collection
            rec = _json_item_record(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                captured_at=captured_at,
                system_id=system_id,
                item=item,
                resource_id=_clean_value(item.get("resource_id")),
                category_hint=hint,
                provenance=f"records:{item.get('resource_id')}",
            )
            if rec:
                records.append(rec)

    return records


def _parse_text_handover_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    """Parse customer_account_handover_20261001.txt (evidence_03)."""
    records: list[ObservedRecord] = []
    line_re = re.compile(
        r"^-\s*([0-9TZ:-]+)\s*\|\s*([a-zA-Z0-9_]+)\s*\|\s*([a-zA-Z0-9_]+)\s*\|\s*([a-zA-Z0-9_]+)\s*\|\s*([a-zA-Z0-9_]+)\s*\|\s*(.*)$"
    )
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = line_re.match(line)
            if not m:
                continue
            ts_str, sys_id, res_id, cat, raw_state, note = m.groups()
            sys_id = _normalize_system_id(sys_id)
            note = note.strip()
            ids = {note} if note and note != "no direct identifier" else set()

            if cat not in _ALL_CATEGORIES and cat != "DATA_FLOW":
                raise EvidenceParseError(
                    f"{file_id}: unsupported handover category {cat!r} for {res_id}"
                )

            # Map raw state to allowed states
            if raw_state == "NOT_FOUND":
                state = "ABSENT"
                has_pii = False
            elif raw_state in ("FOUND", "IDENTIFIABLE"):
                state = "PRESENT"
                has_pii = True
            elif raw_state == "ANONYMIZED":
                state = "ANONYMIZED"
                has_pii = False
            elif raw_state == "REDACTED":
                state = "REDACTED"
                has_pii = False
            elif raw_state == "ACTIVE":
                state = "ACTIVE"
                has_pii = False
            elif raw_state in ("DISABLED", "BLOCKED"):
                state = raw_state
                has_pii = False
            else:
                raise EvidenceParseError(
                    f"{file_id}: unsupported handover state {raw_state!r} for {res_id}"
                )

            records.append(
                ObservedRecord(
                    evidence_id=file_id,
                    file_path=file_path,
                    captured_at=_parse_iso(ts_str),
                    origin=origin,
                    system_id=sys_id,
                    resource_id=res_id,
                    data_category=cat,
                    state=state,
                    has_exposed_pii=has_pii,
                    identifiers=ids,
                    details={"raw_state": raw_state, "note": note},
                    provenance=f"handover:{res_id}",
                )
            )

    return records


def _log_header_fields(line: str) -> dict[str, str]:
    """Extract service/trace/event from the three non key=value log layouts."""
    fields: dict[str, str] = {}

    # [DEBUG] [account_service] [tr-123] profile_lookup_completed: ...
    m = re.match(
        r"^\S+\s+\[[A-Z]+\]\s+\[([A-Za-z0-9_]+)\]\s+\[([A-Za-z0-9_\-]+)\]\s+([A-Za-z0-9_]+):",
        line,
    )
    if m:
        fields["service"] = m.group(1)
        if m.group(2).startswith("tr-"):
            fields["trace_id"] = m.group(2)
        fields["event"] = m.group(3)
        return fields

    # 2026-07-03T07:51:30Z | DEBUG | service | trace | event | ...
    parts = [p.strip() for p in line.split("|")]
    if len(parts) >= 5 and re.match(r"^\d{4}-\d\d-\d\dT", parts[0]):
        fields["service"] = parts[2]
        if parts[3].startswith("tr-"):
            fields["trace_id"] = parts[3]
        fields["event"] = parts[4]
        return fields

    # <15>1 node-1 account_service tr-123 - - level=... (optionally timestamped)
    m = re.search(r"<\d+>1\s+\S+\s+(\S+)\s+(\S+)\s", line)
    if m:
        fields["service"] = m.group(1)
        if m.group(2).startswith("tr-"):
            fields["trace_id"] = m.group(2)

    # 2026-06-08T09:53:38Z requestId=tr-1179991 level=DEBUG function=account_service ...
    if "trace_id" not in fields:
        m = re.search(r"\brequestId=(tr-[A-Za-z0-9_\-]+)", line)
        if m:
            fields["trace_id"] = m.group(1)
    return fields


def _parse_log_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    """Parse structured logs, propagating identifiers across trace contexts.

    Logs frequently put the identity on a ``*_started`` line (lookup_key,
    match_key, subject_key, scan_key) and the resource/result on a later
    completion line of the same trace. Both lines must be joined through
    ``trace_id`` or the resource cannot be attributed to the subject.
    """
    kv_re = re.compile(r'([a-zA-Z0-9_]+)=([^\s"]+|"[^"]*")')

    parsed_lines: list[dict[str, Any]] = []
    trace_ids: dict[str, set[str]] = {}

    with open(file_path, "r", encoding="utf-8", errors="replace") as lf:
        for line_no, raw in enumerate(lf, 1):
            line = raw.strip()
            if not line:
                continue

            fields: dict[str, Any] = {}
            timestamp = re.match(r"^(\d{4}-\d{2}-\d{2}T\S+)", line)
            if timestamp:
                fields["observed_at"] = timestamp.group(1)
            if "{" in line and "}" in line:
                try:
                    start = line.index("{")
                    end = line.rindex("}") + 1
                    data = json.loads(line[start:end])
                    if not isinstance(data, dict):
                        raise ValueError("embedded JSON is not an object")
                    fields.update(data)
                except Exception as exc:
                    raise EvidenceParseError(
                        f"{file_id}: invalid embedded JSON at log line {line_no}"
                    ) from exc

            kvs = dict(kv_re.findall(line))
            # Some exporters escape the quotes inside message="..." (\"key=value\").
            # The plain kv regex stops at the first backslash-escaped quote and
            # would drop every nested field (event, resource_id, identifiers).
            escaped_message = re.search(r'\bmessage="((?:[^"\\]|\\.)*)"', line)
            if escaped_message:
                kvs["message"] = (
                    escaped_message.group(1).replace('\\"', '"').replace("\\\\", "\\")
                )
            message = _clean_value(kvs.get("message"))
            if "resource_id=" in message or "event=" in message:
                kvs.update(dict(kv_re.findall(message)))
            for key, value in _log_header_fields(line).items():
                kvs.setdefault(key, value)
            for key, value in kvs.items():
                fields.setdefault(key, _clean_value(value))

            if not fields:
                continue
            fields = {k: _clean_value(v) for k, v in fields.items()}
            parsed_lines.append(fields)

            trace_id = _clean_value(fields.get("trace_id"))
            if trace_id:
                ids = _collect_ids(fields) | _text_ids(fields)
                if ids:
                    trace_ids.setdefault(trace_id, set()).update(ids)

    skip_events = {
        "deletion_marker_check",
        "cache_lookup",
        "connection_acquired",
        "dependency_retry",
        "dependency_recovered",
        "consumer_lag",
        "checkpoint_saved",
        "batch_started",
        "export_started",
        "export_completed",
        "telemetry_flushed",
        "cache_refresh",
        "thumbnail_failed",
    }

    records: list[ObservedRecord] = []
    for fields in parsed_lines:
        resource_id = _clean_value(fields.get("resource_id"))
        if not resource_id:
            continue

        event = _clean_value(fields.get("event"))
        if event.endswith("_started") or event.endswith("_query_started"):
            continue
        if event in skip_events:
            continue

        trace_id = _clean_value(fields.get("trace_id"))
        identifiers = _collect_ids(fields) | _text_ids(fields)
        if trace_id:
            identifiers.update(trace_ids.get(trace_id, set()))

        service = (
            _clean_value(fields.get("service"))
            or _clean_value(fields.get("function"))
            or _clean_value(fields.get("logger"))
            or origin
        )
        system_id = _normalize_system_id(service)
        if system_id in ("central_observability_export", "log_router", "service_readback_logs"):
            system_id = _normalize_system_id(resource_id)

        record_type = _clean_value(fields.get("record_type"))
        system_hint = _normalize_system_id(_clean_value(fields.get("system")))
        if system_hint in ("central_observability_export", "log_router"):
            system_hint = ""
        if system_hint:
            # Lookup exports scan foreign systems; the record belongs to the
            # system named in the row, not to the service producing the export.
            system_id = system_hint
        category = _category_for(
            system_hint or system_id,
            resource_id,
            record_type,
        )

        # Legacy support contact lookups are subject-owned contact records,
        # and attachment scans/reads inspect a stored file, not the message.
        if system_id == "support_platform" and (
            "contact_query" in event or _is_attachment_event(fields)
        ):
            category = "SUPPORT_ATTACHMENT"
        elif system_id == "analytics_platform" and (
            "contact_lookup" in event
            or _clean_value(fields.get("email_opt_in")).lower() == "true"
        ):
            # Contact/opt-in lookups describe a marketing profile, which policy
            # deletes outright rather than anonymizes.
            category = "MARKETING_PROFILE"
        elif category == "USER_PROFILE" and system_id == "integration_service":
            category = "DATA_FLOW"

        raw_result = _clean_value(fields.get("result"))
        rows = _clean_value(fields.get("rows"))
        total_hits = _clean_value(fields.get("total_hits"))
        http_status = _clean_value(fields.get("http_status"))
        raw_result_known = not raw_result or raw_result.upper() in _RESULT_STATES

        state = _state_for_record(category, fields, raw_result)
        if category == "USER_PROFILE":
            if http_status == "404" or rows == "0" or raw_result.upper() == "NOT_FOUND":
                state = "ABSENT"
        elif category == "SEARCH_INDEX_ENTRY":
            if http_status == "404" or rows == "0" or raw_result.upper() == "NOT_FOUND":
                state = "ABSENT"
            elif total_hits.isdigit():
                state = "PRESENT" if int(total_hits) > 0 else "ABSENT"
            elif raw_result.upper() in ("HIT", "FOUND"):
                state = "PRESENT"
        elif category == "SUPPORT_MESSAGE":
            if state != "ABSENT":
                if event == "message_pii_scan":
                    state = "PRESENT"
                elif raw_result.upper() == "IDENTIFIABLE":
                    state = "PRESENT"
                elif _has_direct_pii(fields) or _text_ids(fields):
                    state = "PRESENT"
                else:
                    # A row count without the record body is not proof of
                    # redaction; _state_for_record returns UNKNOWN for it.
                    state = _state_for_record(category, fields, raw_result)
        elif category == "SUPPORT_ATTACHMENT":
            if state != "ABSENT":
                state = "PRESENT"
        elif category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            if state != "ABSENT":
                direct = _clean_value(fields.get("direct_identifiers"))
                if direct.isdigit() and int(direct) > 0:
                    state = "PRESENT"
                elif event in ("analytics_identity_scan", "analytics_profile_scan"):
                    state = "PRESENT"
                elif _has_direct_ids(fields):
                    state = "PRESENT"
                else:
                    state = "ANONYMIZED"
        elif category == "DATA_FLOW":
            if state != "ABSENT":
                enabled = _clean_value(fields.get("enabled")).lower()
                if enabled in ("true", "false"):
                    state = "ACTIVE" if enabled == "true" else "DISABLED"
        elif category == "BACKUP_ARCHIVE":
            if state != "ABSENT":
                state = _state_for_record(category, fields, raw_result)
        elif category == "USER_EXPORT":
            if state != "ABSENT":
                available = _clean_value(fields.get("available")).lower()
                if available in ("true", "false"):
                    state = "PRESENT" if available == "true" else "ABSENT"
        elif category == "SECURITY_AUDIT_LOG":
            if state != "ABSENT":
                state = "PRESENT"
        elif category == "MARKETING_PROFILE":
            if state != "ABSENT":
                state = "PRESENT"

        # A category-specific branch must not rescue an unrecognized raw
        # result into a policy-significant state.
        if raw_result and not raw_result_known:
            state = "UNKNOWN"

        records.append(
            _make_record(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=_observation_time(fields, captured_at),
                origin=origin,
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                state=state,
                identifiers=identifiers,
                details=fields,
                provenance=f"log:{resource_id}",
            )
        )

    return records


@dataclass(frozen=True)
class CatalogLink:
    """A LINK_RESOURCE_IDENTITY activity: resource, visible alias, and subject."""
    activity_id: str
    event_time: datetime
    system_id: str
    resource_id: str
    alias: str
    identifiers: frozenset
    exclusive: bool
    category_hint: str = ""


_USER_REF_RE = re.compile(r"\buser_\d+\b", re.I)


def catalog_links(activity_rows) -> list[CatalogLink]:
    links: list[CatalogLink] = []
    for row in activity_rows or ():
        if str(row.get("event_type") or "") != "LINK_RESOURCE_IDENTITY":
            continue
        details = str(row.get("details") or "")
        alias = re.search(r"\(([^()]+)\)", details)
        ids = set(_EMAIL_RE.findall(details)) | set(_USER_REF_RE.findall(details))
        links.append(CatalogLink(
            activity_id=str(row.get("activity_id") or ""),
            event_time=_parse_iso(str(row.get("event_time") or "")),
            system_id=_normalize_system_id(str(row.get("target_system") or "")),
            resource_id=str(row.get("resource_id") or "").strip(),
            alias=alias.group(1).strip() if alias else "",
            identifiers=frozenset(i.lower() for i in ids),
            exclusive=bool(re.search(r"belongs only to|no other subject", details, re.I)),
            category_hint=(
                "SUPPORT_ATTACHMENT" if re.search(r"attachment", details, re.I)
                else _category_from_hint(str(row.get("target_system") or ""), str(row.get("resource_id") or "")) or ""
            ),
        ))
    return links


def _alias_index(links: list[CatalogLink]) -> dict[str, CatalogLink]:
    """Visible alias (file name, statement number, reference) -> catalog link."""
    index: dict[str, CatalogLink] = {}
    for link in links:
        for key in (link.alias, Path(link.alias).stem if "." in link.alias else ""):
            if key:
                index.setdefault(key.lower(), link)
    return index


# Resource-id prefixes that name a record directly in documents.
_RESOURCE_TOKEN_RE = re.compile(
    r"\b(account|support|audit_record|export|search|analytics|legal_hold|tombstone|backup|data_flow|marketing)_\d+\b"
)
_PREFIX_SYSTEMS = {
    "account": "account_service",
    "support": "support_platform",
    "audit_record": "security_service",
    "export": "export_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "legal_hold": "legal_service",
    "tombstone": "identity_service",
    "backup": "backup_service",
    "data_flow": "integration_service",
    "marketing": "marketing_platform",
}
_STATEMENT_RE = re.compile(r"\b[A-Z]{2,5}-\d{4}-\d{4}-\d{3,6}\b")
_RETAIN_UNTIL_RE = re.compile(
    r"retain until\s+(\d{1,2} [A-Z][a-z]{2} \d{4})(?:\s+(\d{2})\s*\n?\s*(\d{2}) UTC)?", re.I
)


def _document_date(match: re.Match) -> Optional[str]:
    try:
        value = datetime.strptime(match.group(1), "%d %b %Y").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if match.group(2) and match.group(3):
        value = value.replace(hour=int(match.group(2)), minute=int(match.group(3)))
    return value.isoformat()


def _parse_pdf_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
    aliases: Optional[dict[str, CatalogLink]] = None,
) -> list[ObservedRecord]:
    """Extract records a business document visibly names.

    A record is created only for an explicit resource id printed in the
    document, or for a printed reference (statement number) that the data
    catalog maps to a resource.  The document's identifiers are attached so
    the record can be connected to a subject; no subject is assumed.
    """
    records: list[ObservedRecord] = []
    reader = pypdf.PdfReader(file_path)
    text = "\n".join(page.extract_text() for page in reader.pages)
    lower = text.lower()

    doc_ids = set(_EMAIL_RE.findall(text)) | set(_PHONE_RE.findall(text)) | set(_USER_REF_RE.findall(text))
    is_attachment = "attachment properties" in lower or bool(re.search(r"\bfile\s+\S+\.(?:pdf|png|jpg)\b", lower))
    retain = _RETAIN_UNTIL_RE.search(text)

    targets: dict[tuple[str, str], dict[str, Any]] = {}
    for token in dict.fromkeys(m.group(0) for m in _RESOURCE_TOKEN_RE.finditer(text)):
        prefix = token.rsplit("_", 1)[0]
        targets[(_PREFIX_SYSTEMS[prefix], token)] = {"source": "printed_resource_id"}
    for reference in dict.fromkeys(_STATEMENT_RE.findall(text)):
        link = (aliases or {}).get(reference.lower())
        if link is not None:
            targets.setdefault((link.system_id, link.resource_id), {"source": "catalog_alias", "alias": reference})

    for (system_id, resource_id), details in targets.items():
        if system_id == "support_platform":
            category = "SUPPORT_ATTACHMENT" if is_attachment else "SUPPORT_MESSAGE"
        else:
            category = _category_from_hint(system_id, resource_id) or "UNKNOWN_CATEGORY"
        details = dict(details)
        if category == "SECURITY_AUDIT_LOG" and retain:
            retained = _document_date(retain)
            if retained:
                details["retention_until"] = retained
        identifiers = set(doc_ids)
        if category == "SECURITY_AUDIT_LOG":
            # A journal names its subject by reference only.
            subject = re.search(r"subject reference\s+(user_\d+)", text, re.I)
            identifiers = {subject.group(1)} if subject else set()
            details["subject_reference"] = subject.group(1) if subject else ""
        else:
            for key, pattern in (("email", _EMAIL_RE), ("phone", _PHONE_RE)):
                found = pattern.findall(text)
                if found:
                    details[key] = found[0]
        records.append(
            _make_record(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=captured_at,
                origin=origin,
                system_id=system_id,
                resource_id=resource_id,
                category=category,
                state="PRESENT",
                identifiers=identifiers,
                details=details,
                provenance=f"pdf:{file_path.name}:{resource_id}",
            )
        )

    # General legal-hold register rows.  The register is a table; extract
    # every row that carries an order reference and a retained-until date
    # rather than relying on a filename-specific branch.
    legal_row_re = re.compile(
        r"(ORD-\d+)\s*\|\s*(user_\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|"
        r"\s*([^|]+?)\s*\|\s*Retain until\s+([^|]+?)\s*\|\s*([A-Z]{2})"
    )
    for match in legal_row_re.finditer(text):
        order_id, user_id, reason, row_date, amount, retain_text, market = (
            part.strip() for part in match.groups()
        )
        retained_until = None
        try:
            retained_until = datetime.strptime(retain_text, "%d %b %Y").replace(
                tzinfo=timezone.utc
            ).isoformat()
        except ValueError:
            retained_until = None
        details = {
            "order_reference": order_id,
            "retention_reason": reason,
            "row_date": row_date,
            "amount": amount,
            "market": market,
            "retained_until_raw": retain_text,
        }
        if retained_until:
            details["retained_until"] = retained_until
        records.append(
            ObservedRecord(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=captured_at,
                origin=origin,
                system_id="legal_service",
                resource_id=order_id,
                data_category="LEGAL_HOLD_RECORD",
                state="PRESENT",
                has_exposed_pii=False,
                identifiers={user_id},
                details=details,
                provenance=f"pdf:{file_path.name}:{order_id}",
            )
        )

    return records


_IMAGE_STATES = {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}


def _resolve_visible_resource(
    observation: dict[str, Any],
    aliases: dict[str, CatalogLink],
) -> Optional[tuple[str, str, Optional[CatalogLink]]]:
    """Map what the screen shows to a catalogued (system, resource) pair.

    The model transcribes visible facts; it does not get to mint resource ids.
    A file name, statement number or visible reference resolves through the
    data catalog.  Otherwise the resource id must be printed on the screen.
    """
    details = observation.get("details") or {}
    visible = str(details.get("visible_text") or "")
    resource_id = str(observation.get("resource_id") or "").strip()
    system_id = _normalize_system_id(str(observation.get("system_id") or ""))
    file_name = str(details.get("file_name") or "").strip()

    # File names identify a stored object wherever it is browsed; other
    # visible references only resolve within the same system.
    candidates = [(file_name, True), (Path(file_name).stem if file_name else "", True), (resource_id, False)]
    candidates += [(ref, False) for ref in _STATEMENT_RE.findall(visible)]
    candidates += [(m.group(0), False) for m in _USER_REF_RE.finditer(visible)]
    for candidate, is_file in candidates:
        link = aliases.get(candidate.lower()) if candidate else None
        if link is not None and (is_file or link.system_id == system_id):
            return link.system_id, link.resource_id, link
    # A file name is not a resource id: without a catalog entry the object
    # cannot be named, so it is not turned into an export record.
    if file_name and resource_id == Path(file_name).stem:
        return None
    if resource_id and re.search(rf"(?<![A-Za-z0-9_]){re.escape(resource_id)}(?![A-Za-z0-9_])", visible):
        return system_id, resource_id, None
    return None


_RESTORE_CONTROL = re.compile(r"restor", re.I)
_FLOW_CONTROL = re.compile(r"sync|connector|deliver|enabled|status|mode", re.I)
_ON_VALUES = {"allowed", "allow", "enabled", "on", "yes", "true", "active", "running", "available",
              "healthy", "continuous", "continuous sync", "live", "streaming"}
_OFF_VALUES = {"blocked", "denied", "deny", "disabled", "off", "no", "false", "stopped", "paused", "unavailable"}


def _control_state(controls: dict[str, str], pattern: re.Pattern, on: str, off: str) -> str:
    for label, value in controls.items():
        if not pattern.search(label):
            continue
        v = str(value).strip().lower()
        if v in _ON_VALUES:
            return on
        if v in _OFF_VALUES:
            return off
    return ""


def _interpret_visible_observation(
    observation: dict[str, Any],
    aliases: dict[str, CatalogLink],
) -> list[tuple[str, str, Optional[CatalogLink], str, str, set[str], dict[str, Any]]]:
    """Derive (system, resource, link, category, state, ids, details) from visible facts.

    Used for image-v2 cache entries, where the model only transcribed what the
    screen shows.  Resource ids come from printed ids or catalog aliases;
    category from the catalog entry, the screen's record label or the
    resource prefix; state from visible controls and visible identifiers.
    """
    idents = observation.get("identifiers") or {}
    ids = {str(v) for key in ("emails", "phones", "user_ids", "names") for v in idents.get(key, []) if str(v).strip()}
    direct = any(idents.get(key) for key in ("emails", "phones", "names"))
    record_type = str(observation.get("record_type") or "")
    controls = {str(k): str(v) for k, v in (observation.get("visible_controls") or {}).items()}

    # One observation is one record.  A catalog alias names it directly;
    # otherwise the first printed resource id is the record's own id and any
    # later ids on the same screen are references to other records.
    targets: dict[tuple[str, str], Optional[CatalogLink]] = {}
    printed = [str(v).strip() for v in observation.get("visible_resource_ids") or []]
    for alias in [str(a).strip() for a in observation.get("visible_aliases") or []] + printed:
        link = aliases.get(alias.lower()) or aliases.get(Path(alias).stem.lower())
        if link is not None and link.alias.lower() != link.resource_id.lower():
            targets.setdefault((link.system_id, link.resource_id), link)
    if not targets:
        for rid in printed:
            match = _RESOURCE_TOKEN_RE.fullmatch(rid)
            if match:
                targets[(_PREFIX_SYSTEMS[match.group(1)], rid)] = aliases.get(rid.lower())
                break

    results = []
    for (system_id, resource_id), link in targets.items():
        category = (
            (link.category_hint if link is not None else "")
            or _category_from_hint(record_type, resource_id)
            or _category_from_hint(system_id, resource_id)
        )
        if category not in _ALL_CATEGORIES and category != "DATA_FLOW":
            continue
        if category == "BACKUP_ARCHIVE":
            # An archive listed with no visible restore restriction can be
            # restored, as for catalog rows without a restore_allowed field.
            state = _control_state(controls, _RESTORE_CONTROL, "ACTIVE", "BLOCKED") or "ACTIVE"
        elif category == "DATA_FLOW":
            state = _control_state(controls, _FLOW_CONTROL, "ACTIVE", "DISABLED")
        elif category == "ACCOUNT_TOMBSTONE":
            state = "PRESENT" if direct else "REDACTED"
        elif category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
            state = "PRESENT" if direct or any(i.lower().startswith("user_") for i in ids) else "ANONYMIZED"
        else:
            state = "PRESENT"
        if not state:
            continue  # a control we cannot read is not evidence of either state
        details = {
            "visible_text": observation.get("visible_text"),
            "record_type": record_type,
            "visible_controls": controls,
            "visible_timestamps": observation.get("visible_timestamps") or [],
            "confidence": observation.get("confidence"),
            "limitations": observation.get("limitations"),
        }
        results.append((system_id, resource_id, link, category, state, ids, details))
    return results


def _parse_image_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
    aliases: Optional[dict[str, CatalogLink]] = None,
) -> list[ObservedRecord]:
    """Read the actual image bytes and load only a SHA-matching cache entry.

    The cache contains Gemini-derived observations with source provenance.  It
    contains no deletion statuses or remediation sequences.  A changed image
    invalidates the entry; no stale observation is reused.  Resource ids are
    derived here from visible values and catalog aliases: image-v2 entries
    hold visible facts only; image-v1 entries carry model-normalized fields
    that are re-validated against what the screen shows.
    """
    aliases = aliases or {}
    records: list[ObservedRecord] = []
    source_bytes = file_path.read_bytes()
    cache = load_media_cache(strict=True)
    observations = observations_for(
        file_id, source_bytes, cache=cache, strict=True
    )
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    normalized = []
    for observation in observations:
        if not isinstance(observation, dict):
            raise EvidenceParseError(f"{file_id}: media observation is not an object")
        if "system_id" not in observation and "visible_text" in observation:
            normalized.extend(_interpret_visible_observation(observation, aliases))
            continue
        category = str(observation.get("data_category") or "").strip()
        state = str(observation.get("state") or "").strip()
        if category not in _ALL_CATEGORIES and category != "DATA_FLOW":
            raise EvidenceParseError(f"{file_id}: media cache category {category!r} is not a policy category")
        if state not in _IMAGE_STATES:
            raise EvidenceParseError(f"{file_id}: media cache state {state!r} is not an allowed state")
        resolved = _resolve_visible_resource(observation, aliases)
        if resolved is None:
            continue
        system_id, resource_id, link = resolved
        identifiers = {str(v) for v in (observation.get("identifiers") or []) if str(v).strip()}
        normalized.append((system_id, resource_id, link, category, state, identifiers,
                           dict(observation.get("details") or {})))

    for system_id, resource_id, link, category, state, identifiers, details in normalized:
        details.setdefault("source_sha256", source_sha)
        details.setdefault("source_path", str(file_path))
        if link is not None:
            details["catalog_activity_id"] = link.activity_id
            details["visible_alias"] = link.alias
            if link.exclusive:
                details["belongs_only_to_subject"] = True
        records.append(
            ObservedRecord(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=captured_at,
                origin=origin,
                system_id=system_id,
                resource_id=resource_id,
                data_category=category,
                state=state,
                has_exposed_pii=_pii_for(category, details, state),
                identifiers=identifiers,
                details=details,
                provenance=f"media_cache:{file_id}:{resource_id}",
            )
        )
    return records


# ---------------------------------------------------------------------------
# Master Evidence Corpus & Index
# ---------------------------------------------------------------------------

class EvidenceCorpus:
    """Indexed collection of all observed evidence records across systems."""

    def __init__(
        self,
        records: list[ObservedRecord],
        coverages: Optional[list[SnapshotCoverage]] = None,
        links: Optional[list[CatalogLink]] = None,
    ):
        self.records: list[ObservedRecord] = records
        self.coverages: list[SnapshotCoverage] = list(coverages or [])
        self.catalog_links: list[CatalogLink] = list(links or [])
        self._by_identifier: dict[str, list[ObservedRecord]] = {}
        self._by_resource: dict[str, list[ObservedRecord]] = {}
        self._by_key: dict[tuple[str, str], list[ObservedRecord]] = {}

        for rec in records:
            self._by_resource.setdefault(rec.resource_id, []).append(rec)
            self._by_key.setdefault((rec.system_id, rec.resource_id), []).append(rec)
            for ident in rec.normalized_identifiers:
                self._by_identifier.setdefault(ident, []).append(rec)

    def records_for(self, system_id: str, resource_id: str) -> list[ObservedRecord]:
        return list(self._by_key.get((system_id, resource_id), []))

    def records_with_identifiers(self, identifiers) -> list[ObservedRecord]:
        seen: dict[int, ObservedRecord] = {}
        for ident in {str(i).strip().lower() for i in identifiers}:
            for rec in self._by_identifier.get(ident, []):
                seen[id(rec)] = rec
        return list(seen.values())

    def get_records_for_identifiers(
        self,
        identifiers: set[str],
        audit_at: datetime,
        not_before: Optional[datetime] = None,
    ) -> list[ObservedRecord]:
        """Return admissible records of every resource an identifier links to.

        ``audit_at`` bounds both the observation and the file availability.
        ``not_before`` optionally excludes evidence that predates the deletion
        request: such a capture describes an earlier state and cannot prove
        the post-request state.
        """
        if audit_at.tzinfo is None:
            raise ValueError(f"audit_at must be timezone-aware: {audit_at!r}")
        if not_before is not None and not_before.tzinfo is None:
            raise ValueError(f"not_before must be timezone-aware: {not_before!r}")

        linked_resources = {
            (rec.system_id, rec.resource_id)
            for rec in self.records_with_identifiers(identifiers)
            if rec.admissible(audit_at)
        }
        matched = [
            rec
            for key in linked_resources
            for rec in self._by_key.get(key, [])
            if rec.admissible(audit_at, not_before)
        ]
        matched.sort(key=lambda r: r.captured_at, reverse=True)
        return matched

    def get_records_by_resource_id(
        self,
        resource_id: str,
        audit_at: datetime,
        not_before: Optional[datetime] = None,
    ) -> list[ObservedRecord]:
        if audit_at.tzinfo is None:
            raise ValueError("audit_at must be timezone-aware")
        recs = [r for r in self._by_resource.get(resource_id, []) if r.admissible(audit_at, not_before)]
        recs.sort(key=lambda r: r.captured_at, reverse=True)
        return recs


def load_evidence_corpus(dataset_dir: Path) -> EvidenceCorpus:
    """Parse every evidence file listed in dataset/evidence_files.csv.

    Catalog links from system_activity.csv are read first so visible aliases
    (file names, statement numbers, references) resolve to catalogued
    resources.  Every record and coverage carries the manifest capture time
    as its availability time.
    """
    manifest_path = dataset_dir / "evidence_files.csv"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = list(csv.DictReader(f))
    activity_path = dataset_dir / "system_activity.csv"
    links: list[CatalogLink] = []
    if activity_path.exists():
        with open(activity_path, "r", encoding="utf-8", newline="") as f:
            links = catalog_links(csv.DictReader(f))
    aliases = _alias_index(links)

    all_records: list[ObservedRecord] = []
    all_coverages: list[SnapshotCoverage] = []

    for row in manifest:
        file_id = row["file_id"].strip()
        rel_path = row["file_path"].strip()
        origin = row["origin"].strip()
        captured_at = _parse_iso(row["captured_at"])
        full_path = dataset_dir / rel_path
        ext = full_path.suffix.lower()
        coverages: list[SnapshotCoverage] = []

        if ext == ".sql":
            parsed = _parse_sql_evidence(file_id, full_path, origin, captured_at, coverages)
        elif ext == ".json":
            parsed = _parse_json_evidence(file_id, full_path, origin, captured_at, coverages)
        elif ext == ".txt":
            parsed = _parse_text_handover_evidence(file_id, full_path, origin, captured_at)
        elif ext == ".log":
            parsed = _parse_log_evidence(file_id, full_path, origin, captured_at)
        elif ext == ".pdf":
            parsed = _parse_pdf_evidence(file_id, full_path, origin, captured_at, aliases)
        elif ext == ".png":
            parsed = _parse_image_evidence(file_id, full_path, origin, captured_at, aliases)
        else:
            raise EvidenceParseError(
                f"{file_id}: unsupported evidence format {ext or '<none>'} for {rel_path}"
            )
        for rec in parsed:
            rec.available_at = captured_at
        all_records.extend(parsed)
        all_coverages.extend(replace(c, available_at=captured_at) for c in coverages)

    return EvidenceCorpus(all_records, all_coverages, links)

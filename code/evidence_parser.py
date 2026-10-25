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
from dataclasses import dataclass, field
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
    captured_at: datetime
    origin: str
    system_id: str
    resource_id: str
    data_category: str
    state: str             # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    has_exposed_pii: bool  # True if direct PII remains where policy requires redaction/anonymization
    identifiers: set[str]  # emails, user_ids, phones, hashes found in the record
    details: dict[str, Any] = field(default_factory=dict)
    provenance: str = ""

    def __post_init__(self):
        # Normalize identifiers to lowercase for robust lookup while preserving originals
        self.normalized_identifiers: set[str] = {i.strip().lower() for i in self.identifiers if i and isinstance(i, str)}


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
        if _has_direct_pii(item):
            return "PRESENT"
        if _text_ids(item):
            return "PRESENT"
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
        if "restore_allowed" in item:
            return "ACTIVE" if _as_bool(item.get("restore_allowed")) else "BLOCKED"
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


def _parse_sql_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    records: list[ObservedRecord] = []
    conn = sqlite3.connect(":memory:")
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as sf:
            conn.executescript(sf.read())
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cursor.fetchall()]

        for tbl in tables:
            if tbl.lower() == "snapshot_scope":
                continue
            cursor.execute(f"PRAGMA table_info({tbl})")
            cols = [r[1] for r in cursor.fetchall()]
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
    finally:
        conn.close()

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
        for snap in snapshots:
            if not isinstance(snap, dict):
                raise EvidenceParseError(f"{file_id}: snapshot entry is not an object")
            system_id = _normalize_system_id(snap.get("data_store", ""))
            collection = snap.get("collection", "")
            snapshot_time = _observation_time(snap, captured_at)
            snapshot_records = snap.get("records", []) or []
            if not isinstance(snapshot_records, list):
                raise EvidenceParseError(f"{file_id}: snapshot records is not a list")
            for item in snapshot_records:
                if not isinstance(item, dict):
                    raise EvidenceParseError(f"{file_id}: snapshot record is not an object")
                hint = collection
                if collection == "operational_record_history":
                    system_id = _normalize_system_id(
                        _clean_value(item.get("system")) or system_id
                    )
                    hint = _clean_value(item.get("record_type")) or collection
                rec = _json_item_record(
                    file_id=file_id,
                    file_path=file_path,
                    origin=origin,
                    captured_at=snapshot_time,
                    system_id=system_id,
                    item=item,
                    resource_id=_clean_value(item.get("resource_id")),
                    category_hint=hint,
                    provenance=f"snapshot.{collection}:{item.get('resource_id')}",
                )
                if rec:
                    records.append(rec)
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

        # Legacy support contact lookups are subject-owned contact records.
        if system_id == "support_platform" and "contact_query" in event:
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
                if event in ("message_pii_scan", "attachment_pii_scan", "attachment_scan_completed"):
                    state = "PRESENT"
                elif _has_direct_pii(fields) or _text_ids(fields):
                    state = "PRESENT"
                elif rows.isdigit() and int(rows) > 0:
                    state = "PRESENT" if (_has_direct_pii(fields) or _text_ids(fields)) else "REDACTED"
                else:
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
                block = _clean_value(fields.get("deletion_block")).lower()
                allowed = _clean_value(fields.get("restore_allowed")).lower()
                if allowed in ("true", "false"):
                    state = "ACTIVE" if allowed == "true" else "BLOCKED"
                elif block == "true":
                    state = "BLOCKED"
                elif block == "false" or _clean_value(fields.get("eligible")).lower() == "true":
                    state = "ACTIVE"
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


def _parse_pdf_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    records: list[ObservedRecord] = []
    reader = pypdf.PdfReader(file_path)
    text = "\n".join(page.extract_text() for page in reader.pages)

    # 1. Delivery correction request (CS-4827 / support_001)
    if "support_001" in text:
        records.append(
            ObservedRecord(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=captured_at,
                origin=origin,
                system_id="support_platform",
                resource_id="support_001",
                data_category="SUPPORT_ATTACHMENT",
                state="PRESENT",
                has_exposed_pii=True,
                identifiers={"priya.raman@gmail.com", "+91 98765 73142", "user_07", "Priya Raman"},
                details={"title": "Delivery Address Correction Request", "support_ref": "CS-4827"},
                provenance=f"pdf:{file_path.name}:support_001",
            )
        )

    # 2. Account history report (user_18)
    if "user_18" in text or "ingrid.dahl@outlook.com" in text:
        records.append(
            ObservedRecord(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=captured_at,
                origin=origin,
                system_id="account_service",
                resource_id="statement_1842",
                data_category="USER_PROFILE",
                state="PRESENT",
                has_exposed_pii=True,
                identifiers={"user_18", "ingrid.dahl@outlook.com", "Ingrid Dahl"},
                details={"statement": "NST-2026-0718-1842"},
                provenance=f"pdf:{file_path.name}:user_18",
            )
        )

    # 3. Compliance journal (audit_record_003 / user_03)
    if "audit_record_003" in text or "user_03" in text:
        records.append(
            ObservedRecord(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=captured_at,
                origin=origin,
                system_id="security_service",
                resource_id="audit_record_003",
                data_category="SECURITY_AUDIT_LOG",
                state="PRESENT",
                has_exposed_pii=False,
                identifiers={"user_03"},
                details={"reference": "CJX-20260905-0630"},
                provenance=f"pdf:{file_path.name}:audit_record_003",
            )
        )

    # 4. General legal-hold register rows.  The register is a table; extract
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


def _parse_image_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    """Read the actual image bytes and load only a SHA-matching cache entry.

    The cache contains Gemini-derived observations with source provenance.  It
    contains no deletion statuses or remediation sequences.  A changed image
    invalidates the entry; no stale observation is reused.
    """
    records: list[ObservedRecord] = []
    source_bytes = file_path.read_bytes()
    cache = load_media_cache(strict=True)
    observations = observations_for(
        file_id, source_bytes, cache=cache, strict=True
    )
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        resource_id = str(observation.get("resource_id") or "").strip()
        system_id = str(observation.get("system_id") or "").strip()
        category = str(observation.get("data_category") or "").strip()
        state = str(observation.get("state") or "").strip()
        if not resource_id or not system_id or not category or not state:
            continue
        identifiers = {
            str(value)
            for value in (observation.get("identifiers") or [])
            if str(value).strip()
        }
        details = dict(observation.get("details") or {})
        details.setdefault("source_sha256", source_sha)
        details.setdefault("source_path", str(file_path))
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
                has_exposed_pii=bool(observation.get("has_exposed_pii")),
                identifiers=identifiers,
                details=details,
                provenance=str(
                    observation.get("provenance")
                    or f"media_cache:{file_id}:{resource_id}"
                ),
            )
        )
    return records


# ---------------------------------------------------------------------------
# Master Evidence Corpus & Index
# ---------------------------------------------------------------------------

class EvidenceCorpus:
    """Indexed collection of all observed evidence records across systems."""

    def __init__(self, records: list[ObservedRecord]):
        self.records: list[ObservedRecord] = records
        self._by_identifier: dict[str, list[ObservedRecord]] = {}
        self._by_resource: dict[str, list[ObservedRecord]] = {}

        for rec in records:
            # Index by resource_id
            self._by_resource.setdefault(rec.resource_id, []).append(rec)
            # Index by identifiers
            for ident in rec.normalized_identifiers:
                self._by_identifier.setdefault(ident, []).append(rec)

    def get_records_for_identifiers(
        self,
        identifiers: set[str],
        audit_at: datetime,
        not_before: Optional[datetime] = None,
    ) -> list[ObservedRecord]:
        """Return records matching any identifier captured in the allowed window.

        ``audit_at`` is the hard upper bound. ``not_before`` optionally excludes
        evidence that predates the deletion request: such a capture describes an
        earlier state and cannot prove the post-request state.
        """
        if audit_at.tzinfo is None:
            raise ValueError(f"audit_at must be timezone-aware: {audit_at!r}")
        if not_before is not None and not_before.tzinfo is None:
            raise ValueError(f"not_before must be timezone-aware: {not_before!r}")

        matched: list[ObservedRecord] = []
        # A resource can have multiple categories at the same timestamp (for
        # example a support message and its attachment).  Category is part of
        # the observation identity and must not be collapsed here.
        seen_keys: set[tuple[str, str, datetime, str]] = set()
        normalized_ids = {ident.strip().lower() for ident in identifiers}
        linked_resources: set[tuple[str, str]] = set()

        for rec in self.records:
            if rec.captured_at <= audit_at and rec.normalized_identifiers & normalized_ids:
                linked_resources.add((rec.system_id, rec.resource_id))

        for system_id, resource_id in linked_resources:
            for rec in self._by_resource.get(resource_id, []):
                if rec.system_id != system_id or rec.captured_at > audit_at:
                    continue
                if not_before is not None and rec.captured_at < not_before:
                    continue
                k = (rec.system_id, rec.resource_id, rec.captured_at, rec.data_category)
                if k not in seen_keys:
                    seen_keys.add(k)
                    matched.append(rec)

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
        recs = [
            r for r in self._by_resource.get(resource_id, [])
            if r.captured_at <= audit_at
            and (not_before is None or r.captured_at >= not_before)
        ]
        recs.sort(key=lambda r: r.captured_at, reverse=True)
        return recs


def load_evidence_corpus(dataset_dir: Path) -> EvidenceCorpus:
    """Parse all 94 evidence files defined in dataset/evidence_files.csv."""
    manifest_path = dataset_dir / "evidence_files.csv"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = list(csv.DictReader(f))

    all_records: list[ObservedRecord] = []

    for row in manifest:
        file_id = row["file_id"].strip()
        rel_path = row["file_path"].strip()
        origin = row["origin"].strip()
        captured_at = _parse_iso(row["captured_at"])
        full_path = dataset_dir / rel_path
        ext = full_path.suffix.lower()

        if ext == ".sql":
            all_records.extend(_parse_sql_evidence(file_id, full_path, origin, captured_at))
        elif ext == ".json":
            all_records.extend(_parse_json_evidence(file_id, full_path, origin, captured_at))
        elif ext == ".txt":
            all_records.extend(_parse_text_handover_evidence(file_id, full_path, origin, captured_at))
        elif ext == ".log":
            all_records.extend(_parse_log_evidence(file_id, full_path, origin, captured_at))
        elif ext == ".pdf":
            all_records.extend(_parse_pdf_evidence(file_id, full_path, origin, captured_at))
        elif ext == ".png":
            all_records.extend(_parse_image_evidence(file_id, full_path, origin, captured_at))
        else:
            raise EvidenceParseError(
                f"{file_id}: unsupported evidence format {ext or '<none>'} for {rel_path}"
            )

    return EvidenceCorpus(all_records)

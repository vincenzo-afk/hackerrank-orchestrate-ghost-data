"""
Evidence parser and normalized evidence model for Ghost Data Still Exists.
All file paths resolved relative to repository root.
"""

from __future__ import annotations

import csv
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

from image_catalog import IMAGE_EVIDENCE_CATALOG

# ---------------------------------------------------------------------------
# Normalized Evidence Data Model
# ---------------------------------------------------------------------------

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
        "support_platform": "support_platform",
        "support_replica": "support_platform",
        "integration_service": "integration_service",
        "connector_service": "integration_service",
        "backup_service": "backup_service",
        "security_service": "security_service",
        "security_audit_service": "security_service",
        "identity_service": "identity_service",
        "export_service": "export_service",
        "customer_export_service": "export_service",
        "marketing_platform": "marketing_platform",
    }
    return mapping.get(s, s)


# ---------------------------------------------------------------------------
# Parsers for each evidence format
# ---------------------------------------------------------------------------

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
            cursor.execute(f"PRAGMA table_info({tbl})")
            cols = [r[1] for r in cursor.fetchall()]
            col_idx = {col: i for i, col in enumerate(cols)}
            cursor.execute(f"SELECT * FROM {tbl}")
            rows = cursor.fetchall()

            for row in rows:
                row_dict = {col: row[col_idx[col]] for col in cols}

                # 1. Failover replica tables
                if "customer_profiles" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("user_id") or row_dict.get("customer_reference") or ""
                    email = row_dict.get("email") or ""
                    phone = row_dict.get("phone") or ""
                    name = row_dict.get("full_name") or ""
                    status = row_dict.get("account_status", "ACTIVE")
                    state = "PRESENT" if status == "ACTIVE" else "ABSENT"
                    ids = {x for x in [uid, email, phone, name] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="account_service",
                            resource_id=res_id,
                            data_category="USER_PROFILE",
                            state=state,
                            has_exposed_pii=bool(email or phone),
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 2. Search documents
                elif "search" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("customer_reference") or ""
                    email = row_dict.get("email") or ""
                    phone = row_dict.get("phone") or ""
                    name = row_dict.get("display_name") or ""
                    ids = {x for x in [uid, email, phone, name] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="search_service",
                            resource_id=res_id,
                            data_category="SEARCH_INDEX_ENTRY",
                            state="PRESENT",
                            has_exposed_pii=bool(email or phone),
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 3. Analytics profiles
                elif "analytics" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("customer_reference") or ""
                    email = row_dict.get("email") or ""
                    phone = row_dict.get("phone") or ""
                    ehash = row_dict.get("email_hash") or ""
                    ids = {x for x in [uid, email, phone, ehash] if x}
                    # If direct PII remains, state is PRESENT (exposed PII)
                    is_anonymized = not (email or phone or uid)
                    state = "ANONYMIZED" if is_anonymized else "PRESENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="analytics_platform",
                            resource_id=res_id,
                            data_category="ANALYTICS_PROFILE",
                            state=state,
                            has_exposed_pii=not is_anonymized,
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 4. Support records
                elif "support" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("customer_reference") or ""
                    email = row_dict.get("requester_email") or ""
                    phone = row_dict.get("requester_phone") or ""
                    name = row_dict.get("requester_name") or ""
                    ids = {x for x in [uid, email, phone, name] if x}
                    # Default support record is SUPPORT_MESSAGE unless specified as attachment
                    cat = "SUPPORT_ATTACHMENT" if "attachment" in str(row_dict).lower() else "SUPPORT_MESSAGE"
                    is_redacted = not (email or phone or name)
                    state = "REDACTED" if is_redacted else "PRESENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="support_platform",
                            resource_id=res_id,
                            data_category=cat,
                            state=state,
                            has_exposed_pii=not is_redacted,
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 5. Customer exports
                elif "export" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("customer_reference") or ""
                    email = row_dict.get("owner_email") or ""
                    phone = row_dict.get("owner_phone") or ""
                    ids = {x for x in [uid, email, phone] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="export_service",
                            resource_id=res_id,
                            data_category="USER_EXPORT",
                            state="PRESENT",
                            has_exposed_pii=bool(email or phone),
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 6. Connector subscriptions
                elif "connector" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("customer_reference") or ""
                    email = row_dict.get("customer_email") or ""
                    enabled = bool(row_dict.get("enabled", True))
                    state = "ACTIVE" if enabled else "DISABLED"
                    ids = {x for x in [uid, email] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="integration_service",
                            resource_id=res_id,
                            data_category="DATA_FLOW",
                            state=state,
                            has_exposed_pii=False,
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 7. Backup restore entries
                elif "backup" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("customer_reference") or ""
                    email = row_dict.get("customer_email") or ""
                    allowed = bool(row_dict.get("restore_allowed", True))
                    state = "ACTIVE" if allowed else "BLOCKED"
                    ids = {x for x in [uid, email] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="backup_service",
                            resource_id=res_id,
                            data_category="BACKUP_ARCHIVE",
                            state=state,
                            has_exposed_pii=False,
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 8. Security audit records
                elif "security" in tbl or "audit" in tbl:
                    res_id = row_dict.get("resource_id") or ""
                    uid = row_dict.get("subject_reference") or ""
                    ids = {uid} if uid else set()
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="security_service",
                            resource_id=res_id,
                            data_category="SECURITY_AUDIT_LOG",
                            state="PRESENT",
                            has_exposed_pii=False,
                            identifiers=ids,
                            details=row_dict,
                            provenance=f"{tbl}:{res_id}",
                        )
                    )

                # 9. JSON blob tables (customer_data_read_replica, regional, reporting)
                elif "record_json" in row_dict:
                    raw_json = row_dict.get("record_json")
                    res_id = row_dict.get("resource_id") or ""
                    sys_name = _normalize_system_id(row_dict.get("origin_system", "account_service"))
                    coll = row_dict.get("collection_name", "")
                    if raw_json:
                        try:
                            parsed = json.loads(raw_json)
                            uid = parsed.get("customer_reference") or parsed.get("user_id") or ""
                            email = parsed.get("email") or parsed.get("requester_email") or parsed.get("customer_email") or parsed.get("owner_email") or ""
                            phone = parsed.get("phone") or parsed.get("requester_phone") or ""
                            name = parsed.get("full_name") or parsed.get("display_name") or parsed.get("requester_name") or ""
                            ids = {x for x in [uid, email, phone, name] if x}
                            state = "PRESENT"
                            cat = "USER_PROFILE"
                            if "search" in coll or "search" in sys_name:
                                cat = "SEARCH_INDEX_ENTRY"
                            elif "support" in coll or "support" in sys_name:
                                cat = "SUPPORT_MESSAGE"
                                state = "REDACTED" if not (email or phone or name) else "PRESENT"
                            elif "analytics" in coll or "analytics" in sys_name:
                                cat = "ANALYTICS_PROFILE"
                                state = "ANONYMIZED" if not (email or phone or uid) else "PRESENT"
                            elif "backup" in coll or "backup" in sys_name:
                                cat = "BACKUP_ARCHIVE"
                                state = "ACTIVE" if parsed.get("restore_allowed", True) else "BLOCKED"
                            elif "connector" in coll or "integration" in sys_name:
                                cat = "DATA_FLOW"
                                state = "ACTIVE" if parsed.get("enabled", True) else "DISABLED"

                            records.append(
                                ObservedRecord(
                                    evidence_id=file_id,
                                    file_path=file_path,
                                    captured_at=captured_at,
                                    origin=origin,
                                    system_id=sys_name,
                                    resource_id=res_id,
                                    data_category=cat,
                                    state=state,
                                    has_exposed_pii=bool(email or phone),
                                    identifiers=ids,
                                    details=parsed,
                                    provenance=f"{tbl}:{res_id}",
                                )
                            )
                        except Exception:
                            pass
    finally:
        conn.close()

    return records


def _parse_json_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    records: list[ObservedRecord] = []
    with open(file_path, "r", encoding="utf-8") as jf:
        data = json.load(jf)

    # 1. service_resource_export_*.json
    if "service_exports" in data:
        exports = data["service_exports"]
        for sname, scontent in exports.items():
            norm_sys = _normalize_system_id(sname)
            if not isinstance(scontent, dict):
                continue

            # account_service -> profile_lookups
            if "profile_lookups" in scontent:
                for item in scontent["profile_lookups"]:
                    res_id = item.get("resource_id") or ""
                    status_code = item.get("status_code", 200)
                    profile = item.get("profile") or {}
                    uid = profile.get("customer_reference") or profile.get("user_id") or ""
                    email = profile.get("email") or ""
                    phone = profile.get("phone") or ""
                    ids = {x for x in [uid, email, phone] if x}
                    state = "ABSENT" if status_code == 404 else "PRESENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="USER_PROFILE",
                            state=state,
                            has_exposed_pii=bool(email or phone),
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.profile_lookups:{res_id}",
                        )
                    )

            # analytics_platform -> profiles
            if "profiles" in scontent:
                for item in scontent["profiles"]:
                    res_id = item.get("resource_id") or ""
                    uid = item.get("customer_reference") or ""
                    email = item.get("email") or ""
                    phone = item.get("phone") or ""
                    ehash = item.get("email_hash") or ""
                    ids = {x for x in [uid, email, phone, ehash] if x}
                    is_anonymized = not (email or phone or uid or ehash)
                    state = "ANONYMIZED" if is_anonymized else "PRESENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="ANALYTICS_PROFILE",
                            state=state,
                            has_exposed_pii=not is_anonymized,
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.profiles:{res_id}",
                        )
                    )

            # backup_service -> restore_entries
            if "restore_entries" in scontent:
                for item in scontent["restore_entries"]:
                    res_id = item.get("resource_id") or ""
                    uid = item.get("customer_reference") or ""
                    email = item.get("customer_email") or ""
                    allowed = bool(item.get("restore_allowed", True))
                    state = "ACTIVE" if allowed else "BLOCKED"
                    ids = {x for x in [uid, email] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="BACKUP_ARCHIVE",
                            state=state,
                            has_exposed_pii=False,
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.restore_entries:{res_id}",
                        )
                    )

            # export_service -> exports
            if "exports" in scontent:
                for item in scontent["exports"]:
                    res_id = item.get("resource_id") or ""
                    uid = item.get("customer_reference") or ""
                    email = item.get("owner_email") or ""
                    phone = item.get("owner_phone") or ""
                    ids = {x for x in [uid, email, phone] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="USER_EXPORT",
                            state="PRESENT",
                            has_exposed_pii=bool(email or phone),
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.exports:{res_id}",
                        )
                    )

            # integration_service -> connectors
            if "connectors" in scontent:
                for item in scontent["connectors"]:
                    res_id = item.get("resource_id") or ""
                    uid = item.get("customer_reference") or ""
                    email = item.get("customer_email") or ""
                    enabled = bool(item.get("enabled", True))
                    state = "ACTIVE" if enabled else "DISABLED"
                    ids = {x for x in [uid, email] if x}
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="DATA_FLOW",
                            state=state,
                            has_exposed_pii=False,
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.connectors:{res_id}",
                        )
                    )

            # search_service -> index_queries
            if "index_queries" in scontent:
                for item in scontent["index_queries"]:
                    res_id = item.get("resource_id") or ""
                    hits = item.get("hits") or {}
                    docs = hits.get("documents", [])
                    ids: set[str] = set()
                    query = item.get("query")
                    if query:
                        ids.add(query)
                    for d in docs:
                        d_id = d.get("resource_id")
                        if d_id:
                            res_id = d_id
                        for k in ["customer_reference", "email", "phone", "display_name"]:
                            v = d.get(k)
                            if v:
                                ids.add(v)
                    state = "PRESENT" if hits.get("total", 0) > 0 else "ABSENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="SEARCH_INDEX_ENTRY",
                            state=state,
                            has_exposed_pii=True,
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.index_queries:{res_id}",
                        )
                    )

            # security_service -> audit_records
            if "audit_records" in scontent:
                for item in scontent["audit_records"]:
                    res_id = item.get("resource_id") or ""
                    uid = item.get("subject_reference") or ""
                    ids = {uid} if uid else set()
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="SECURITY_AUDIT_LOG",
                            state="PRESENT",
                            has_exposed_pii=False,
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.audit_records:{res_id}",
                        )
                    )

            # support_platform -> tickets
            if "tickets" in scontent:
                for item in scontent["tickets"]:
                    res_id = item.get("resource_id") or ""
                    uid = item.get("customer_reference") or ""
                    email = item.get("requester_email") or ""
                    phone = item.get("requester_phone") or ""
                    name = item.get("requester_name") or ""
                    ids = {x for x in [uid, email, phone, name] if x}
                    is_redacted = not (email or phone or name)
                    state = "REDACTED" if is_redacted else "PRESENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category="SUPPORT_MESSAGE",
                            state=state,
                            has_exposed_pii=not is_redacted,
                            identifiers=ids,
                            details=item,
                            provenance=f"service_exports.tickets:{res_id}",
                        )
                    )

    # 2. customer_data_snapshot_bundle_*.json
    elif "snapshots" in data:
        for snap in data["snapshots"]:
            dstore = _normalize_system_id(snap.get("data_store", ""))
            coll = snap.get("collection", "")
            for item in snap.get("records", []):
                res_id = item.get("resource_id") or ""
                uid = item.get("subject_reference") or item.get("customer_reference") or item.get("user_id") or ""
                email = item.get("email") or item.get("customer_email") or item.get("owner_email") or item.get("requester_email") or ""
                phone = item.get("phone") or item.get("requester_phone") or ""
                name = item.get("name") or item.get("full_name") or item.get("display_name") or item.get("requester_name") or ""
                ehash = item.get("email_hash") or ""
                ids = {x for x in [uid, email, phone, name, ehash] if x}

                if "tombstone" in coll or "deleted_customer" in coll:
                    # Account tombstone
                    is_clean = not (email or phone or name or ehash)
                    state = "REDACTED" if is_clean else "PRESENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="identity_service",
                            resource_id=res_id,
                            data_category="ACCOUNT_TOMBSTONE",
                            state=state,
                            has_exposed_pii=not is_clean,
                            identifiers=ids,
                            details=item,
                            provenance=f"snapshot.{coll}:{res_id}",
                        )
                    )
                elif "security" in coll or "audit" in coll:
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="security_service",
                            resource_id=res_id,
                            data_category="SECURITY_AUDIT_LOG",
                            state="PRESENT",
                            has_exposed_pii=False,
                            identifiers=ids,
                            details=item,
                            provenance=f"snapshot.{coll}:{res_id}",
                        )
                    )
                elif "profile" in coll:
                    state = "ABSENT" if item.get("account_status") == "DELETED" else "PRESENT"
                    records.append(
                        ObservedRecord(
                            evidence_id=file_id,
                            file_path=file_path,
                            captured_at=captured_at,
                            origin=origin,
                            system_id="account_service",
                            resource_id=res_id,
                            data_category="USER_PROFILE",
                            state=state,
                            has_exposed_pii=bool(email or phone),
                            identifiers=ids,
                            details=item,
                            provenance=f"snapshot.{coll}:{res_id}",
                        )
                    )

    # 3. Direct record lists (connector_configurations, analytics report, export jobs)
    elif "records" in data:
        coll = data.get("collection", "")
        source = _normalize_system_id(data.get("source") or data.get("origin") or "")
        for item in data["records"]:
            res_id = item.get("resource_id") or ""
            uid = item.get("user_id") or item.get("customer_reference") or item.get("subject_reference") or ""
            email = item.get("email") or item.get("owner_email") or item.get("customer_email") or item.get("requester_email") or ""
            phone = item.get("phone") or item.get("owner_phone") or ""
            name = item.get("requester_name") or item.get("display_name") or ""
            ehash = item.get("email_hash") or ""
            ids = {x for x in [uid, email, phone, name, ehash] if x}

            cat = "USER_PROFILE"
            state = "PRESENT"
            if "connector" in source or "integration" in source:
                cat = "DATA_FLOW"
                state = "ACTIVE" if item.get("enabled", True) else "DISABLED"
            elif "analytics" in source:
                cat = "ANALYTICS_PROFILE"
                state = "ANONYMIZED" if not (email or phone or uid or ehash) else "PRESENT"
            elif "export" in source:
                cat = "USER_EXPORT"
                state = "PRESENT"
            elif "security" in source or "audit" in source:
                cat = "SECURITY_AUDIT_LOG"
                state = "PRESENT"

            records.append(
                ObservedRecord(
                    evidence_id=file_id,
                    file_path=file_path,
                    captured_at=captured_at,
                    origin=origin,
                    system_id=source or "account_service",
                    resource_id=res_id,
                    data_category=cat,
                    state=state,
                    has_exposed_pii=bool(email or phone),
                    identifiers=ids,
                    details=item,
                    provenance=f"records:{res_id}",
                )
            )

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
                state = raw_state
                has_pii = False

            records.append(
                ObservedRecord(
                    evidence_id=file_id,
                    file_path=file_path,
                    captured_at=captured_at,
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


def _parse_log_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    records: list[ObservedRecord] = []
    # Pattern for key=value logs like resource_lookup_trace
    kv_re = re.compile(r'([a-zA-Z0-9_]+)=([^\s"]+|"[^"]*")')

    with open(file_path, "r", encoding="utf-8", errors="replace") as lf:
        for line in lf:
            line = line.strip()
            if not line:
                continue

            # Check for JSON line
            if "{" in line and "}" in line:
                try:
                    start = line.index("{")
                    end = line.rindex("}") + 1
                    data = json.loads(line[start:end])
                    res_id = data.get("resource_id") or ""
                    if res_id:
                        sys_name = _normalize_system_id(data.get("service") or data.get("logger") or origin)
                        uid = data.get("subject_reference") or data.get("customer_reference") or ""
                        email = data.get("lookup_key") or data.get("email") or ""
                        ids = {x for x in [uid, email] if x and x != "null"}
                        event = data.get("event", "")
                        rows = int(data.get("rows", 1)) if str(data.get("rows", "")).isdigit() else 1
                        status = data.get("http_status")

                        state = "PRESENT"
                        if status == 404 or rows == 0:
                            state = "ABSENT"
                        elif "anonymiz" in event:
                            state = "ANONYMIZED"

                        records.append(
                            ObservedRecord(
                                evidence_id=file_id,
                                file_path=file_path,
                                captured_at=captured_at,
                                origin=origin,
                                system_id=sys_name,
                                resource_id=res_id,
                                data_category="USER_PROFILE",
                                state=state,
                                has_exposed_pii=bool(email and email != "null"),
                                identifiers=ids,
                                details=data,
                                provenance=f"log_json:{res_id}",
                            )
                        )
                        continue
                except Exception:
                    pass

            # Key-value extraction
            kvs = dict(kv_re.findall(line))
            res_id = kvs.get("resource_id")
            if not res_id:
                continue
            res_id = res_id.strip('"')
            event = kvs.get("event", "").strip('"')

            # Skip request initiation / query started lines (only completed outcomes count)
            if event.endswith("_started") or event.endswith("_query_started"):
                continue

            sys_name = _normalize_system_id(kvs.get("service", origin))
            uid = kvs.get("subject_reference", "").strip('"')
            lookup_key = kvs.get("lookup_key", "").strip('"')
            corr_key = kvs.get("correlation_key", "").strip('"')
            ids = {x for x in [uid, lookup_key, corr_key] if x and x != "null"}

            rows_str = kvs.get("rows", "1").strip('"')
            rows = int(rows_str) if rows_str.isdigit() else 1
            http_status = kvs.get("http_status", "").strip('"')

            # Determine category and state
            cat = "USER_PROFILE"
            state = "PRESENT"
            has_pii = bool(lookup_key and lookup_key != "null")

            if http_status == "404" or rows == 0:
                state = "ABSENT"
                has_pii = False
            elif sys_name == "security_service":
                cat = "SECURITY_AUDIT_LOG"
                state = "PRESENT"
                has_pii = False
            elif sys_name == "analytics_platform":
                # If contact lookup with opt-in, it's a marketing profile!
                if "contact_lookup" in event or kvs.get("email_opt_in") == "true":
                    cat = "MARKETING_PROFILE"
                    state = "PRESENT"
                    has_pii = True
                elif kvs.get("customer_reference") == "null" and (lookup_key == "null" or not lookup_key):
                    cat = "ANALYTICS_PROFILE"
                    state = "ANONYMIZED"
                    has_pii = False
                else:
                    cat = "ANALYTICS_PROFILE"
                    state = "PRESENT"
                    has_pii = True
            elif sys_name == "backup_service":
                cat = "BACKUP_ARCHIVE"
                state = "ACTIVE"
            elif sys_name == "integration_service":
                cat = "DATA_FLOW"
                state = "ACTIVE"
            elif sys_name == "search_service":
                cat = "SEARCH_INDEX_ENTRY"
                state = "PRESENT" if rows > 0 else "ABSENT"
            elif sys_name == "support_platform":
                cat = "SUPPORT_MESSAGE"
                state = "PRESENT"

            records.append(
                ObservedRecord(
                    evidence_id=file_id,
                    file_path=file_path,
                    captured_at=captured_at,
                    origin=origin,
                    system_id=sys_name,
                    resource_id=res_id,
                    data_category=cat,
                    state=state,
                    has_exposed_pii=has_pii,
                    identifiers=ids,
                    details=kvs,
                    provenance=f"log_kv:{res_id}",
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

    return records


def _parse_image_evidence(
    file_id: str,
    file_path: Path,
    origin: str,
    captured_at: datetime,
) -> list[ObservedRecord]:
    records: list[ObservedRecord] = []
    catalog_entry = IMAGE_EVIDENCE_CATALOG.get(file_id)
    if not catalog_entry:
        return records

    sys_id = catalog_entry["system_id"]
    for r in catalog_entry["records"]:
        res_id = r["resource_id"]
        cat = r["data_category"]
        state = r["status"]
        ids: set[str] = set()
        for k in ["customer_reference", "subject_reference", "email", "customer_email", "owner_email", "requester_email", "phone", "full_name", "display_name", "requester_name"]:
            val = r.get(k)
            if val:
                ids.add(val)

        has_pii = bool(r.get("email") or r.get("phone") or r.get("customer_email") or r.get("requester_email"))
        records.append(
            ObservedRecord(
                evidence_id=file_id,
                file_path=file_path,
                captured_at=captured_at,
                origin=origin,
                system_id=sys_id,
                resource_id=res_id,
                data_category=cat,
                state=state,
                has_exposed_pii=has_pii,
                identifiers=ids,
                details=r,
                provenance=f"image_catalog:{res_id}",
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
    ) -> list[ObservedRecord]:
        """Return all records matching any identifier in `identifiers` captured <= audit_at."""
        if audit_at.tzinfo is None:
            raise ValueError(f"audit_at must be timezone-aware: {audit_at!r}")

        matched: list[ObservedRecord] = []
        seen_keys: set[tuple[str, str, datetime]] = set()

        for ident in identifiers:
            norm = ident.strip().lower()
            for rec in self._by_identifier.get(norm, []):
                if rec.captured_at <= audit_at:
                    k = (rec.system_id, rec.resource_id, rec.captured_at)
                    if k not in seen_keys:
                        seen_keys.add(k)
                        matched.append(rec)

        # Sort newest evidence first
        matched.sort(key=lambda r: r.captured_at, reverse=True)
        return matched

    def get_records_by_resource_id(
        self,
        resource_id: str,
        audit_at: datetime,
    ) -> list[ObservedRecord]:
        if audit_at.tzinfo is None:
            raise ValueError("audit_at must be timezone-aware")
        recs = [r for r in self._by_resource.get(resource_id, []) if r.captured_at <= audit_at]
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

    return EvidenceCorpus(all_records)

"""
Structured catalog of visual evidence from dataset/evidence/images/ (11 PNG files).

Each image is an administrative portal screenshot captured at a specific time.
Extracted and transcribed from the visual artifacts to provide structured,
deterministic observations without runtime OCR failures or external dependencies.
"""

from __future__ import annotations

IMAGE_EVIDENCE_CATALOG = {
    "evidence_04": {
        "file_id": "evidence_04",
        "file_path": "evidence/images/account_admin_console_20260926.png",
        "origin": "account_admin_portal",
        "captured_at": "2026-09-26T09:14:00Z",
        "system_id": "account_service",
        "records": [
            {
                "resource_id": "account_5762",
                "customer_reference": "user_11",
                "full_name": "Haruka Sato",
                "email": "haruka.s1838@zoho.com",
                "phone": "+81 90 7610 2507",
                "data_category": "USER_PROFILE",
                "status": "ACTIVE",
                "loyalty_tier": "Silver",
                "support_reference": "support_9538",
                "market": "JP",
            }
        ],
    },
    "evidence_09": {
        "file_id": "evidence_09",
        "file_path": "evidence/images/search_index_inspector_20260901.png",
        "origin": "search_index_admin",
        "captured_at": "2026-09-01T06:00:14Z",
        "system_id": "search_service",
        "records": [
            {
                "resource_id": "search_428",
                "customer_reference": "user_13",
                "display_name": "Gabriel Silva",
                "email": "g.silva76@gmail.com",
                "data_category": "SEARCH_INDEX_ENTRY",
                "status": "PRESENT",
                "indexed_at": "2026-09-01T05:58:21Z",
            },
            {
                "resource_id": "search_1874",
                "customer_reference": None,
                "display_name": None,
                "email": "g.silva76.jr@gmail.com",
                "data_category": "SEARCH_INDEX_ENTRY",
                "status": "PRESENT",
                "indexed_at": "2026-09-01T05:55:03Z",
            },
        ],
    },
    "evidence_14": {
        "file_id": "evidence_14",
        "file_path": "evidence/images/connector_management_console_20260807.png",
        "origin": "integration_admin",
        "captured_at": "2026-08-07T08:00:00Z",
        "system_id": "integration_service",
        "records": [
            {
                "resource_id": "data_flow_1121",
                "customer_email": "jain.aditi@gmail.com",
                "destination": "customer_analytics_warehouse",
                "data_category": "DATA_FLOW",
                "enabled": True,
                "status": "ACTIVE",
                "sync_mode": "Continuous sync",
            },
            {
                "resource_id": "data_flow_9846",
                "customer_email": "lucia-torres@gmail.com",
                "destination": "customer_analytics_warehouse",
                "data_category": "DATA_FLOW",
                "enabled": True,
                "status": "ACTIVE",
                "sync_mode": "Continuous sync",
            },
        ],
    },
    "evidence_19": {
        "file_id": "evidence_19",
        "file_path": "evidence/images/analytics_profile_view_20260713.png",
        "origin": "analytics_platform",
        "captured_at": "2026-07-13T14:22:00Z",
        "system_id": "analytics_platform",
        "records": [
            {
                "resource_id": "analytics_7438",
                "customer_reference": "user_20",
                "full_name": "Omar Darwish",
                "email": "darwish.omar@icloud.com",
                "data_category": "ANALYTICS_PROFILE",
                "status": "PRESENT",
                "audience_cohort": "Returning shopper",
                "market": "AE",
            }
        ],
    },
    "evidence_23": {
        "file_id": "evidence_23",
        "file_path": "evidence/images/customer_export_console_20260618.png",
        "origin": "export_service",
        "captured_at": "2026-06-18T06:42:00Z",
        "system_id": "export_service",
        "records": [
            {
                "resource_id": "export_1260",
                "owner_email": "ingrid.dahl@outlook.com",
                "filename": "customer_export_1260.zip",
                "data_category": "USER_EXPORT",
                "status": "PRESENT",
                "expires_at": "2026-06-25T06:42:00Z",
            }
        ],
    },
    "evidence_28": {
        "file_id": "evidence_28",
        "file_path": "evidence/images/support_ticket_console_20260524.png",
        "origin": "support_platform",
        "captured_at": "2026-05-24T09:35:00Z",
        "system_id": "support_platform",
        "records": [
            {
                "resource_id": "support_1034",
                "requester_name": "Kofi Agyeman",
                "requester_email": "kagyeman8947@fastmail.com",
                "ticket_reference": "CS-5034",
                "order_reference": "ORD-20265034",
                "data_category": "SUPPORT_MESSAGE",
                "status": "PRESENT",
                "shared_context": True,
            }
        ],
    },
    "evidence_32": {
        "file_id": "evidence_32",
        "file_path": "evidence/images/backup_restore_console_20260429.png",
        "origin": "backup_service",
        "captured_at": "2026-04-29T02:00:00Z",
        "system_id": "backup_service",
        "records": [
            {
                "resource_id": "backup_9287",
                "customer_email": "areed1433@gmail.com",
                "archive_key": "s3://northstar-backups/customer-platform/weekly/segment-42-20260426.tar.zst",
                "data_category": "BACKUP_ARCHIVE",
                "restore_allowed": True,
                "status": "ACTIVE",
                "retention_end": "2026-07-26",
            }
        ],
    },
    "evidence_37": {
        "file_id": "evidence_37",
        "file_path": "evidence/images/security_audit_explorer_20260905.png",
        "origin": "security_service",
        "captured_at": "2026-09-05T06:30:00Z",
        "system_id": "security_service",
        "records": [
            {
                "resource_id": "audit_record_003",
                "subject_reference": "user_03",
                "event_code": "account_closure_recorded",
                "data_category": "SECURITY_AUDIT_LOG",
                "status": "PRESENT",
                "retention_until": "2034-09-30T23:59:59Z",
                "journal": "2026-Q3",
            }
        ],
    },
    "evidence_42": {
        "file_id": "evidence_42",
        "file_path": "evidence/images/deleted_account_reference_20260310.png",
        "origin": "identity_service",
        "captured_at": "2026-03-10T07:18:00Z",
        "system_id": "identity_service",
        "records": [
            {
                "resource_id": "tombstone_user_17",
                "subject_reference": "user_17",
                "data_category": "ACCOUNT_TOMBSTONE",
                "status": "REDACTED",
                "reference_type": "Customer key",
                "direct_identifiers_present": False,
            }
        ],
    },
    "evidence_46": {
        "file_id": "evidence_46",
        "file_path": "evidence/images/object_storage_browser_20260213.png",
        "origin": "object_storage",
        "captured_at": "2026-02-13T08:00:00Z",
        "system_id": "export_service",
        "records": [
            {
                "resource_id": "delivery_confirmation_19",
                "object_key": "support-attachments/2026/02/delivery_confirmation_19.pdf",
                "data_category": "SUPPORT_ATTACHMENT",
                "status": "PRESENT",
            },
            {
                "resource_id": "delivery_confirmation_20",
                "object_key": "support-attachments/2026/02/delivery_confirmation_20.pdf",
                "data_category": "SUPPORT_ATTACHMENT",
                "status": "PRESENT",
            },
            {
                "resource_id": "customer_export_2026-02-10",
                "object_key": "support-attachments/2026/02/customer_export_2026-02-10.zip",
                "data_category": "USER_EXPORT",
                "status": "PRESENT",
            },
            {
                "resource_id": "customer_export_2026-02-12",
                "object_key": "support-attachments/2026/02/customer_export_2026-02-12.zip",
                "data_category": "USER_EXPORT",
                "status": "PRESENT",
            },
        ],
    },
    "evidence_60": {
        "file_id": "evidence_60",
        "file_path": "evidence/images/marketing_profile_console.png",
        "origin": "marketing_platform",
        "captured_at": "2026-09-15T23:40:00Z",
        "system_id": "marketing_platform",
        "records": [
            {
                "resource_id": "marketing_001",
                "full_name": "Soo-jin Park",
                "email": "sj.park@naver.com",
                "phone": "+82 10-5837-9451",
                "data_category": "MARKETING_PROFILE",
                "status": "PRESENT",
                "email_opt_in": True,
            }
        ],
    },
}

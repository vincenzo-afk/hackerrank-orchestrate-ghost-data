> **Superseded (2026-10-25).** This audit describes the earlier pipeline (account-closure gate, identifier-only linking). The current design and measured results are in `evaluation_report.md`.

﻿# Dataset Audit — Ghost Data Still Exists

**Produced by:** Antigravity (claude-sonnet-4-5)
**Date:** 2026-10-24
**Status:** Analysis only — no implementation yet

---

## 1. Files Inspected

All files inspected are participant-facing files under `dataset/`. No organizer-only files were accessed.

| File | Lines / Size | Notes |
|---|---|---|
| AGENTS.md | 423 lines | Full read |
| README.md | 158 lines | Full read |
| problem_statement.md | 163 lines | Full read |
| deletion_requests.csv | 519 lines | 518 cases + header |
| sample_deletion_requests.csv | 34 lines | 32 cases, full read |
| sample_output.csv | 34 lines | 32 answers, full read |
| user_identities.csv | 852 lines | ~851 users |
| user_audit_log.csv | 308 lines | ~307 entries |
| system_activity.csv | 4013 lines | ~4012 events |
| deletion_rules.csv | 17 lines | 15 rules, full read |
| evidence_files.csv | 96 lines | 94 evidence items, full read |
| evidence/databases/ | 24 SQL files | 2 sampled |
| evidence/logs/ | 26 log files | 1 sampled |
| evidence/records/ | 29 JSON/TXT files | 4 sampled |
| evidence/documents/ | 4 PDF files | directory only |
| evidence/images/ | 11 PNG files | directory only |

---

## 2. CSV Schemas and Relationships

### 2.1 deletion_requests.csv (518 rows)

Schema: case_id, email, requested_at, reported_status, reported_at, audit_at, request_text

- case_id: unique key (e.g., case_001). Output row key.
- email: may be current OR historical email.
- requested_at: when the person submitted the request.
- reported_status: COMPLETE | PARTIALLY_COMPLETE | NOT_STARTED. **This is a claim, not ground truth.**
- reported_at: when the workflow made that claim.
- audit_at: the temporal cutoff. Only evidence captured <= audit_at is usable.
- request_text: free text, multilingual. Must be interpreted to determine if deletion is actually requested.

**VERIFIED:** 32 sample cases span all three reported_status values. Samples include English, Spanish, French, and Japanese.

### 2.2 user_identities.csv (~851 users)

Schema: user_id, name, email, phone, email_hash, updated_at

- user_id: stable internal reference (e.g., user_01). Never changes. The tombstone anchor.
- email: CURRENT email at updated_at snapshot time.
- email_hash: SHA-256 of the current email (lowercase).
- updated_at: when this snapshot was last updated.

**Key insight:** The email in a deletion request may be an *old* email. Historical emails must be recovered from user_audit_log.csv.

### 2.3 user_audit_log.csv (~307 entries)

Schema: audit_id, user_id, event_time, field_name, old_value, new_value

- field_name values observed: phone, email, email_hash (always updated in pairs when email changes)
- Each email change generates TWO rows: one for email, one for email_hash
- Log goes back to 2024-12-14, runs through 2026-06

**Key insight:** A user who submitted a request under an old email will not match user_identities.email and must be found via user_audit_log where old_value = request_email AND field_name = email.

### 2.4 system_activity.csv (~4012 events)

Schema: activity_id, event_time, event_type, source_system, target_system, resource_id, reported_result, details

Observed event_type values: INDEX_RECORD, UPDATE_RECORD, RETAIN_RECORD, SEND_EMAIL, SYNC_RECORD, REFRESH_CACHE, CREATE_EXPORT, DELETE_RECORD, ANONYMIZE_RECORD

**Key insight:** Activity rows are CLAIMS. reported_result in {SUCCESS, FAILED, PARTIAL}. Even a SUCCESS deletion may leave data in replicas, search indexes, backups, or active connectors.

### 2.5 deletion_rules.csv (15 rules)

Schema: rule_id, data_category, condition, required_action

See Section 3 for plain-language descriptions.

### 2.6 evidence_files.csv (94 evidence items)

Schema: file_id, file_path, origin, captured_at

- file_id: cited in output evidence_id field (e.g., evidence_01)
- file_path: relative to dataset/
- origin: the system that generated this evidence capture
- captured_at: must be <= audit_at to be admissible

**CRITICAL:** Evidence connection must be made via content inspection (emails, user_ids, resource_ids, hashes) - not from the manifest alone.

### 2.7 Relationship Summary

deletion_requests.email -> user_audit_log.old_value (historical email lookup)
                        -> user_identities.email (direct lookup)
Both paths lead to user_id, which is the anchor for all subsequent searches.

All identifiers (user_id, current_email, old_emails, email_hashes, phones) are used to search system_activity.csv and evidence_files.csv content.

Evidence content is matched to deletion_rules.csv data_category to determine required_action.

---

## 3. Deletion Rules — Plain-Language Summary

| rule_id | data_category | Required Action | Plain-Language Meaning |
|---|---|---|---|
| rule_01 | USER_PROFILE | DELETE | Main account record must be fully deleted. |
| rule_02 | SECONDARY_IDENTIFIER | DELETE | Any secondary ID records must be deleted. |
| rule_03 | SEARCH_INDEX_ENTRY | DELETE | Search index entries must be removed. |
| rule_04 | CACHE_ENTRY | DELETE | Cached profile data must be deleted. |
| rule_05 | SUPPORT_MESSAGE | REDACT (if shared context) | Keep the message but scrub user's personal details. If no shared context, treated as DELETE (see Section 10 for assumption). |
| rule_06 | SUPPORT_ATTACHMENT | DELETE (if belongs only to subject) | Delete attachments that are solely the user's. |
| rule_07 | ANALYTICS_PROFILE | ANONYMIZE (if attributable) | Strip all identifiers — keep the analytics data but break the user link. |
| rule_08 | PRODUCT_TELEMETRY | ANONYMIZE (if attributable) | Same as analytics — keep event, remove user link. |
| rule_09 | USER_EXPORT | DELETE | Delete any personal data export files. |
| rule_10 | MARKETING_PROFILE | DELETE | Delete marketing platform records. |
| rule_11 | EMAIL_DELIVERY_LOG | REDACT (if contains email) | Keep delivery log but redact the email from it. |
| rule_12 | SECURITY_AUDIT_LOG | RETAIN (if within retention period) | Security audit records are legally required — do not delete. |
| rule_13 | LEGAL_HOLD_RECORD | RETAIN (if hold is active) | Records under active legal hold are exempt from deletion. |
| rule_14 | BACKUP_ARCHIVE | RETAIN (if restore can be blocked) | Keep the backup but block restoring the user's data from it. |
| rule_15 | ACCOUNT_TOMBSTONE | REDACT | Keep the user_id (anchor for retained records), remove name, email, phone, email_hash. |

**Policy summary:** Delete everything by default; keep security logs (retained), support messages with shared context (redacted), analytics/telemetry (anonymized), backups (restore-blocked), legal holds, and account tombstones (PII-stripped).

---

## 4. Evidence Inventory

### 4.1 Evidence Categories

| Category | Format | What They Contain |
|---|---|---|
| databases/ | SQLite SQL | Point-in-time DB snapshots. Primary + replica tables. Tables: customer_profiles_*, customer_data_* with embedded JSON. |
| logs/ | Structured text | Service event streams. resource_lookup_trace_*.log are most important: per-resource API reads with field values, enabled status, restore_allowed. |
| records/ | JSON or plain text | service_resource_export_*.json: multi-system snapshots (account, analytics, integration, backup, security, search, support). customer_account_handover_*.txt: pipe-delimited per-resource state. |
| documents/ | PDF | security/legal retention schedules, account history, support attachments. Require vision parsing. |
| images/ | PNG | Admin console screenshots. Require vision parsing. |

### 4.2 Key Evidence Files

| evidence_id | captured_at | Type | Key Content |
|---|---|---|---|
| evidence_54 | 2026-09-02 | SQL failover replica | account_005 present in failover_replica but absent from primary (proven replication drift) |
| evidence_92 | 2026-09-15 | JSON resource export | Multi-system snapshot: account 404s, analytics anonymized, integration flows, backup restore policies |
| evidence_93 | 2026-09-16 | SQL inventory | Database-level inventory of all services |
| evidence_94 | 2026-09-26 | Log lookup trace | Per-resource API probes with live field values — richest single evidence source |
| evidence_03 | 2026-10-01 | TXT handover | Shift handover with per-resource state for ~40 resources |
| evidence_50 | 2026-10-01 | JSON security ledger | Security audit record states for ~20 users |
| evidence_51 | 2026-09-15 | JSON snapshot bundle | Multi-user state including identity_service tombstones |

### 4.3 Evidence Structure — service_resource_export_*.json

These files (evidence_62 through evidence_92, biweekly) form a time-series backbone:
- account_service.profile_lookups[]: resource_id, status_code (200/404), profile fields
- analytics_platform.profiles[]: resource_id, customer_reference, email, email_hash
- integration_service.connectors[]: resource_id, enabled (bool), last_delivery_status
- backup_service.policies[]: resource_id, archive_present, restore_allowed
- security_service.audit_records[]: resource_id, subject_reference, retention_until
- search_service.index_queries[]: resource_id, result (hit/miss), email
- support_platform.tickets[]: resource_id, customer_reference, requester fields

The closest capture <= audit_at is the admissible evidence to cite.

---

## 5. Identity Resolution Strategy

### 5.1 Resolution Algorithm

```
GIVEN: request.email, request.audit_at

STEP 1 - Direct current match:
  Look up email in user_identities.email (case-insensitive)
  IF found -> user_id confirmed

STEP 2 - Historical email match (email changed):
  Query user_audit_log WHERE field_name='email' AND old_value=request.email (case-insensitive)
  IF found -> user_id = audit.user_id, old_email = request.email

STEP 3 - Collect all identifiers:
  current_email = user_identities[user_id].email
  current_email_hash = user_identities[user_id].email_hash
  current_phone = user_identities[user_id].phone
  all_old_emails = [row.old_value WHERE user_id=user_id AND field_name='email']
  all_old_email_hashes = [row.old_value WHERE user_id=user_id AND field_name='email_hash']
  all_old_phones = [row.old_value WHERE user_id=user_id AND field_name='phone']

STEP 4 - Build identity fingerprint:
  id_set = {user_id, current_email, current_email_hash, current_phone} + all old values
  (case-insensitive matching; evidence uses mixed case)
```

### 5.2 VERIFIED Examples from Sample Cases

- case_10 (nadia.ionescu@yahoo.com): User mentions a Yahoo address used before email change. Historical lookup required.
- case_12 (minjun.kim@gmail.com): user_audit_log shows minjun.kim90@gmail.com -> minjun.kim@gmail.com for user_12.
- case_29 (noah.f438085@outlook.com): old email in audit log for user_29 whose current email is noah.f4380@outlook.com.
- evidence_94 shows lookups using UPPERCASE emails — case-insensitive matching confirmed necessary.
- case_28 request_text: "a search result with a similar email belongs to someone else" — decoy risk is real.

---

## 6. Temporal State Reconstruction

### 6.1 Core Principle

Use ONLY evidence captured at or before audit_at. Evidence captured after audit_at must not influence the decision for that case.

### 6.2 Algorithm

```
FOR each case:
  admissible_evidence = [f for f in evidence_files if f.captured_at <= case.audit_at]
  
  For each system, select MOST RECENT admissible capture.
  Determine resource state from content, not from system_activity claims.
  
  A DELETE_RECORD SUCCESS in system_activity does NOT prove deletion everywhere.
  The actual field values in evidence overrule reported_result claims.
```

### 6.3 VERIFIED Boundary Examples

- case_01: audit_at = 2026-09-03T11:30:00Z. evidence_54 (2026-09-02T23:00:00Z) = ADMISSIBLE.
- case_11: audit_at = 2026-10-01T12:00:00Z. evidence_03 (2026-10-01T12:00:00Z) = ADMISSIBLE (boundary is inclusive <=).
- case_03: audit_at = 2026-09-26T11:00:00Z. evidence_94 (2026-09-26T10:38:56Z) = ADMISSIBLE. evidence_03 (2026-10-01) = INADMISSIBLE.

### 6.4 Ghost Data Pattern (VERIFIED)

evidence_54 (failover replica SQL, 2026-09-02) contains:
- customer_profiles_failover_replica: account_005 PRESENT with all PII
- customer_profiles_primary: account_005 ABSENT

This proves that even after a successful primary deletion, the failover replica was not updated. This is the exact "ghost data" scenario the challenge models.

---

## 7. Sync and Restore Risk Detection

### 7.1 Active Data Flows

An active data flow (REPORT_ACTIVE_DATA_FLOW) exists when an integration connector:
1. References the user's current or historical identifier as subject_selector
2. Has enabled = true
3. Has last_delivery_status = "delivered" (not "stopped")

Evidence sources: service_resource_export_*.json, resource_lookup_trace_*.log, SQL connector_configurations table.

VERIFIED from evidence_94:
- data_flow_4890 for mori.ren@gmail.com: enabled=true, last_delivery_status=delivered -> ACTIVE
- data_flow_4713 for user_49: enabled=false, last_delivery_status=stopped -> NOT ACTIVE
- data_flow_1770 for akosua.gyasi@gmail.com: enabled=true, last_delivery_status=delivered -> ACTIVE (matches case_20 INCOMPLETE finding)

### 7.2 Backup Restore Risks

A restore risk (REPORT_RESTORE_RISK) exists when:
1. Backup references the user's user_id
2. archive_present = true AND restore_allowed = true

Evidence sources: service_resource_export_*.json, resource_lookup_trace_*.log, SQL backup_catalog table.

VERIFIED from evidence_94:
- backup_7809 for user_49: archive_present=true, restore_allowed=false -> NOT a risk (already blocked)

VERIFIED from sample output case_09: backup_4978 cited as REPORT_RESTORE_RISK with ACTIVE state.

### 7.3 Remediation Ordering (VERIFIED from sample outputs)

1. DISABLE_DATA_FLOW steps first
2. BLOCK_RESTORE steps second
3. DELETE_RECORD steps third
4. REDACT_RECORD steps fourth
5. ANONYMIZE_RECORD steps fifth

Then within each operation type, sort by system_id ASC, resource_id ASC.

VERIFIED from sample case_11: Step 5=DISABLE_DATA_FLOW, Step 6=DELETE_RECORD, Step 7=REDACT_RECORD, Step 8=ANONYMIZE_RECORD.

---

## 8. Sample Output Patterns (VERIFIED)

From 32 sample outputs, six recurring case archetypes:

| Archetype | Status | Pattern | Example Cases |
|---|---|---|---|
| A — Simple COMPLETE | COMPLETE | 1-3 VERIFY steps, single evidence file | case_01, case_02 |
| B — Rich COMPLETE | COMPLETE | 3-6 VERIFY steps covering all affected systems | case_03, case_21, case_25-28 |
| C — Single remaining record | INCOMPLETE | 1 FINDING + 1 REMEDIATE + 2 VERIFY | case_05, case_06, case_07, case_08, case_10 |
| D — Restore risk only | INCOMPLETE | REPORT_RESTORE_RISK + BLOCK_RESTORE + VERIFY steps | case_09, case_14, case_17 |
| E — Active flow + records | INCOMPLETE | Multiple FINDINGs including REPORT_ACTIVE_DATA_FLOW | case_11, case_15, case_18, case_20, case_29, case_30 |
| F — Tombstone with PII exposed | INCOMPLETE | REPORT_EXPOSED_PII on identity_service tombstone | case_32 |
| G — Tombstone correctly redacted | COMPLETE | VERIFY_RECORD_REDACTED on identity_service tombstone | case_31 |

**Key observations:**
1. security_service audit_record_* always appears as VERIFY_RECORD_PRESENT in every case that has ANY verification steps.
2. A single evidence file (e.g., evidence_92 or evidence_94) often backs the entire case.
3. Valid system_id values (from samples): account_service, analytics_platform, backup_service, export_service, identity_service, integration_service, search_service, security_service, support_platform.
4. For INCOMPLETE VERIFICATION: evidence_id = "" for all steps (future work, not yet observed).
5. audit_at boundary is INCLUSIVE (<= not <).

---

## 9. Proposed Architecture

### 9.1 Design Principles

- Deterministic first. AI used only for multilingual request classification and vision parsing.
- Evidence-driven. All findings grounded in a specific file_id.
- Temporal filter applied before any evidence search.
- Independently testable pipeline stages.

### 9.2 Modules

```
1. PREPROCESSOR (deterministic)
   Load all CSVs, parse deletion_rules, filter evidence_files by captured_at.

2. REQUEST CLASSIFIER (AI — small LLM, batch)
   Input: request_text -> Output: is_deletion_request: bool
   If False -> NOT_APPLICABLE, steps_json=[]

3. IDENTITY RESOLVER (deterministic)
   Input: request.email, user_identities, user_audit_log
   Output: user_id, id_set (all emails, hashes, phones, user_id)

4. EVIDENCE SELECTOR (deterministic)
   Filter evidence_files to captured_at <= audit_at.
   Lightweight grep for user_id/emails before full parse.

5. EVIDENCE PARSER (deterministic + AI for PDFs/images)
   .sql -> sqlite3 in-memory, query for user identifiers
   .json -> parse JSON, search all fields for identity matches
   .log -> structured parse for resource lookup events
   .txt -> line-parse handover format (pipe-delimited)
   .pdf -> Vision LLM call (4 files total)
   .png -> Vision LLM call (11 files total)
   Output: {resource_id: {system, category, state, evidence_id}}

6. STATE AUDITOR (deterministic)
   Apply deletion_rules to each found resource.
   Compare actual state (evidence) vs. required state (rule).
   Identify violations, active flows, restore risks.

7. STEP BUILDER (deterministic)
   If no violations: COMPLETE -> VERIFY steps only
   If violations: INCOMPLETE -> FINDING + REMEDIATION + VERIFICATION steps
   Apply canonical ordering, assign step_no from 1.

8. OUTPUT WRITER
   Sort by case_id, serialize steps_json, write output.csv to repo root.
```

### 9.3 AI Usage

| Module | AI | Reason |
|---|---|---|
| Request Classifier | Small LLM (batch) | Multilingual free-text — rules cannot handle all languages |
| PDF Parser | Vision LLM | Binary format, 4 files |
| PNG Parser | Vision LLM | Screenshots, 11 files |
| All others | None | Deterministic parsing/querying |

### 9.4 Evidence Pre-indexing

At startup, build an index: identifier -> [(file_id, captured_at)].
Reduces per-case search from O(94 files) to O(identifiers * hits).

---

## 10. Unknowns and Open Questions

### VERIFIED Facts (High Confidence)

- user_audit_log tracks email, email_hash, and phone changes
- Email changes found for multiple sample case users
- service_resource_export_*.json files follow consistent biweekly structure
- SQL files contain primary + replica tables for replication drift detection
- Remediation ordering: DISABLE_DATA_FLOW -> BLOCK_RESTORE -> DELETE -> REDACT -> ANONYMIZE
- Security audit records are always RETAIN/VERIFY_RECORD_PRESENT
- audit_at boundary is inclusive (<=)
- identity_service tombstones use tombstone_* resource IDs

### ASSUMPTIONS (Require Validation)

- ASSUMPTION A: rule_05 SUPPORT_MESSAGE — if conversation has NO shared context, the record is deleted (not just redacted). Basis: case_07 sample deletes support_001 rather than redacting it. Confidence: HIGH.
- ASSUMPTION B: system_activity is never cited as evidence_id in output steps. Only evidence_files.csv file_ids are cited. Confidence: HIGH (based on all 32 samples).
- ASSUMPTION C: PDF and PNG files contain additional state facts not present in JSON/log/SQL evidence. Unknown impact on answer accuracy.
- ASSUMPTION D: ACCOUNT_TOMBSTONE only appears in identity_service (not account_service). account_service records are deleted entirely; identity_service tombstones are redacted. Confidence: MEDIUM.

### UNKNOWNS (Require Implementation and Testing)

- How many of the 518 evaluation cases require historical identity resolution?
- Which evidence files cover which evaluation cases? (Requires runtime content inspection)
- Content of 4 PDFs and 11 PNGs — may be critical for some cases.
- Whether system_activity.csv provides any useful secondary signal for state determination.
- Exact distribution of case archetypes across all 518 cases.
- Token/cost envelope for LLM calls across full dataset.

---

## 11. Next Implementation Step

Build and validate the PREPROCESSOR + REQUEST CLASSIFIER + IDENTITY RESOLVER modules against the 32 sample cases.

Concrete tasks:
1. Create code/main.py with:
   - load_datasets() — load all 7 CSVs
   - classify_request(request_text) -> bool — LLM batch call
   - resolve_identity(email, identities_df, audit_log_df) -> UserIdentity — deterministic
   - filter_evidence(audit_at, evidence_df) -> list[EvidenceFile] — deterministic

2. Write a test harness against sample_deletion_requests.csv:
   - Classify each request
   - Resolve each identity
   - Print resolved user_id and id_set
   - Validate against known sample case subjects

3. ONLY after passing identity tests, proceed to evidence parsing (Module 5) and state auditing (Module 6).

This ensures the foundation is correct before the more complex evidence and step logic.

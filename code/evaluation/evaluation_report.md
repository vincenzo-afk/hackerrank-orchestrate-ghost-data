# Evaluation Report — Ghost Data Still Exists

Measured on 2026-10-25 with Python 3.12.10. Reproduce from the repository root:

```bash
python code/main.py             # writes output.csv; refuses to write on any contract violation
python -m pytest code/tests -q  # 225 passed, 1 live-API test skipped by default
python code/evaluation/main.py  # the numbers below
```

The production run is deterministic and makes no model or network calls.

## 1. Public sample (32 cases, scored against `dataset/sample_output.csv`)

| Metric | Before this revision | Final |
| --- | --- | --- |
| Case-level status accuracy | 25/32 (0.781) | **32/32 (1.000)** |
| Exact rows (status + full step sequence) | 12/32 | **30/32** |
| Sequence accuracy | 0.375 | **0.938** |
| Step TP / FP / FN (whole-step match) | 156 / 10 / 37 | **191 / 0 / 2** |
| Step precision / recall / F1 | 0.940 / 0.808 / 0.869 | **1.000 / 0.990 / 0.995** |
| Field-level accuracy (position-aligned) | 1008/1351 (0.746) | **1321/1351 (0.978)** |

The two remaining misses are `VERIFY_RECORD_PRESENT` steps for
`audit_record_6645` (case_18) and `audit_record_5569` (case_20). Neither id
appears in any participant-visible file or activity row, so no evidence-based
method can produce them. They are not hard-coded.

Sample rows also pass the same contract validator as the full output (0 errors).

## 2. Full output (518 evaluation cases)

| Check | Result |
| --- | --- |
| Rows / sorted unique `case_id` | 518 / pass |
| Status distribution | COMPLETE 153 · INCOMPLETE 355 · NOT_APPLICABLE 10 |
| Steps | 3,242 |
| Empty arrays | only the 10 NOT_APPLICABLE rows; 0 authorized empty plans |
| Field schema, consecutive `step_no`, operation/state pairs | pass |
| Phase → operation → system → resource ordering | pass |
| COMPLETE rows contain only evidence-backed verifications | pass |
| INCOMPLETE remediation and future verification use `evidence_id=""` | pass |
| Every finding has its remediation and final verification | pass |
| No contradictory treatments for one resource | pass |
| No account or analytics resource assigned to two cases | pass |
| No citation of a file or event later than `audit_at` | pass |
| Every citation is a resource linked to the subject | pass |
| Written file equals a fresh in-memory run | pass |
| Contract errors | **0** |

`output.csv`: 647,764 bytes, SHA-256 `3ce0059cdcfdc5ffa18628751fe3b399cfc56e249784bf303b7a11ffa08db0fb`, LF line endings.

## 3. Linker diagnostics (final run)

| Item | Value |
| --- | --- |
| Resources linked by identifiers + resolved worker events | 1,030 |
| Identifier-free resources assigned from worker activity | 407 |
| Catalog links | 15 |
| Profile-naming fallback candidates | 9 (only case_04's is proven by a snapshot; 8 unproven candidates produce no step) |
| Learned phase model | period 30 s; leave-one-out residuals −1 s: 244, 0 s: 443, +1 s: 202, +2 s: 1 |
| Low-margin (tied) assignments | 26, listed by `code/evaluation/main.py` |

## 4. Custom evaluation cases

Synthetic fixtures with known answers, independent of the public sample:

| Case | File | What it checks | Result |
| --- | --- | --- | --- |
| CE1 intent | `test_custom_eval.py::TestCE1Intent` | negated and marketing-only requests are NOT_APPLICABLE; Korean deletion detected | pass |
| CE2 temporal isolation | `TestCE2TemporalIsolation` | later evidence cannot complete a case; pre-request evidence inadmissible | pass |
| CE3 restore policy | `TestCE3RestorePolicy` | restore risk → block before verification | pass |
| CE4 tombstone | `TestCE4TombstonePolicy` | exposed tombstone redacted; clean tombstone verified | pass |
| CE5 activity ownership | `TestCE5ResourceLinks` | an activity-assigned account without evidence is a future check, not proof | pass |
| CE6 global assignment | `test_plan_regressions.py::test_linker_learns_cadence_and_assigns_one_to_one` | cadence learned from resolved pairs; one-to-one; status agreement breaks a tie | pass |
| CE7 foreign owner | `::test_linker_rejects_resource_owned_by_another_subject` | a resource whose evidence names another user is never assigned | pass |
| CE8 coverage | `::test_full_snapshot_omission_proves_absence` and two negatives | omission proves absence only for a complete, subject-covering, post-deletion snapshot | pass |
| CE9 replica drift | `::test_replica_presence_survives_primary_deletion` | primary absence does not hide a surviving replica copy | pass |
| CE10 late file | `::test_post_audit_evidence_is_never_cited` | a state from a file published after `audit_at` is never cited | pass |
| CE11 parser fixes | `::test_identifiable_support_lookup_is_present`, `::test_restore_denial_is_blocked_and_unknown_is_not_a_risk`, `::test_attachment_scan_is_an_attachment` | the three state-mapping defects | pass |
| CE12 aliases | `::test_filename_resolves_to_catalogued_object` and three more | file names, statement numbers and user references resolve through the catalog | pass |
| CE13 no shortcuts | `::test_production_code_has_no_case_ids_or_sample_answers` | production code contains no case ids and never reads sample answers | pass |

## 5. Failures found and improvements made

1. **Identifier-free accounts and analytics were never linked** (sample status
   25/32, 37 FN). Added `code/activity_linker.py`, a global one-to-one
   minimum-cost assignment of deletion-worker events. It learns from
   identifier-resolved requests: per-template timing windows, status/result
   agreement, audit-time proximity of readbacks, and a per-request sub-minute
   phase shared by all of a request's worker events. The phase feature alone
   lifted ownership accuracy on the sample from 27/32 to 32/32.
2. **The account-closure gate** forced cases to INCOMPLETE. It was removed;
   the account is an ordinary obligation.
3. **Absence by omission** now requires coverage metadata: a full table in a
   point-in-time database snapshot, or a capture scoped to the subject, taken
   after the deletion. Empty or non-covering inventories prove nothing.
4. **Physical copies** (primary, read, regional, reporting, failover
   replicas) are reconstructed separately; any surviving copy is a violation.
5. **Parser defects:** `IDENTIFIABLE` support lookups were read as REDACTED
   (false COMPLETE; cases 88, 342, 484 now report exposed PII); `decision=deny`
   restore authorizations were restore risks (now BLOCKED; cases 64, 213, 264,
   463, 464); attachment scans were messages (now one DELETE treatment); a row
   count without the body no longer proves redaction.
6. **Hard-coded PDF branches** naming specific users were replaced by generic
   extraction (printed resource ids, identifiers, retention dates, catalog
   aliases for statement numbers).
7. **Image ids minted from file names** (`delivery_confirmation_19`,
   `tombstone_user_17`) are now resolved through catalog aliases
   (`object_storage/object_19`, `tombstone_17`); uncatalogued file names create
   no record.
8. **Evidence availability:** a file published after `audit_at` is never cited
   and cannot prove compliance. Its state can still plan future verification.
   Applying this rule was needed to keep four correct sample steps.
9. **Support category:** a later attachment reading replaces the earlier
   message interpretation of the same record, so no record gets both REDACT and
   DELETE.
10. **Fail-closed output:** `code/output_validator.py` runs before writing.
    During the final image-cache experiment it blocked an output with two empty
    authorized plans (see the usage report).

## 6. Residual risks

- 26 worker events sit in bursts where several requests share every learned
  signal; their assignment is a deterministic tie-break.
- The profile-naming fallback (`account_{n:03d}`) is supported by 4 of 41
  visible user/account pairs. It is used only when a snapshot proves the
  candidate's state; it affects one sample case and no evaluation row.
- Request intent is rule-based (EN/ES/PT/FR/JA/KO). All 550 requests (518 +
  32 sample) classify with a matched signal: 549 high confidence, 1 medium
  (indirect "already gone" wording), none low. No model call was needed for
  uncertain intent.

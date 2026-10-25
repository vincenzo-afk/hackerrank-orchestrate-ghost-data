# Evaluation Report — Ghost Data Still Exists

All results below were measured on 2026-10-25 with Python 3.14.7. Reproduce from the repository root:

```bash
python -X utf8 code/main.py
python -X utf8 -m pytest code/tests -q
python -X utf8 code/evaluation/main.py
```

The pipeline is deterministic and makes no model or external API calls.

## 1. Full 518-case output validation

| Check | Measured result |
| --- | --- |
| Requests / output rows | 518 / 518 |
| Sorted, unique `case_id` values | pass |
| Status distribution | COMPLETE 74; INCOMPLETE 434; NOT_APPLICABLE 10 |
| JSON steps | 2,843 total; 5.49 per request |
| Consecutive step numbers and exact seven-field schema | pass |
| Phase, operation, system, and resource ordering | pass |
| Allowed operation/state combinations | pass |
| Finding and COMPLETE-verification citations | pass; cited observation exists, supports the case identity, and is inside the request window |
| Remediation and INCOMPLETE-verification evidence fields | pass; all empty |
| COMPLETE rows containing account closure plus evidence-backed verifications | pass, 74/74 |
| Empty step arrays | 10 NOT_APPLICABLE plus 1 evidence-gap INCOMPLETE row (`case_63`) |
| Validator errors | **0** |

The final `output.csv` is 566,590 bytes with SHA-256 `92b2ef07718bc2c3acf414e7ebb413e4102b37233af5182bf5325ecd5dfbad46`. It uses deterministic LF line endings. The final source run exited 0 in 6.277 seconds. Wall-clock time varies with machine load while output is deterministic.

The parser read 94 manifest entries into 2,932 normalized records from 93 files; `evidence_90` is an intentionally empty inventory snapshot. The output contains **895 file citations**.

### Material changes from the previous `f5b6…` output

The Phase 1 fixes changed the output from 150/358/10 to 74/434/10:

- **76 COMPLETE cases became INCOMPLETE** because no evidence-backed account closure (an absent `USER_PROFILE` or clean `ACCOUNT_TOMBSTONE`) exists. Their existing verification checks become future checks with empty evidence. This is a conservative evidence decision; it does not claim that those accounts still exist.
- **Six support-ticket cases gained the missing attachment treatment** (`case_131`, `case_179`, `case_227`, `case_275`, `case_431`, `case_527`): each now contains `REPORT_REMAINING_RECORD`, `DELETE_RECORD`, and `VERIFY_RECORD_ABSENT` for the attachment in addition to the message redaction plan. This adds 18 steps.
- **Nine cases lost an unsupported `VERIFY_RECORD_ANONYMIZED` step** whose source record was explicitly `NOT_FOUND`; absence is no longer rewritten as anonymization.
- **`case_61` recovered three attachment steps** from an explicit file/object link whose object key matches the evidence record; it remains INCOMPLETE for missing account closure. **`case_63` remains an evidence-gap INCOMPLETE row with no plan** because its only marketing link contradicts the image identifiers.
- **Nine analytics records with explicit false policy conditions gained a verification-only `VERIFY_RECORD_ANONYMIZED` step**; no remediation was invented. This adds nine steps.
- Net step count from the original `f5b6…` baseline: **2,828 → 2,843**.

## 2. Public-sample evaluation

A step matches only when `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id` all match. Exact-case and sequence comparisons preserve array order. The field metrics use both the aligned position denominator and the missing-step-penalized denominator.

| Metric | Previous candidate | Current fixed candidate |
| --- | ---: | ---: |
| Correct deletion status | 29/32 | **25/32** |
| Exact cases | 12/32 | **12/32** |
| Sequence accuracy | 12/32 | **12/32** |
| Step TP / FP / FN | 166 / 0 / 27 | **156 / 10 / 37** |
| Precision | 1.000000 | **0.939759** |
| Recall | 0.860104 | **0.808290** |
| F1 | 0.924791 | **0.869081** |
| Aligned field correct / total | 1,018 / 1,162 | **1,008 / 1,162** |
| Aligned field accuracy | 0.876076 | **0.867470** |
| Missing-step-penalized field accuracy | 0.753516 | **0.746114** |

The public sample now has **seven status mismatches**: `case_01`, `case_02`, and `case_04` remain false INCOMPLETE, while the account-closure gate additionally returns INCOMPLETE for `case_21`, `case_25`, `case_27`, and `case_28`. The gold answers mark those four COMPLETE. The missing account/analytics resources are either absent from the evidence corpus or appear only as anonymous rows (`profile: null`/`status_code: 404` or null identifiers) with no subject link, so the new status is evidence-conservative rather than an assertion that the accounts exist.

The 37 unmatched gold steps comprise the previous 27 evidence-mapping gaps plus 10 verification steps from those four cases whose evidence fields become empty future checks when the case is INCOMPLETE. The 10 false-positive predictions are those same future checks, not invented resources. Exact-case count remains 12/32.

### Remaining status and step mismatches

| Case | Gold status/steps | Predicted status/steps | Remaining gold resources |
| --- | --- | --- | --- |
| case_01 | COMPLETE / 1 | INCOMPLETE / 0 | `account_001` |
| case_02 | COMPLETE / 1 | INCOMPLETE / 0 | `account_002` |
| case_03 | COMPLETE / 3 | COMPLETE / 2 | `analytics_9406` |
| case_04 | COMPLETE / 2 | INCOMPLETE / 0 | `account_004`, `analytics_901` |
| case_07 | INCOMPLETE / 4 | INCOMPLETE / 3 | `account_007` |
| case_08 | INCOMPLETE / 4 | INCOMPLETE / 3 | `account_008` |
| case_10 | INCOMPLETE / 4 | INCOMPLETE / 3 | `account_010` |
| case_18 | INCOMPLETE / 14 | INCOMPLETE / 12 | `account_5521`, `audit_record_6645` |
| case_20 | INCOMPLETE / 8 | INCOMPLETE / 6 | `account_5037`, `audit_record_5569` |
| case_21 | COMPLETE / 3 | INCOMPLETE / 1 | `account_6440`, `analytics_5335` |
| case_22 | INCOMPLETE / 8 | INCOMPLETE / 7 | `account_4990` |
| case_23 | INCOMPLETE / 8 | INCOMPLETE / 7 | `account_410` |
| case_25 | COMPLETE / 3 | INCOMPLETE / 1 | `account_3136`, `analytics_1895` |
| case_26 | COMPLETE / 6 | COMPLETE / 5 | `analytics_4566` |
| case_27 | COMPLETE / 6 | INCOMPLETE / 4 | `account_3866`, `analytics_4574` |
| case_28 | COMPLETE / 6 | INCOMPLETE / 4 | `account_5482`, `analytics_6077` |
| case_29 | INCOMPLETE / 14 | INCOMPLETE / 13 | `account_7012` |
| case_30 | INCOMPLETE / 14 | INCOMPLETE / 13 | `account_4163` |
| case_31 | COMPLETE / 3 | COMPLETE / 2 | `account_4857` |
| case_32 | INCOMPLETE / 5 | INCOMPLETE / 4 | `account_8858` |

The missing resources are either absent from the evidence corpus or appear only in anonymous rows with no subject link. The agent does not infer IDs from `sample_output.csv`, naming patterns, neighboring activity, or unlinked activity claims. Those rows cannot support a defensible account or analytics verification.

## 3. Regression tests

`python -X utf8 -m pytest code/tests -q` exited 0 with **202 passed, 1 skipped**. The skipped test is the opt-in live Gemini smoke test; ordinary tests make no network call. The archive was rebuilt from this source and re-verified in a fresh directory outside the repository, with the same test result, a zero-error evaluator run, and the same output hash. The suite includes the original foundation/evidence/state tests plus participant-created CE cases:

| Group | Coverage |
| --- | --- |
| CE-1 | Negation, marketing-only scope, explicit deletion, and Korean deletion intent |
| CE-2 | Post-cutoff exclusion, pre-request state exclusion, same-state citation stability, anonymous readback linkage, and rejection of post-cutoff identity links |
| CE-3 | Restore-risk finding, blocking remediation, and ordered future verification |
| CE-4 | Exposed versus clean account tombstones |
| CE-5 | `source_resource_id` adds a future check without converting an activity claim into proof |
| Parser regression | Real `evidence_06` log-line and `evidence_02` snapshot timestamps override manifest export times |
| Recorded-at regression | Record-level timestamp precedence, six JSON formats, exact boundaries, stale FOUND vs newer ABSENT, post-audit reappearance, and exact-at-audit COMPLETE flips |
| Policy regression | True, false, and ambiguous outcomes for every condition-bearing supplied rule; false/unsupported conditions have no invented remediation |
| Legal PDF regression | Six legal-hold rows extracted from `evidence_27`; no current request window admits them |
| Media cache regression | Source SHA validation, missing/invalid/hash-mismatch failures, valid empty cache, and six visible `case_45` audit records |
| Gemini extractor regression | Missing key, schema/grounding rejection, cache hit/invalidation, retry, and key redaction; live call opt-in only |
| CSV regression | Deterministic LF serialization and exact header |
| Failure propagation | A reconstruction exception raises a case-scoped `RuntimeError` with the original cause, and a failed audit writes no output file |
| Phase 1 correctness | Account-closure completeness, dual support-category processing, consistent/contradictory/out-of-window/unestablished identity links, explicit file/object link recovery, explicit absence, unknown category hints, policy gaps, malformed SQL/JSON/log evidence, and cache failure |
| False-condition verification | Already-compliant analytics and email records receive verification-only steps when their supplied condition is false; no remediation is emitted |
| Incomplete-case audit | All 434 baseline INCOMPLETE cases assessed in `reports/incomplete_case_audit.csv` with evidence, resources, obligations, root cause, correction, and expected status |
| Identity temporal | Pre-audit alias/new-value resolution, post-audit alias rejection, post-audit snapshot rejection, and pre-audit link versus later contradiction |
| Raw token handling | Every category maps unknown non-empty result tokens to `UNKNOWN`; account-status unknown and every category-specific log override are covered |
| Validator regression | Current output accepted; missing account closure, missing support and non-support treatments, unsupported extra actions, and evidence-backed empty INCOMPLETE plans rejected |

## 4. Defects fixed in the final takeover

1. **Manifest timestamps hid admissible observations.** JSON items/snapshots, log lines, and TXT handover rows now use their internal observation timestamps, falling back to the manifest only when no internal timestamp exists.
2. **Anonymous readbacks lost established resource identity.** An observation at or before the cutoff with a subject identifier now links later observations of the same `(system_id, resource_id)`; post-cutoff records cannot establish that link. The state observation itself must still be inside `[requested_at, audit_at]`.
3. **Redundant evidence changed citations.** Newest admissible evidence determines state and equal-time conflicts prefer non-compliant state. Among same-category observations agreeing with that state, the earliest confirming observation supplies a stable citation.
4. **Linked source resources were omitted from future checks.** Explicit `source_resource_id` links plus an in-window policy activity can add a future verification only to an INCOMPLETE case. They cannot create evidence-backed state or a COMPLETE verdict.
5. **Field accuracy ignored missing steps.** The evaluator penalizes all fields of missing and extra steps.
6. **Validation checked only manifest time and IDs.** It now verifies the cited system/resource/state observation, the request window, citation identity support, account closure, and category-specific support treatment.
7. **Record-level `recorded_at` was ignored.** Six JSON evidence formats used the enclosing snapshot or manifest time instead of each record's observation time. The parser now preserves `observed_at` and record-level `captured_at` precedence, then falls back to `recorded_at`.
8. **Policy conditions were collapsed into fixed category sets.** All supplied conditions are evaluated. Explicit false conditions produce no remediation and become policy gaps; unsupported conditions fail closed; missing policy rules fail closed.
9. **Static image transcriptions were removed.** Gemini's official SDK extracted observations from the actual 11 image files; the offline pipeline uses a SHA-validated derived-observation cache. Missing, malformed, incomplete, or hash-mismatched cache evidence now fails the run.
10. **PDF extraction missed the legal register.** A general table-row parser extracts all six `ORD-*` legal-hold rows from `evidence_27`.
11. **CSV line endings were inconsistent.** `run_full_pipeline` uses an explicit LF terminator.
12. **Support categories were collapsed.** Deduplication now keys on `(system_id, resource_id, data_category)`, both in the corpus and in reconstruction. Six live support cases now carry both message and attachment treatments.
13. **Activity links could override contradictory evidence.** Direct identifiers corroborate a link. An anonymous record requires an explicit file/object match; contradictory strong identifiers still reject the link. The original observation timestamp is preserved.
14. **Absent observations became compliant-looking states.** Explicit `NOT_FOUND`/equivalent is preserved as `ABSENT` for every category and is not overridden by log-specific presence branches.
15. **Unknown categories silently disappeared.** Unmapped parser hints become `UNKNOWN_CATEGORY`; no policy rule means a policy gap, not an unconditional profile deletion.
16. **Unsafe policy fallbacks.** Unknown support-attachment ownership no longer triggers DELETE; false conditions no longer produce REDACT/ANONYMIZE remediation.
17. **Malformed evidence was silently skipped.** Invalid SQL `record_json`, malformed JSON containers/items, invalid embedded log JSON, unknown handover states/categories, unsupported evidence extensions, and cache failures now raise traceable errors.
18. **Completeness could be claimed from one retained audit record.** Every deletion case now requires an evidence-backed account closure and policy-compliant treatment for every evidence-supported resource/category; otherwise it is INCOMPLETE.
19. **Incomplete evidence gaps could become empty plans.** The validator flags an INCOMPLETE row that has matched evidence but no steps. An empty plan is retained only where no resource can be established from evidence (`case_63`); `case_61` recovered its file-linked attachment plan.
20. **Explicit file/object identity links were over-rejected.** A `LINK_RESOURCE_IDENTITY` event with a matching object key can establish an anonymous attachment when the evidence has no conflicting strong identifier; the observation timestamp is preserved. `case_61` recovers its attachment plan without forcing COMPLETE.
22. **Test and dependency integrity.** `pytest` is declared, production tests use `require_evidence=True`, and synthetic tests cover the newly closed paths.
23. **Identity history was not bounded by `audit_at`.** `resolve_identity(..., as_of=audit_at)` now excludes later email/phone/hash changes and later snapshot updates; pre-audit aliases and new values are retained. Five temporal tests were added; the current output is unchanged.
24. **Unknown raw result tokens could become policy-significant states.** `_state_for_record` returns `UNKNOWN` for any non-empty unrecognized result token; log-specific branches cannot rescue it. `UNKNOWN` forces an INCOMPLETE evidence gap, and the validator rejects unsupported evidence states. Table-driven tests cover every category and log override.
25. **Validator coverage was support-specific.** `_expected_operations` now derives required findings/remediation/verification from every policy category and the allowed operation mapping, and rejects missing treatments and unsupported extra actions. Non-deletion cases are exempt because no deletion action is authorized.

Earlier fixes retained in this submission include escaped-message decoding, trace-context propagation, ACTIVE profile normalization, correct service attribution, false-COMPLETE guards, deterministic serialization, and package-safe repository-root detection.

### Policy rule audit

| Rule | Category / condition | Implementation and decision | Regression test |
|---|---|---|---|
| rule_01 | USER_PROFILE / Always | DELETE; ABSENT verification also closes the account | `test_always_rules`, completeness tests |
| rule_02 | SECONDARY_IDENTIFIER / Always | DELETE; no current evidence records | `test_always_rules`, sparse-rule test |
| rule_03 | SEARCH_INDEX_ENTRY / Always | DELETE | `test_always_rules`, retrieval tests |
| rule_04 | CACHE_ENTRY / Always | DELETE; no current evidence records | `test_always_rules`, sparse-rule test |
| rule_05 | SUPPORT_MESSAGE / shared customer, agent, or order context | true/unknown → REDACT; explicit false → policy gap | `test_support_message_shared_condition_true_false_unknown` |
| rule_06 | SUPPORT_ATTACHMENT / belongs only to deletion subject | true → DELETE; false/unknown → policy gap, never DELETE | `test_support_attachment_belongs_only_condition`, unknown-owner test |
| rule_07 | ANALYTICS_PROFILE / attributable to user | true/unknown → ANONYMIZE; explicit false → policy gap | `test_analytics_attributable_condition` |
| rule_08 | PRODUCT_TELEMETRY / attributable to user | same as rule_07; no current evidence records | sparse-rule test |
| rule_09 | USER_EXPORT / Always | DELETE | `test_always_rules` |
| rule_10 | MARKETING_PROFILE / Always | DELETE | `test_always_rules` |
| rule_11 | EMAIL_DELIVERY_LOG / contains user email | true/unknown → REDACT; explicit false → policy gap | `test_email_delivery_log_condition`, sparse-rule test |
| rule_12 | SECURITY_AUDIT_LOG / within retention period | true/unknown → RETAIN and verify present; false → policy gap; ABSENT → retention gap | `test_audit_retention_condition` |
| rule_13 | LEGAL_HOLD_RECORD / active legal hold | true/unknown → RETAIN; false → policy gap; no current request window admits the records | `test_legal_hold_condition`, legal register tests |
| rule_14 | BACKUP_ARCHIVE / restore access can be blocked | ACTIVE → restore-risk finding + BLOCK_RESTORE; BLOCKED → verification; ABSENT → retention gap | `test_backup_restore_condition`, backup risk tests |
| rule_15 | ACCOUNT_TOMBSTONE / deleted account + stable reference | true → REDACT; false/unknown handling as above; clean REDACTED also closes the account | `test_tombstone_condition`, tombstone tests |

## 5. Custom evaluation cases

CE-1 through CE-5 are participant-created tests, separate from the public sample: intent/negation, temporal isolation, restore blocking, tombstone treatment, and resource-link verification. Phase 1 adds synthetic tests for account-closure completeness, dual support categories, link consistency, cache failure, absent-state handling, unknown categories, false policy branches, malformed evidence, bounded identity history, unknown raw tokens, and validator rejection cases. These tests encode contract behavior, not public labels.

## 6. Residual semantic risks

- Public samples cannot establish the 27 resource mappings or the hidden-case distribution; hidden accuracy is unknown.
- The named COMPLETE rules do not explicitly require an account-closure observation. The gate is inferred from the account-deletion scope of every request and the “every relevant copy” rule; it is configurable via `require_account_closure`. If a future request were not account-scoped, the global gate would be over-conservative. It moved 76 cases to INCOMPLETE: the evidence does not prove those accounts are closed, but it also does not prove they still exist. Those cases may be scored as false INCOMPLETE if hidden truth uses unobserved mappings.
- Categories not observed in admissible evidence cannot be proven absent. The gate establishes account closure and verifies every evidence-supported resource, not every hypothetical copy.
- **Specification conflict for evidence gaps:** `AGENTS.md` §6.4 requires an INCOMPLETE row to contain findings, a complete remediation plan, and verification checks, while the allowed operation vocabulary requires a real system/resource. For `case_63`, identity cannot be established, so no permitted resource exists. The safest behavior is `INCOMPLETE` with `[]` and an internal evidence-gap reason; inventing a resource or operation would violate the contract. `case_61` recovered its file-linked attachment plan but remains INCOMPLETE for missing account closure.
- **350-target assessment:** the final output has 74 COMPLETE, 76 cases blocked only by the inferred account-closure condition, 357 cases with actual remaining records/restore risks, and one unresolved identity. Removing the inferred gate would yield at most 150 COMPLETE, still below 350 without ignoring real findings or fabricating evidence. The 434-case assessment is in `reports/incomplete_case_audit.csv`.
- Identity history is now bounded by `audit_at` and covered by tests; no current case changes.
- Unknown non-empty result tokens now become `UNKNOWN` and force an evidence gap; genuine malformed records raise explicit parse errors.
- The Gemini extractor validates status/grounding but not `data_category`; the checked-in offline cache is pre-vetted, but live refresh should validate categories.
- The legal-hold register is outside every current request window; future windows should re-evaluate it.
- The media cache is rules-based permitted by the participant-facing caching encouragement and the packaging prohibitions; no organizer sign-off is claimed.
- Hidden canonical answers are unavailable; public metrics are not proof of hidden accuracy.

## 7. Final artifact state

- `output.csv`: 566,590 bytes, SHA-256 `92b2ef07718bc2c3acf414e7ebb413e4102b37233af5182bf5325ecd5dfbad46`.
- `reports/incomplete_case_audit.csv`: 434 baseline INCOMPLETE cases, 24 columns, generated from the current source/evidence.
- `code.zip`: rebuilt from this source after the fixes, with no dataset, caches, nested archives, credentials, or absolute paths.
- `submission_manifest.sha256`: regenerated for the final archive, logs, reports, and audit table; `sha256sum -c` passes.

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
| Status distribution | COMPLETE 150; INCOMPLETE 358; NOT_APPLICABLE 10 |
| JSON steps | 2,828 total; 5.46 per request |
| Consecutive step numbers and exact seven-field schema | pass |
| Phase, operation, system, and resource ordering | pass |
| Allowed operation/state combinations | pass |
| Finding and COMPLETE-verification citations | pass; cited observation exists and is inside the request window |
| Remediation and INCOMPLETE-verification evidence fields | pass; all empty |
| COMPLETE rows containing only evidence-backed verifications | pass, 150/150 |
| Empty step arrays | 10, all NOT_APPLICABLE |
| Validator errors | **0** |

The final `output.csv` is 564,902 bytes with SHA-256 `f5b6f1ebabb0e56834a881007ad91f6080302778bec31b1ad42d1c582d6a04e4`. It uses deterministic LF line endings. In the final audit run, the full pipeline exited 0 in 8.323 seconds; a repeat run took 8.224 seconds and produced the same hash. Wall-clock time varies with machine load while output is deterministic.

The parser read 94 evidence files into 2,932 normalized records; 70 evidence files are cited in the final output. Findings comprise 365 remaining records, 187 exposed-PII records, 113 active data flows, and 31 restore risks.

The record-level `recorded_at` correction changed 25 evaluation rows: three status flips (`case_342`, `case_390`, and `case_484` from INCOMPLETE to COMPLETE) and 22 same-status step corrections. The SHA-validated Gemini image observations add the five missing visible audit records for `case_45` (`evidence_37`), expanding that COMPLETE case from one to six verification steps. Public-sample metrics were unchanged.

| Reported workflow status | Requests | COMPLETE | INCOMPLETE | NOT_APPLICABLE |
| --- | ---: | ---: | ---: | ---: |
| COMPLETE | 254 | 92 | 162 | 0 |
| PARTIALLY_COMPLETE | 152 | 36 | 116 | 0 |
| NOT_STARTED | 112 | 22 | 80 | 10 |

All 518 request emails resolved: 418 through current email and 100 through historical email. Intent classification produced 508 deletion cases and 10 NOT_APPLICABLE cases.

## 2. Public-sample evaluation

A step matches only when `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id` all match. Exact-case and sequence comparisons preserve array order. Two field metrics are reported because they answer different questions:

- **Aligned field accuracy** counts the seven fields at each position where both gold and prediction have a step. It measures field correctness without charging for missing steps.
- **Missing-step-penalized field accuracy** uses `max(gold_steps, predicted_steps)` at each position, so all seven fields of a missing or extra step count as incorrect.

| Metric | Verified baseline | Final | Change |
| --- | ---: | ---: | ---: |
| Correct deletion status | 29/32 | 29/32 | 0 |
| Exact cases | 9/32 | 12/32 | +3 |
| Sequence accuracy | 9/32 | 12/32 | +3 |
| Step TP / FP / FN | 158 / 0 / 35 | 166 / 0 / 27 | +8 / 0 / -8 |
| Precision | 1.000000 | 1.000000 | 0 |
| Recall | 0.818653 | 0.860104 | +0.041451 |
| F1 | 0.900285 | 0.924791 | +0.024506 |
| Aligned field correct / total | 960 / 1,106 | 1,018 / 1,162 | +58 / +56 |
| Aligned field accuracy | 0.867993 | 0.876076 | +0.008083 |
| Missing-step-penalized field accuracy | 0.710585 | 0.753516 | +0.042931 |

The aligned denominator is seven fields for each matched step: 158 steps × 7 = 1,106 at baseline and 166 × 7 = 1,162 final. The missing-step-penalized denominator is 193 gold steps × 7 = 1,351 in both runs; no predicted sample step is extraneous. The baseline's originally reported 0.867993 used the aligned denominator, so the comparable final aligned value is 0.876076, not 0.753516.

The public-sample metrics above are unchanged by the `recorded_at` correction and the SHA-validated media cache because none of those observations changes the 32 sample cases.

Eight previously missing steps were recovered without using sample answers at inference:

- `account_3960` and `audit_record_4902`: per-line timestamps in `evidence_06` preserve the trace-linked subject and place both observations before `case_09.audit_at`.
- `audit_record_4128`, `audit_record_7095`, `audit_record_3954`, and `audit_record_1707`: snapshot-internal `captured_at` values in `evidence_02` are exactly the applicable audit time, although the bundle was exported later.
- `account_5684`: an identified earlier snapshot establishes the resource/subject link; the later anonymous `evidence_92` readback supplies ABSENT state.
- `account_006`: `search_001` explicitly names `source_resource_id=account_006`; its deletion activity adds only a future verification in an already-INCOMPLETE case, not proof of deletion.

### Every remaining per-case mismatch

There are no remaining false-positive sample steps. Each row below lists every gold step still absent from the prediction.

| Case | Gold status/steps | Predicted status/steps | Missing resources |
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
| case_21 | COMPLETE / 3 | COMPLETE / 1 | `account_6440`, `analytics_5335` |
| case_22 | INCOMPLETE / 8 | INCOMPLETE / 7 | `account_4990` |
| case_23 | INCOMPLETE / 8 | INCOMPLETE / 7 | `account_410` |
| case_25 | COMPLETE / 3 | COMPLETE / 1 | `account_3136`, `analytics_1895` |
| case_26 | COMPLETE / 6 | COMPLETE / 5 | `analytics_4566` |
| case_27 | COMPLETE / 6 | COMPLETE / 4 | `account_3866`, `analytics_4574` |
| case_28 | COMPLETE / 6 | COMPLETE / 4 | `account_5482`, `analytics_6077` |
| case_29 | INCOMPLETE / 14 | INCOMPLETE / 13 | `account_7012` |
| case_30 | INCOMPLETE / 14 | INCOMPLETE / 13 | `account_4163` |
| case_31 | COMPLETE / 3 | COMPLETE / 2 | `account_4857` |
| case_32 | INCOMPLETE / 5 | INCOMPLETE / 4 | `account_8858` |

The three status mismatches remain case_01, case_02, and case_04, all false INCOMPLETE. The 27 missing steps comprise 18 account verifications, 7 analytics verifications, and 2 retained-audit verifications.

### Why the remaining steps are not inferred

The public activity stream names these account and analytics resources, but the relevant operation rows contain no subject identifier or explicit case/resource link. Timestamp proximity and neighboring activity rows do not prove that a resource belongs to a particular request. The analytics evidence has null identity fields, and most anonymous account readbacks have no earlier identified observation of the same resource. `audit_record_6645` and `audit_record_5569` have no participant-evidence occurrence with a subject link.

Sparse or empty snapshots also do not supply the missing resource-to-subject mapping. Inferring `account_N` from `user_N`, copying mappings from `sample_output.csv`, or treating a deletion result as proof would violate the evidence contract. The pipeline therefore retains these measured mismatches rather than guessing.

## 3. Regression tests

`python -X utf8 -m pytest code/tests -q` exited 0 with **127 passed, 1 skipped**. The skipped test is the opt-in live Gemini smoke test; ordinary tests make no network call. The suite includes the original foundation/evidence/state tests plus participant-created CE cases:

| Group | Coverage |
| --- | --- |
| CE-1 | Negation, marketing-only scope, explicit deletion, and Korean deletion intent |
| CE-2 | Post-cutoff exclusion, pre-request state exclusion, same-state citation stability, anonymous readback linkage, and rejection of post-cutoff identity links |
| CE-3 | Restore-risk finding, blocking remediation, and ordered future verification |
| CE-4 | Exposed versus clean account tombstones |
| CE-5 | `source_resource_id` adds a future check without converting an activity claim into proof |
| Parser regression | Real `evidence_06` log-line and `evidence_02` snapshot timestamps override manifest export times |
| Recorded-at regression | Record-level timestamp precedence, six JSON formats, exact boundaries, stale FOUND vs newer ABSENT, post-audit reappearance, and exact-at-audit COMPLETE flips |
| Policy regression | True, false, and ambiguous outcomes for every condition-bearing supplied rule; unsupported conditions fail closed |
| Legal PDF regression | Six legal-hold rows extracted from `evidence_27`; no current request window admits them |
| Media cache regression | Source SHA validation, changed-image invalidation, tombstone/support normalization, and six visible `case_45` audit records |
| Gemini extractor regression | Missing key, schema/grounding rejection, cache hit/invalidation, retry, and key redaction; live call opt-in only |
| CSV regression | Deterministic LF serialization and exact header |

## 4. Defects fixed in the final takeover

1. **Manifest timestamps hid admissible observations.** JSON items/snapshots, log lines, and TXT handover rows now use their internal observation timestamps, falling back to the manifest only when no internal timestamp exists.
2. **Anonymous readbacks lost established resource identity.** An observation at or before the cutoff with a subject identifier now links later observations of the same `(system_id, resource_id)`; post-cutoff records cannot establish that link. The state observation itself must still be inside `[requested_at, audit_at]`.
3. **Redundant evidence changed citations.** Newest admissible evidence still determines state and equal-time conflicts still prefer non-compliant state. Among observations agreeing with that state, the earliest confirming observation supplies a stable citation.
4. **Linked source resources were omitted from future checks.** Explicit `source_resource_id` links plus an in-window policy activity can add a future verification only to an INCOMPLETE case. They cannot create evidence-backed state or a COMPLETE verdict.
5. **Field accuracy ignored missing steps.** The evaluator now penalizes all fields of missing and extra steps.
6. **Validation checked only manifest time and IDs.** It now verifies the cited system/resource/state observation and its internal timestamp, full operation ordering, and COMPLETE phase semantics.
7. **Record-level `recorded_at` was ignored.** Six JSON evidence formats used the enclosing snapshot or manifest time instead of each record's observation time. The parser now preserves `observed_at` and record-level `captured_at` precedence, then falls back to `recorded_at`. This admitted exact-at-audit observations, blocked later reappearances from changing earlier answers, and removed stale findings. Regression coverage is in `code/tests/test_recorded_at.py`.
8. **Policy conditions were collapsed into fixed category sets.** `code/policy_engine.py` now loads and evaluates every supplied condition with explicit bounded predicates and records the selected rule/condition. Explicit false conditions fail closed when the CSV supplies no inverse action; analytics/email records already in the compliant state retain verification-only behavior; unsupported conditions fail closed. Tests cover true, false, and ambiguous outcomes for each condition-bearing rule.
9. **Static image transcriptions were in the inference path.** The static catalog was removed. Gemini's official SDK extracted observations from the actual 11 image files; the offline pipeline uses a SHA-validated derived-observation cache. The security screenshot's six visible audit records replaced the single catalog record, adding five evidence-backed `case_45` verifications. The cache contains no final statuses; changed image bytes invalidate it.
10. **PDF extraction missed the legal register.** A general table-row parser now extracts all six `ORD-*` legal-hold rows from `evidence_27`, including retained-until dates and subject references. They are outside every current admissible request window, so no current decision is forced.
11. **CSV line endings were inconsistent.** `run_full_pipeline` now uses an explicit LF terminator and a regression test; the final bytes hash to `f5b6…`.

Earlier fixes retained in this submission include escaped-message decoding, trace-context propagation, ACTIVE profile normalization, correct service attribution, false-COMPLETE guards, and package-safe repository-root detection.

### Policy rule audit

`code/policy_engine.py` selects exactly one supplied rule per category. There are no overlapping same-category rules, so precedence is explicit; unsupported conditions and false conditional branches without a supplied action fail closed.

| Rule | Category / condition | Implementation and decision | Regression test |
|---|---|---|---|
| rule_01 | USER_PROFILE / Always | DELETE | `test_always_rules` |
| rule_02 | SECONDARY_IDENTIFIER / Always | DELETE | `test_always_rules` |
| rule_03 | SEARCH_INDEX_ENTRY / Always | DELETE | `test_always_rules` |
| rule_04 | CACHE_ENTRY / Always | DELETE | `test_always_rules` |
| rule_05 | SUPPORT_MESSAGE / shared customer, agent, or order context | true/unknown → REDACT; explicit false → fail closed | `test_support_message_shared_condition_true_false_unknown` |
| rule_06 | SUPPORT_ATTACHMENT / belongs only to deletion subject | true/unknown → DELETE; explicit false → fail closed | `test_support_attachment_belongs_only_condition` |
| rule_07 | ANALYTICS_PROFILE / attributable to user | true → ANONYMIZE; false → verification-only; unknown → ANONYMIZE | `test_analytics_attributable_condition` |
| rule_08 | PRODUCT_TELEMETRY / attributable to user | same as rule_07; no current records | `test_analytics_attributable_condition` |
| rule_09 | USER_EXPORT / Always | DELETE | `test_always_rules` |
| rule_10 | MARKETING_PROFILE / Always | DELETE | `test_always_rules` |
| rule_11 | EMAIL_DELIVERY_LOG / contains user email | true → REDACT; false → verification-only; unknown → REDACT | `test_email_delivery_log_condition` |
| rule_12 | SECURITY_AUDIT_LOG / within retention period | true/unknown → RETAIN; explicit false → fail closed | `test_audit_retention_condition` |
| rule_13 | LEGAL_HOLD_RECORD / active legal hold | true/unknown → RETAIN; explicit false → fail closed | `test_legal_hold_condition` |
| rule_14 | BACKUP_ARCHIVE / restore access can be blocked | RETAIN; reconstruction uses the explicit restore state (ACTIVE → risk + BLOCK_RESTORE; BLOCKED → verify) | `test_backup_restore_condition` |
| rule_15 | ACCOUNT_TOMBSTONE / deleted account + stable reference | true/unknown → REDACT; explicit false → fail closed | `test_tombstone_condition` |

Missing condition fields use the documented conservative treatment for the category; explicit false conditions do not invent an inverse action. Unsupported conditions set the case to INCOMPLETE via the policy-gap path (`test_unsupported_condition_fails_closed`, `test_false_conditional_decision_fails_closed_in_reconstruction`).

## 5. Residual semantic risks

- Public samples cannot establish the 27 mappings listed above; hidden-case accuracy cannot be measured locally.
- The legal retention register `evidence_27` is now parsed into six `LEGAL_HOLD_RECORD` observations for `user_08`, `user_12`, `user_17`, `user_21`, `user_24`, and `user_29`. It is captured 2026-05-29T08:00:00Z; `case_46` (user_17, requested 2026-03-08, audit 2026-03-11) audits before the capture, while the other requests are submitted after 2026-05-29 and are excluded by the request lower bound. No current decision changes, but new relevant data would be available if a future request window includes the capture.
- The image cache contains Gemini-derived observations with visible supporting text and source SHA-256. Independent inspection of all 11 original PNGs confirmed the six `user_03` audit IDs `001`–`006`, the support/analytics/search/marketing/export/backup rows, and the object-storage filenames. Some fields are normalized rather than literal: `tombstone_user_17` is derived from visible `user_17` + “Retained reference”; backup `ACTIVE` is a conservative normalization when `restore_allowed` is not visibly stated; export states are generic `PRESENT`; and object-storage resource IDs/system IDs are filename/console-derived. These limitations are recorded in the cache. `support_9538` from the account page is excluded because only a page-level support reference is visible, not a support-message body.
- The cache is included in `code.zip` so the offline run is reproducible; verify that including derived media observations is permitted by the final submission rules. It is not a gold answer set and must be refreshed if an image changes.
- All 1,013 evidence citations were independently resolved. Nine citations point to anonymous readback records; each resource is linked by a separate identified observation or an explicit `LINK_RESOURCE_IDENTITY` activity within the admissible cutoff. No duplicate step tuples, fabricated evidence IDs, post-cutoff citations, or unsupported remediation citations were found.
- The policy engine's handling of absent condition fields remains a conservative interpretation of natural-language policy text; only the six audit rows visibly present in `evidence_37` were added to `case_45`. No unlinked cache extras changed a decision.
- The live Gemini extraction experiment sent only the selected local screenshots to Google; no dataset archive, `log.txt`, or API key was uploaded. Ordinary tests use mocked clients; the live test is opt-in and was skipped by default.
- The implementation uses `[requested_at, audit_at]` for state observations. The written contract explicitly states the upper cutoff, while the public samples also reject stale pre-request state. A controlled temporary build with `not_before=None` measured exact cases 10/32, TP/FP/FN 165/6/28 (versus 12/32 and 166/0/27), and the evaluator exited 1 on full-output validation. The lower bound was therefore retained.
- A resource with several same-state observations can legitimately support more than one citation. The deterministic earliest-confirming rule matches the public convention while newest-state conflict handling remains unchanged.
- `agent-trace.zip` must be staged only after the relevant sessions are closed, then reviewed for secrets, personal information, and unrelated files as required by `agent_trace_instructions.md`.
- The Gemini credential was pasted into the development conversation and must be treated as compromised. It is absent from all working-tree artifacts, but it may be present in session/agent-trace data; rotate it and redact it before trace submission.

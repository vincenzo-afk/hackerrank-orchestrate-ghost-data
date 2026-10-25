# Phase 1 code audit and corrective changes — 2026-10-25

## A. Verdict

**CODE RE-VERIFIED WITH EXPLICIT EVIDENCE LIMITATIONS.** The confirmed Phase 1
defects were fixed and covered by regression tests. The code is reproducible and
the validator reports zero contract errors, but the implementation is not
unconditionally complete: unobserved categories cannot be proven absent, 37
public-sample gold steps remain unmatched, and 76 full-dataset cases are now
conservatively INCOMPLETE because account closure is not evidenced.

## B. Fixes applied

| Defect | Location | Fix |
|---|---|---|
| Support message/attachment collapsed by resource ID | `state_reconstruction.py`, `evidence_parser.py` | Deduplicate by `(system_id, resource_id, data_category)` in both the corpus and reconstruction; six real support cases now receive both treatments |
| Activity link overrode contradictory evidence and timestamp | `state_reconstruction.py` | Direct identifiers corroborate a link; an anonymous record requires a matching file/object key; contradictory strong identifiers reject the link; the record observation time is preserved. `case_61` recovered its attachment plan. |
| Unsupported COMPLETE from partial evidence | `state_reconstruction.py`, `main.py` | Require evidence-backed account closure and policy-compliant treatment for every evidence-supported resource/category; otherwise INCOMPLETE. The account condition is an inferred minimum from the account-deletion scope, not a separately named CSV rule. |
| Missing/invalid media cache silently removed evidence | `media_cache.py`, `evidence_parser.py` | Strict cache loading: missing, malformed, incomplete, and hash-mismatched cache evidence raises; valid empty cache remains valid |
| Explicit absence rewritten as PRESENT/REDACTED/ANONYMIZED | `evidence_parser.py` | `NOT_FOUND`/equivalent returns ABSENT before category-specific normalization; log overrides preserve absence |
| Unknown parser category became USER_PROFILE | `evidence_parser.py`, `policy_engine.py` | Unmapped hints become `UNKNOWN_CATEGORY`; no supplied rule is a policy gap |
| False/unknown policy branches invented actions | `policy_engine.py`, `state_reconstruction.py` | False conditions produce no remediation. Already-compliant analytics/email records receive a verification-only step; unknown support-attachment ownership cannot trigger DELETE. |
| Compliant false-condition records lost verification | `state_reconstruction.py`, `evaluation/main.py` | Nine analytics records already `ANONYMIZED` now receive `VERIFY_RECORD_ANONYMIZED` for an explicit false condition; no remediation is added. |
| Malformed evidence silently vanished | `evidence_parser.py` | Invalid SQL JSON, malformed JSON containers/items, invalid log JSON, unknown handover states/categories, and unsupported extensions raise `EvidenceParseError` |
| Identity history used post-audit changes | `main.py` (`resolve_identity`, `_identity_values_as_of`) | Current snapshots and historical email/phone/hash changes are bounded by `audit_at`; pre-audit aliases remain resolvable |
| Unknown raw tokens became policy states | `evidence_parser.py` (`_state_for_record`, log branches) | Any non-empty unrecognized result becomes `UNKNOWN`; reconstruction emits an INCOMPLETE evidence gap and the validator flags unsupported states |
| Validator was support-specific | `evaluation/main.py` (`_expected_operations`) | All policy categories use deterministic expected findings/remediation/verification; missing required actions and unsupported extra actions are rejected; non-deletion cases are exempt |
| Undeclared test dependency | `requirements.txt` | Added `pytest>=8,<10` |

## C. Current measurements

- Tests: **202 passed, 1 skipped**; the skip is the opt-in live Gemini test.
- Evaluator: **0 contract errors**, exit 0.
- Output: **518 rows**, **2,843 steps**, 74 COMPLETE / 434 INCOMPLETE / 10 NOT_APPLICABLE.
- Output SHA-256: `92b2ef07718bc2c3acf414e7ebb413e4102b37233af5182bf5325ecd5dfbad46`.
- Output size: 566,590 bytes.
- Case audit: `reports/incomplete_case_audit.csv`, 434 rows, 24 columns.
- Public sample: 25/32 status, 12/32 exact, TP/FP/FN 156/10/37, precision 0.939759, recall 0.808290, F1 0.869081; aligned field accuracy 1,008/1,162; missing-step-penalized 1,008/1,351.

The public sample status decrease is caused by the account-closure gate: four
cases (`case_21`, `case_25`, `case_27`, `case_28`) are now INCOMPLETE because the
account/analytics resources in participant evidence are anonymous and not
linked to the subject. The 10 false-positive sample steps are evidence-stripped
future checks from those cases; the 37 unmatched gold steps are the previous 27
mapping gaps plus those 10 checks.

## D. Material output changes

- 76 cases moved COMPLETE → INCOMPLETE for missing evidence-backed account
  closure; their verification checks become future checks with empty evidence.
- Six support cases gained 18 attachment finding/remediation/verification steps.
- Nine cases lost an unsupported analytics `VERIFY_RECORD_ANONYMIZED` step where
  the source record was explicitly `NOT_FOUND`.
- Nine compliant analytics records with explicit false conditions gained
  verification-only `VERIFY_RECORD_ANONYMIZED` steps.
- `case_61` recovered its three attachment steps from an explicit file/object
  link, while remaining INCOMPLETE for missing account closure. `case_63`
  remains an evidence-gap INCOMPLETE row with no plan because the only
  marketing link contradicts the image identifiers.
- Net step change from the original baseline: 2,828 → 2,843.

## E. Remaining risks

- The 27 original public-sample mappings remain unavailable from evidence; no
  sample labels or inferred IDs were used.
- Unobserved categories cannot be proven absent; the gate establishes account
  closure and verified evidence-supported resources only.
- The named COMPLETE rules do not explicitly state account closure; the gate is
  inferred from the account-deletion scope and the “every relevant copy” rule.
  It may produce false INCOMPLETE against hidden truth that relies on
  unobserved mappings. This is an explicit evidence decision, not an assertion
  those accounts still exist.
- **Evidence-gap specification conflict:** `AGENTS.md` §6.4 requires an
  INCOMPLETE row to include findings, a complete remediation plan, and
  verification checks, but every allowed operation requires a real
  system/resource. For unresolved identity (`case_63`) no permitted resource
  exists. The safest behavior is INCOMPLETE with `[]`; inventing a resource or
  operation would violate the contract. `case_61` recovered its plan through an
  explicit file/object link but remains INCOMPLETE for missing account closure.
- The 350 COMPLETE target was not reached: 74 cases are COMPLETE, 76 are blocked
  solely by the inferred account-closure condition, and 357 have actual
  remaining records/restore risks. Removing the inferred gate would yield at
  most 150 COMPLETE, still below 350 without ignoring real findings or
  fabricating evidence.
- The optional live Gemini extractor validates status/grounding but not
  `data_category`; the checked-in offline cache is pre-vetted.
- The legal-hold register is outside every current request window; future
  windows should re-evaluate it.

## F. Reproducibility

```text
python -B code/main.py                  => 0 (518 rows, 2,843 steps)
python -B -m pytest code/tests -q       => 0 (202 passed, 1 skipped)
python -B code/evaluation/main.py       => 0 (518 rows, 0 contract errors)
```

The archive and manifest are rebuilt only after the source tests and evaluator
pass; the external-extraction verification is run on the exact rebuilt archive.
No commit, push, upload, or submission was performed.

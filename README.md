# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.


## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.

---

## Solution — implementation in this repository

### What it does

`code/main.py` reads the participant-facing files in `dataset/` and writes
`output.csv` at the repository root. The production run is deterministic and
offline; it makes no model or network calls, so the run costs $0 and is
reproducible. Image records come from a SHA-validated cache of observations
extracted from the actual image bytes by Gemini; an explicit live refresh path
is available for regenerating observations.

Pipeline stages:

1. `load_datasets` loads and validates the CSVs (518 requests, 850 identities,
   306 audit-log rows, 4 011 activity events, 15 deletion rules, 94 evidence
   files).
2. `classify_request` detects deletion intent in EN/ES/PT/FR/JA/KO, with
   negation, marketing opt-out, access/export and keep-intent handling.
3. `resolve_identity` joins each request email to a user through current and
   historical emails, hashed identifiers, phone numbers and user IDs.
4. `load_evidence_corpus` parses SQL snapshots, JSON bundles, logs (key=value,
   JSON, pipe, syslog), PDFs and SHA-validated Gemini-derived image observations
   into normalised records.
5. `reconstruct_case_state` keeps only records captured inside
   `[requested_at, audit_at]`, deduplicates them (newest capture wins), applies
   the condition-bearing `deletion_rules.csv` through `code/policy_engine.py`,
   and emits FINDING / REMEDIATION / VERIFICATION steps.
6. The CSV is written sorted by `case_id` with the required header.

### Setup

Python 3.10+ (verified on 3.14.7).

```bash
pip install -r code/requirements.txt
```

`pypdf` is required for PDF extraction. `pydantic` and `google-genai` are
required for the optional live Gemini refresh path; the normal offline run uses
the checked-in SHA-validated cache and does not call Gemini. `pytest` is needed
to run the tests.

### Run

```bash
python code/main.py            # regenerates ./output.csv (518 rows)
python -m pytest code/tests -q # 202 tests passed, 1 live test skipped by default
python code/evaluation/main.py # sample scoring + full output validation
```

`code/evaluation/main.py` exits non-zero if the 518-row output violates the
contract; the last run reported 0 errors.

### Gemini image refresh (explicit, optional)

The normal run never calls the network. To refresh observations for one local
image, set `GEMINI_API_KEY` in the environment and run:

```bash
python code/gemini_extractor.py dataset/evidence/images/support_ticket_console_20260524.png evidence_28
```

`GEMINI_MODEL` defaults to `gemini-3.8-flash`; set it explicitly to use another
model available to the account. Only the selected image bytes and the extraction
prompt are sent to Gemini. No API key, dataset archive, or `log.txt` is uploaded.
The extractor validates the JSON schema, rejects invented identifiers/resource
IDs, caches by source SHA-256 + model + prompt version, and never chooses a
deletion status or remediation step. Do not commit the API key or `.gemini_cache/`.
The final offline run reported in `code/evaluation/usage_report.md` makes zero
model calls; the separate controlled Gemini extraction experiment is documented
there.

### Reports

- `code/evaluation/evaluation_report.md` — contract checks, sample metrics,
  custom evaluation cases, defects found and fixed.
- `code/evaluation/usage_report.md` — final offline full-dataset measurements
  (0 model calls, $0.00) plus the separate controlled Gemini extraction
  experiment and token counts.

### Design guarantees

- Only evidence with a timestamp at or before `audit_at` (and at or after
  `requested_at`) can decide a case. Record-level JSON `recorded_at` values
  take precedence over the enclosing snapshot/export time, while more specific
  `observed_at` and record-level `captured_at` fields retain precedence.
- Identity history is bounded by `audit_at`: later email/phone/hash changes and
  later snapshot updates are not used to resolve or link a case.
- A case is `COMPLETE` only when the account closure is evidenced (an absent
  `USER_PROFILE` or a clean `ACCOUNT_TOMBSTONE`) and every evidence-supported
  resource/category has a policy-compliant verification. This closure condition
  is an inferred minimum from the account-deletion scope and the “every
  relevant copy” rule; it is not a separately named CSV rule. Unobserved
  categories are not treated as absent; missing evidence yields `INCOMPLETE`,
  never an invented record.
- Support tickets retain both `SUPPORT_MESSAGE` and `SUPPORT_ATTACHMENT`
  treatments when they share a resource ID. Activity identity links are used
  only when the evidence record already contains a matching subject identifier;
  the record's observation timestamp is never replaced by the link timestamp.
- Findings and `COMPLETE` verifications cite a `file_id`, `activity_id` or
  `audit_id`; remediation and future verification steps use `evidence_id=""`.
- Image observations are loaded only when the cache is valid and the actual
  image SHA-256 matches the cache entry. Missing, malformed, incomplete, or
  hash-mismatched cache evidence fails the run instead of silently shrinking
  the evidence set.
- Policy decisions are selected from `deletion_rules.csv`; false conditions,
  unsupported conditions, unknown categories, and unknown support-attachment
  ownership fail closed and cannot manufacture a complete verdict.
- Explicit absence (`NOT_FOUND`/equivalent) is never converted into `PRESENT`,
  `REDACTED`, or `ANONYMIZED`. Non-empty raw result tokens outside the
  recognized vocabulary become `UNKNOWN` and force an INCOMPLETE evidence gap.
  Malformed SQL/JSON/log records and unsupported evidence formats raise an
  explicit parse error.
- Required imports and every case reconstruction are fail-visible. A parser,
  cache, policy, or reconstruction failure raises with the affected `case_id`
  and writes no output CSV instead of emitting a plausible `INCOMPLETE` row.

### Known limitation

Thirty-seven public-sample gold steps remain unmatched: 27 are unrecoverable
from participant-visible evidence (18 account, 7 anonymous analytics, and 2
retained-audit verifications), and 10 are verifications whose evidence fields
become future checks when the conservative account-closure gate returns
`INCOMPLETE`. The relevant resource names or anonymous rows do not establish a
subject link; sparse snapshots cannot supply that mapping. The agent does not
infer IDs from sample answers, neighboring activity, or naming patterns.

The account-closure gate also moved 76 full-dataset cases from `COMPLETE` to
`INCOMPLETE` because no evidence-backed absent profile or clean tombstone exists
for them. That is a conservative evidence decision, not proof that those
accounts exist. The evaluation report lists the status and step differences and
all remaining public per-case mismatches.

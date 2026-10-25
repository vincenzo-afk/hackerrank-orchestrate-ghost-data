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
offline: it makes no model or network calls. Screenshot evidence is read
through a SHA-validated cache of visible facts that a vision model transcribed
from the image bytes (`code/media_observations.json`); the cache is rebuilt
only by the explicit refresh command below.

The pipeline is a global, multi-pass audit. All 518 evaluation requests and
the 32 sample requests are linked together, because a deletion-worker event
can belong to only one request; each output subset is then audited and
validated separately.

1. **Authorize.** `classify_request` reads only `request_text` (EN/ES/PT/FR/JA/KO)
   and returns `NOT_APPLICABLE,[]` for access, export, correction, login help,
   marketing-only opt-out and negated deletion. `reported_status` is never used.
2. **Resolve identity.** Current and historical emails, phones, hashes and the
   `user_id`, bounded by `audit_at`. Names are never used to match records.
3. **Normalize evidence** (`code/evidence_parser.py`). Every observation records
   system, resource, physical copy (primary or named replica), category, state,
   identifiers, the time the state held (`observed_at`) and the time its file
   existed (`available_at`). Snapshot coverage is recorded too: which store,
   category and copy a capture is complete for, and for which subjects.
   Images and PDFs resolve file names, statement numbers and references through
   `LINK_RESOURCE_IDENTITY` catalog aliases; nothing is minted from a file name.
4. **Link resources globally** (`code/activity_linker.py`). Deleted accounts and
   anonymized analytics carry no identifier. The linker learns the deletion
   worker's cadence from identifier-resolved requests (timing window per
   template, `reported_status`/`reported_result` agreement, audit-time proximity
   of readbacks, and a per-request sub-minute phase shared by all of a request's
   worker events), then assigns the remaining events with a one-to-one
   minimum-cost (Hungarian) matching per target system. Low-margin assignments
   are kept as diagnostics. Resources whose evidence names another known
   subject are never assigned. A data-derived profile-naming fallback is used
   only when no account was recovered and only if a snapshot proves its state.
5. **Reconstruct and plan** (`code/state_reconstruction.py`). Each physical copy
   is reconstructed independently; any surviving copy that must be deleted is a
   violation. Absence is inferred from a snapshot omission only when the
   snapshot is complete for that store, category, copy and subject, and was
   taken after the deletion ran. `deletion_rules.csv` is applied through
   `code/policy_engine.py`. A case is `COMPLETE` only when every in-scope
   resource has its required state proven by evidence that existed at
   `audit_at`; there is no separate account-closure flag.
6. **Validate and write** (`code/output_validator.py`). The contract is checked
   before `output.csv` is written; an invalid output is never written.

### Setup

Python 3.10+ (verified on 3.12).

```bash
pip install -r code/requirements.txt
```

`pypdf` reads PDF evidence. `pydantic` and `google-genai` are used only by the
optional media refresh; `pytest` runs the tests.

### Run

```bash
python code/main.py             # writes ./output.csv (518 rows), fails closed on contract errors
python -m pytest code/tests -q  # unit, regression and dataset tests
python code/evaluation/main.py  # sample scoring + full output validation + linker diagnostics
```

### Media refresh (explicit, optional)

The normal run never calls a model. To rebuild the image cache from the
screenshots, put the key in the environment (never in a file) and run:

```bash
GROQ_API_KEY=... python code/refresh_media_cache.py                      # qwen/qwen3.8-27b on Groq
GEMINI_API_KEY=... python code/refresh_media_cache.py --provider gemini  # alternative provider
```

The model is asked only for visible facts (printed ids, aliases, identifiers,
timestamps, the screen's own record label, visible controls) and must quote the
supporting text. Responses with extra fields such as a system, category or
state are rejected, and every id or identifier must appear in the quoted text.
Resource ids, categories and states are derived deterministically from those
facts. The cache is keyed by image SHA-256, model and prompt version.

### Reports

- `code/evaluation/evaluation_report.md` — contract checks, sample metrics,
  custom evaluation cases, failures found and improvements made.
- `code/evaluation/usage_report.md` — model usage for the final run.

### Design guarantees

- A state counts only if it held at or before `audit_at` (and at or after
  `requested_at`). It can be cited, or prove compliance, only if its file
  existed by `audit_at`; a state known only from a later file becomes an
  evidence gap with a future verification step.
- Workflow statuses and activity results are claims. Activity establishes
  ownership; readbacks and complete snapshots establish state.
- Findings cite a participant-visible `file_id`; remediation and future
  verification steps use `evidence_id=""`.
- Unknown categories, unreadable results and unsupported conditions fail closed.
  Malformed evidence and an invalid media cache stop the run.
- Production code reads no sample answers or organizer files and contains no
  case ids (enforced by a test).

### Known limitations

- Two public-sample steps are unmatched: retained audit records that appear in
  no participant-visible file or activity.
- Some deletion-worker events fall in bursts where several requests share
  every signal. They are assigned deterministically and listed as low-margin
  diagnostics by `code/evaluation/main.py`.

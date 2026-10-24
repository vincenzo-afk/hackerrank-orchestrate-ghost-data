# Usage Report — Ghost Data Still Exists

Measured on 2026-10-25 on the full 518-request dataset (`dataset/deletion_requests.csv`).

## 1. Model usage

The submitted agent is a deterministic rule-based pipeline. It does **not** call
an LLM or any external API at inference time.

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Cost |
| --- | --- | --- | --- | --- | --- | --- |
| none | none | **0** | **0** | **0** | **0** | **$0.00** |

| Aggregate | Value |
| --- | --- |
| Total model calls | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |

No API keys, endpoints, or credentials are read or required. All reasoning
(identity resolution, intent classification, evidence parsing, policy
application, step planning) is implemented in Python under `code/`.

## 2. Full-dataset run

Command:

```bash
python -X utf8 code/main.py
```

| Measurement | Value |
| --- | --- |
| Requests processed | 518 |
| Output rows written | 518 (`./output.csv`) |
| Evidence files parsed | 94 |
| Normalised evidence records | 2 911 |
| Steps generated | 2 823 |
| Average steps per request | 5.45 |
| Wall-clock runtime | **9.922 s** (final audit run; repeat 10.145 s) |
| Average runtime per request | **~19.2 ms** |
| Memory / token cost per request | not applicable (no model; no per-request network work) |
| Exit code | 0 |

Status distribution: INCOMPLETE 358, COMPLETE 150, NOT_APPLICABLE 10.
The output is 564 376 bytes, with SHA-256
`e9227291f636af17b44190ab61f3e95eafbffe82c7004760006bbf0c8ace745e`.

## 3. Verification runs

| Command | Result |
| --- | --- |
| `python -X utf8 -m pytest code/tests -q` | **100 passed** (66 foundation + 14 evidence/state + 12 participant-created custom-evaluation + 8 recorded-at regression tests), exit 0 |
| `python -X utf8 code/evaluation/main.py` | 0 contract errors; sample status accuracy 29/32; exact cases 12/32; step TP/FP/FN 166/0/27; precision 1.0, recall 0.860104, F1 0.924791 |
| `python -X utf8 code/main.py` (repeat) | byte-identical `output.csv` (deterministic) |

## 4. Environment

- Python 3.14.7, Windows 10 (10.0.19045)
- `pypdf` 6.21.2 (PDF evidence extraction)
- `pytest` 9.1.1 (tests only, not required at runtime)
- Standard library for everything else (csv, json, sqlite3, re, dataclasses)

Because there are no model calls, there is no provider pricing table to apply;
the estimated cost is exactly $0.00 for both the full run and per request.

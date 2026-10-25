# Usage Report — Ghost Data Still Exists

Measured on 2026-10-25 on the full 518-request dataset (`dataset/deletion_requests.csv`).

## 1. Model usage

The submitted agent is a deterministic rule-based pipeline. The final
full-dataset run does **not** call an LLM or any external API. Image records are
read from a SHA-validated cache of observations produced by a separate,
explicitly requested Gemini extraction experiment.

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
| Normalised evidence records | 2 932 |
| Steps generated | 2 828 |
| Average steps per request | 5.46 |
| Wall-clock runtime | **8.323 s** (final audit run; repeat 8.224 s) |
| Average runtime per request | **~16.1 ms** |
| Memory / token cost per request | not applicable (no model; no per-request network work) |
| Exit code | 0 |

Status distribution: INCOMPLETE 358, COMPLETE 150, NOT_APPLICABLE 10.
The output is 564 902 bytes with deterministic LF line endings and SHA-256
`f5b6f1ebabb0e56834a881007ad91f6080302778bec31b1ad42d1c582d6a04e4`.

### Controlled Gemini extraction experiment (development only)

| Provider | Model | Successful calls | Failed calls | Prompt tokens | Output tokens | Reasoning tokens | Total tokens |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Google | `gemini-3.8-flash` | 13 | 1 (HTTP 503, retried) | 18,075 | 9,502 | 33,458 | **61,035** |

Thirteen successful calls comprised 11 screenshot extractions for the media
cache plus two exploratory smoke calls. The experiment sent only the selected
local PNG files; no dataset archive, `log.txt`, API key, or credential was
uploaded. The final offline run above uses the validated cache and makes
**0 model calls / 0 tokens**. The SDK did not expose a configured price table;
no cost estimate is asserted for the experiment. Per successful experiment
call, the average was 4,695 total tokens.

## 3. Verification runs

| Command | Result |
| --- | --- |
| `python -X utf8 -m pytest code/tests -q` | **127 passed, 1 skipped** (the opt-in live Gemini smoke test is skipped by default), exit 0 |
| `python -X utf8 code/evaluation/main.py` | 0 contract errors; sample status accuracy 29/32; exact cases 12/32; step TP/FP/FN 166/0/27; precision 1.0, recall 0.860104, F1 0.924791 |
| `python -X utf8 code/main.py` (repeat) | byte-identical `output.csv` (deterministic) |

## 4. Environment

- Python 3.14.7, Windows 10 (10.0.19045)
- `pypdf` 6.21.2 (PDF evidence extraction)
- `pydantic` 2.13.5 and `google-genai` 1.75.0 (optional live Gemini refresh; not used by the final offline run)
- `pytest` 9.1.1 (tests only, not required at runtime)
- Standard library for everything else (csv, json, sqlite3, re, dataclasses)

The final offline run has no model calls, so its provider cost is exactly
$0.00 for both the full run and per request. The separate Gemini experiment
used the token counts above; no pricing estimate is claimed.

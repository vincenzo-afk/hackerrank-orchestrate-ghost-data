# Usage Report — Ghost Data Still Exists

Measured on 2026-10-25.

## 1. Final full-dataset run (the run that produced `output.csv`)

| Item | Value |
| --- | --- |
| Command | `python code/main.py` |
| Requests processed | 518 evaluation (+32 sample requests linked in the same global pass) |
| Model providers / models called | none |
| Model calls | 0 |
| Input / output tokens | 0 / 0 |
| Total / average tokens per request | 0 / 0 |
| Estimated cost | $0.00 total; $0.00 per request |
| Wall-clock | about 3 s |

Screenshot evidence is read from `code/media_observations.json`, a cache of
visible facts keyed by each image's SHA-256. The production run only reads that
cache. It was built earlier with `gemini-3.8-flash` (11 images, one call each)
and spot-checked against the screenshots in this revision.

## 2. Media-extraction runs made in this revision

| Provider | Model | Images | Calls | Input tokens | Output tokens | Total tokens | Cost | Used in final output? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Groq (free tier) | `qwen/qwen3.8-27b` | 11 | 11 successful (+1 rate-limited retry, +1 prompt probe) | 22,451 | 9,524 | 31,975 | $0.00 (free tier) | **No — rejected** |
| Google | `gemini-3.8-flash` | 1 of 11 before the run was stopped | 1–2 | not recorded (run interrupted) | — | — | free tier | No |
| **Total recorded** | | | | **22,451** | **9,524** | **31,975** | **$0.00** | |

Per-request average for the Groq experiment, if it were attributed to the 518
requests: 61.7 tokens per request. It does not apply to the final run, which
makes no calls.

Groq's only vision-capable model was the requested replacement for Gemini. Its
output was checked against the screenshots before use and rejected:

- evidence_09: read the look-alike decoy `g.silva76.jr@gmail.com` as
  `g.silva76@gmail.com`. That would attribute another person's search record
  to case_35.
- evidence_28: read `kagyeman8947@fastmail.com` as
  `kagayeman8947@fastmail.com`. A stricter character-by-character prompt gave
  the same result.
- evidence_32: truncated decoy addresses (`bluepeakco` → `bluepeako`,
  `company.com` → `company.co`).

With that cache, the output validator also refused to write `output.csv`
(2 authorized empty plans). Two interpreter defects it exposed were fixed: a
screen-level reference was treated as a record, and a printed user reference
was not resolved through the catalog. The rejected cache is kept for audit at
`code/evaluation/groq_media_observations_rejected.json` and contains no keys.
With the verified cache, the final output is byte-identical before and after
those fixes.

## 3. Rebuilding the cache

```bash
GROQ_API_KEY=...   python code/refresh_media_cache.py                      # qwen/qwen3.8-27b
GEMINI_API_KEY=... python code/refresh_media_cache.py --provider gemini  # gemini-3.8-flash
```

Keys are read from the environment only. Each image is one call of about 2,000
input tokens. Groq's free tier allows 1,000 output tokens per minute, so the
refresh paces itself and retries after 65 seconds on HTTP 429. Re-verify the
transcribed identifiers against the screenshots before replacing the cache.

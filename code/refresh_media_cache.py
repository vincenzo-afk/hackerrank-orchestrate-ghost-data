"""Rebuild media_observations.json from the evidence images with Gemini.

Usage (keys from the environment only):
    GROQ_API_KEY=... python code/refresh_media_cache.py              # qwen/qwen3.8-27b
    GEMINI_API_KEY=... python code/refresh_media_cache.py --provider gemini

Each image in dataset/evidence_files.csv is sent once with the image-v2
prompt, which asks only for visible facts.  The cache stores the source
SHA-256, model, prompt version and per-image token usage; evidence_parser
derives resource ids, categories and states from those facts.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path

from gemini_extractor import GROQ_DEFAULT_MODEL, PROMPT_VERSION, GeminiExtractor, GroqExtractor

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_PATH = Path(__file__).with_name("media_observations.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=("groq", "gemini"), default="groq")
    parser.add_argument("--model", default=None)
    args = parser.parse_args()
    cls = GroqExtractor if args.provider == "groq" else GeminiExtractor
    extractor = cls(model=args.model, max_retries=6)
    args.model = extractor.model
    dataset = REPO_ROOT / "dataset"
    with open(dataset / "evidence_files.csv", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["file_path"].lower().endswith(".png")]
    images, totals = {}, {"calls": 0, "prompt_token_count": 0, "candidates_token_count": 0,
                          "thoughts_token_count": 0, "total_token_count": 0}
    for row in rows:
        result = extractor.extract_image(dataset / row["file_path"], row["file_id"])
        totals["calls"] += 0 if result.cached else 1
        for key in ("prompt_token_count", "candidates_token_count", "thoughts_token_count", "total_token_count"):
            totals[key] += int(result.usage.get(key, 0) or 0)
        images[row["file_id"]] = {
            "file_path": row["file_path"],
            "sha256": result.source_sha256,
            "origin": row["origin"],
            "captured_at": row["captured_at"],
            "usage": result.usage,
            "observations": result.observations,
        }
        print(row["file_id"], len(result.observations), result.usage)
    CACHE_PATH.write_text(json.dumps({
        "version": "image-observations-v2",
        "provider": args.provider,
        "model": args.model,
        "prompt_version": PROMPT_VERSION,
        "usage_totals": totals,
        "images": images,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("totals", totals)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""SHA-validated cache of Gemini-derived image observations.

The cache is not an answer key.  It stores only observations extracted from
individual source images, together with the source SHA-256, model ID, prompt
version, and visible supporting text.  Production reconstruction still applies
the normal identity, temporal, policy, and citation checks.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

DEFAULT_CACHE_PATH = Path(__file__).with_name("media_observations.json")


def load_media_cache(path: Path = DEFAULT_CACHE_PATH) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("images"), dict):
        return {}
    return data


def observations_for(
    file_id: str,
    source_bytes: bytes,
    cache: Optional[dict[str, Any]] = None,
    path: Path = DEFAULT_CACHE_PATH,
) -> list[dict[str, Any]]:
    cache = cache if cache is not None else load_media_cache(path)
    entry = (cache.get("images") or {}).get(file_id)
    if not isinstance(entry, dict):
        return []
    expected = str(entry.get("sha256") or "")
    actual = hashlib.sha256(source_bytes).hexdigest()
    if not expected or expected != actual:
        return []
    observations = entry.get("observations")
    return observations if isinstance(observations, list) else []

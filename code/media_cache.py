"""SHA-validated cache of Gemini-derived image observations.

The cache is not an answer key.  It stores only observations extracted from
individual source images, together with the source SHA-256, model ID, prompt
version, and visible supporting text.  Production reconstruction still applies
the normal identity, temporal, policy, and citation checks.

A missing, unreadable, malformed, or hash-mismatched cache is an evidence
failure, not an empty evidence set.  Callers that cannot proceed without the
cached observations must use ``strict=True`` so the failure is visible.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

DEFAULT_CACHE_PATH = Path(__file__).with_name("media_observations.json")


class MediaCacheError(RuntimeError):
    """Base class for an unusable media cache."""


class MediaCacheMissing(MediaCacheError):
    """The cache file does not exist."""


class MediaCacheInvalid(MediaCacheError):
    """The cache file is unreadable or structurally invalid."""


class MediaCacheEntryMissing(MediaCacheError):
    """The cache has no entry for a referenced image."""


class MediaCacheHashMismatch(MediaCacheError):
    """The cached source hash does not match the image bytes."""


def load_media_cache(path: Path = DEFAULT_CACHE_PATH, *, strict: bool = False) -> dict[str, Any]:
    if not path.exists():
        if strict:
            raise MediaCacheMissing(f"media cache file not found: {path}")
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if strict:
            raise MediaCacheInvalid(f"media cache is unreadable or invalid: {path}") from exc
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("images"), dict):
        if strict:
            raise MediaCacheInvalid(f"media cache has no images mapping: {path}")
        return {}
    return data


def observations_for(
    file_id: str,
    source_bytes: bytes,
    cache: Optional[dict[str, Any]] = None,
    path: Path = DEFAULT_CACHE_PATH,
    *,
    strict: bool = False,
) -> list[dict[str, Any]]:
    if cache is None:
        cache = load_media_cache(path, strict=strict)
    entry = (cache.get("images") or {}).get(file_id)
    if not isinstance(entry, dict):
        if strict:
            raise MediaCacheEntryMissing(f"media cache has no entry for {file_id}")
        return []
    expected = str(entry.get("sha256") or "")
    actual = hashlib.sha256(source_bytes).hexdigest()
    if not expected or expected != actual:
        if strict:
            raise MediaCacheHashMismatch(f"media cache SHA-256 does not match {file_id}")
        return []
    observations = entry.get("observations")
    if not isinstance(observations, list):
        if strict:
            raise MediaCacheInvalid(f"media cache observations are not a list for {file_id}")
        return []
    return observations
